/*
THREAT MODEL (Cerberus Engine)

Attack vectors:
  - CWE-440: Panic in custom Probe implementations.
    Risk: A single malicious or buggy probe crashes the entire watchdog OS process.
  - CWE-116: Malicious ProbeID or Target for log/DSN injection.
    Risk: Control characters in ID/Target corrupt baseline files or exploit loggers.
  - CWE-400: "Drift Storm" flooding the event channel.
    Risk: Rapid state changes cause congestion or OOM.
  - CWE-770: "Slow Probe DoS" consuming worker threads.
    Risk: Hung probes delay other critical security checks.
  - CWE-354: Tampering with baseline files.
    Risk: Attacker modifies persisted baseline to hide drift.
*/
package cerberus

import (
	"encoding/json"
	"testing"
	"time"
)

type SecurityTestContext struct {
	t       *testing.T
	tempDir string
}

func NewSecurityTestContext(t *testing.T) *SecurityTestContext {
	t.Helper()
	return &SecurityTestContext{
		t:       t,
		tempDir: t.TempDir(),
	}
}

func (s *SecurityTestContext) ExpectSecurityError(err error) {
	s.t.Helper()
	if err == nil {
		s.t.Fatal("expected security error, got nil")
	}
}

func (s *SecurityTestContext) ExpectSecuritySuccess(err error) {
	s.t.Helper()
	if err != nil {
		s.t.Fatalf("expected success, got error: %v", err)
	}
}

// ATTACK VECTOR: CWE-440 (Denial of Service via Panic)
// IMPACT: A custom probe panics, crashing the entire Themis OS.
// MITIGATION EXPECTED: Global panic recovery in pollProbe catches the panic and emits a ChangeError.
func TestSecurity_ProbePanic_Isolated(t *testing.T) {
	t.Parallel()
	ctx := NewSecurityTestContext(t)

	c := New(Config{PollInterval: 10 * time.Millisecond, BufferSize: 8})

	panicProbe := &mockProbe{
		id:         "panic-probe",
		shouldPanic: true,
	}

	err := c.RegisterProbe(panicProbe)
	ctx.ExpectSecuritySuccess(err)

	err = c.Start()
	ctx.ExpectSecuritySuccess(err)
	defer func() { _ = c.Stop() }()

	// Wait for the panic event
	timeout := time.After(200 * time.Millisecond)
	var recovered bool

	for {
		select {
		case drift := <-c.Drifts():
			if drift.ChangeType == ChangeError {
				if drift.Error != nil {
					errStr := drift.Error.Error()
					if errStr == "[CERBERUS_PROBE_PANIC]: probe execution panicked" ||
					   (len(errStr) > 22 && errStr[:22] == "[CERBERUS_PROBE_PANIC]") {
						recovered = true
						break
					}
				}
			}
		case <-timeout:
			t.Fatal("timeout waiting for panic recovery event")
		}
		if recovered {
			break
		}
	}

	if !recovered {
		t.Fatal("panic was not caught and converted to ChangeError")
	}
}

// ATTACK VECTOR: CWE-20 (Improper Input Validation) / CWE-400 (Resource Exhaustion)
// IMPACT: Extremely small or negative poll intervals cause CPU spin loops. Large values cause OOM.
// MITIGATION EXPECTED: applyDefaults() clamps invalid values to safe operational defaults.
func TestSecurity_Config_MinBounds_Enforced(t *testing.T) {
	t.Parallel()
	
	// Fuzz-like inputs for config
	testCases := []struct {
		name     string
		config   Config
		validate func(*testing.T, Config)
	}{
		{
			name: "Negative PollInterval",
			config: Config{PollInterval: -100 * time.Millisecond},
			validate: func(t *testing.T, c Config) {
				if c.PollInterval != DefaultPollInterval {
					t.Errorf("expected default poll interval %v, got %v", DefaultPollInterval, c.PollInterval)
				}
			},
		},
		{
			name: "Zero BufferSize",
			config: Config{BufferSize: 0},
			validate: func(t *testing.T, c Config) {
				if c.BufferSize != DefaultBufferSize {
					t.Errorf("expected default buffer size %d, got %d", DefaultBufferSize, c.BufferSize)
				}
			},
		},
		{
			name: "Negative BufferSize",
			config: Config{BufferSize: -100},
			validate: func(t *testing.T, c Config) {
				if c.BufferSize != DefaultBufferSize {
					t.Errorf("expected default buffer size %d, got %d", DefaultBufferSize, c.BufferSize)
				}
			},
		},
		{
			name: "Negative ProbeTimeout",
			config: Config{ProbeTimeout: -5 * time.Second},
			validate: func(t *testing.T, c Config) {
				if c.ProbeTimeout != DefaultProbeTimeout {
					t.Errorf("expected default probe timeout %v, got %v", DefaultProbeTimeout, c.ProbeTimeout)
				}
			},
		},
		{
			name: "Zero CongestionThreshold",
			config: Config{CongestionThreshold: 0},
			validate: func(t *testing.T, c Config) {
				if c.CongestionThreshold != DefaultCongestionThreshold {
					t.Errorf("expected default congestion threshold %d, got %d", DefaultCongestionThreshold, c.CongestionThreshold)
				}
			},
		},
		{
			name: "Negative CongestionThreshold",
			config: Config{CongestionThreshold: -50},
			validate: func(t *testing.T, c Config) {
				if c.CongestionThreshold != DefaultCongestionThreshold {
					t.Errorf("expected default congestion threshold %d, got %d", DefaultCongestionThreshold, c.CongestionThreshold)
				}
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			safeConfig := tc.config.applyDefaults()
			tc.validate(t, safeConfig)
		})
	}
}

func FuzzCerberusInitialization(f *testing.F) {
	// Add sane and extreme seed values
	f.Add(int64(500*time.Millisecond), 64, int64(1*time.Second), int64(10))
	f.Add(int64(-100), -5, int64(-100), int64(-5))
	f.Add(int64(0), 0, int64(0), int64(0))

	f.Fuzz(func(t *testing.T, pollInterval int64, bufferSize int, probeTimeout int64, congestionThreshold int64) {
		cfg := Config{
			PollInterval:        time.Duration(pollInterval),
			BufferSize:          bufferSize,
			ProbeTimeout:        time.Duration(probeTimeout),
			CongestionThreshold: congestionThreshold,
		}

		safeConfig := cfg.applyDefaults()

		// Verify no zero or negative values leaked through
		if safeConfig.PollInterval <= 0 {
			t.Errorf("PollInterval must be positive, got %v", safeConfig.PollInterval)
		}
		if safeConfig.BufferSize <= 0 {
			t.Errorf("BufferSize must be positive, got %d", safeConfig.BufferSize)
		}
		if safeConfig.ProbeTimeout <= 0 {
			t.Errorf("ProbeTimeout must be positive, got %v", safeConfig.ProbeTimeout)
		}
		if safeConfig.CongestionThreshold <= 0 {
			t.Errorf("CongestionThreshold must be positive, got %d", safeConfig.CongestionThreshold)
		}
	})
}

// ATTACK VECTOR: CWE-116 (Improper Output Neutralization for Logs) / CWE-20 (Improper Input Validation)
// IMPACT: Malicious IDs can be used for log spoofing or breaking internal map keys.
// MITIGATION EXPECTED: Validate() rejects characters outside ^[a-zA-Z0-9_\-\.]+$
func TestSecurity_ProbeDefinition_IDValidation(t *testing.T) {
	t.Parallel()

	invalidIDs := []string{
		"probe with spaces",
		"probe\nwith\nnewlines",
		"probe/with/slashes",
		"../../../etc/passwd",
		"probe\x00withnull",
		"probe!@#$",
		"probe🚀",
	}

	for _, id := range invalidIDs {
		def := ProbeDefinition{
			ID:           id,
			ResourceType: ResourceFile,
			Target:       "/valid/target",
		}
		
		err := def.Validate()
		if err == nil {
			t.Errorf("expected security error for invalid ID %q, got nil", id)
		}
	}
}

// FuzzProbeDefinitionValidation tests for injection and boundary bypasses on ProbeDefinition inputs.
func FuzzProbeDefinitionValidation(f *testing.F) {
	// Add sane valid seeds
	f.Add("valid-probe-1", "/etc/passwd", "key=value")
	f.Add("network_monitor.443", "0.0.0.0:443", "")
	
	// Add adversarial seeds
	f.Add("../../../etc/shadow", "valid-target", "")
	f.Add("probe\x00null", "target\x00null", "")
	f.Add("long-id-1234567890123456789012345678901234567890", "a", "")

	f.Fuzz(func(t *testing.T, id string, target string, metaKey string) {
		def := ProbeDefinition{
			ID:           id,
			ResourceType: ResourceFile,
			Target:       target,
			Metadata:     map[string]string{metaKey: "value"},
		}

		err := def.Validate()
		
		// If the ID contains invalid characters or exceeds limits, it must error
		if len(id) == 0 || len(id) > MaxProbeIDLength || len(target) == 0 || len(target) > MaxProbeTargetLength || !validIDRegex.MatchString(id) {
			if err == nil {
				t.Errorf("expected error for malformed input, but got nil. ID: %q, Target: %q", id, target)
			}
		}

		// A panic here would fail the fuzz test automatically.
	})
}

// ATTACK VECTOR: CWE-354 (Improper Validation of Integrity Check Value)
// IMPACT: Tampering with baseline state hides configuration drift from the security monitor.
// MITIGATION EXPECTED: VerifyBaseline rejects malformed JSON and incorrectly sized signatures, preventing bypasses or panics.
func FuzzSignedBaselineVerification(f *testing.F) {
	// Add valid and malformed signature seeds
	f.Add(`{"states":{"probe-1":{"probe_id":"probe-1","hash":12345}}}`, "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 1)
	f.Add(`malformed json`, "invalid hex", -1)
	f.Add(``, "", 0)

	f.Fuzz(func(t *testing.T, jsonPayload string, sigHex string, version int) {
		// Mock out a SignedBaseline struct from the fuzzer inputs
		signed := &SignedBaseline{
			Signature: sigHex,
			Version:   version,
		}
		
		// Attempt to unmarshal the fuzzed JSON into the map (may fail, which is fine)
		_ = json.Unmarshal([]byte(jsonPayload), &signed.States)
		
		key := []byte("fuzz-test-signing-key-16-bytes!")
		
		// The execution must not panic, regardless of how garbage the input is
		valid, err := VerifyBaseline(signed, key)
		
		// If the signature string is valid hex but incorrect length for SHA256 (64 chars),
		// hmac.Equal safely handles mismatched lengths without panicking.
		// We just want to ensure it doesn't crash.
		// We also want to ensure that it doesn't return valid == true for garbage signatures.
		if err == nil && valid && len(sigHex) != 64 {
			// It should only succeed if the signature perfectly matches, which is cryptographically
			// impossible for a fuzzer to guess.
			t.Errorf("VerifyBaseline incorrectly returned valid=true on invalid length signature: %s", sigHex)
		}
	})
}

// ATTACK VECTOR: CWE-20 (Improper Input Validation)
// IMPACT: Injecting negative or massive poll intervals causes CPU spin loops or scheduling starvation.
// MITIGATION EXPECTED: clampInterval strictly enforces MinPollInterval (10ms) and prevents negative values.
func FuzzSensitivityIntervals(f *testing.F) {
	// Add extreme boundaries
	f.Add(int64(-100))
	f.Add(int64(0))
	f.Add(int64(5 * time.Millisecond)) // Below MinPollInterval
	f.Add(int64(100 * time.Millisecond)) // Valid

	f.Fuzz(func(t *testing.T, intervalNs int64) {
		profile := NewSensitivityProfile()
		
		interval := time.Duration(intervalNs)
		profile.SetInterval(ResourceFile, interval)
		
		retrieved := profile.GetInterval(ResourceFile)
		
		if retrieved < MinPollInterval {
			t.Errorf("GetInterval returned %v, which is less than MinPollInterval (%v)", retrieved, MinPollInterval)
		}
	})
}

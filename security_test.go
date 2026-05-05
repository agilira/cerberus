/*
THREAT MODEL (Cerberus Engine)

This file covers the external-facing attack surface of the Cerberus watchdog.
A reviewer must understand the threat model here without reading production code.

Attack vectors and mitigations:

	CWE-440: Expected Behavior Violation via Probe Panic
	  Risk: A custom Probe implementation panics, crashing the host process.
	  Mitigation: pollProbe wraps each Probe.Probe() call in a deferred recover;
	  panics are converted to ChangeError drift events — never propagated up.

	CWE-20: Improper Input Validation — Config Bounds
	  Risk: Negative or zero intervals create CPU spin-loops; huge buffers cause OOM.
	  Mitigation: Config.applyDefaults() enforces positive lower bounds on every field.

	CWE-116: Log / DSN Injection via Probe IDs
	  Risk: Newlines, null bytes, or path separators in probe IDs corrupt log output
	  or exploit downstream log parsers and storage backends.
	  Mitigation: ProbeDefinition.Validate() enforces ^[a-zA-Z0-9_\-\.]+$ and
	  length limits (MaxProbeIDLength, MaxProbeTargetLength).

	CWE-354: Baseline Integrity Bypass
	  Risk: An attacker modifies persisted baseline state to hide infrastructure drift.
	  Mitigation: SignedBaseline uses HMAC-SHA256 with constant-time comparison;
	  VerifyBaseline rejects any tampered payload regardless of byte length.

	CWE-400: Resource Exhaustion via Drift Storm
	  Risk: A high-frequency probe floods emitDrift, exhausting the channel buffer
	  and triggering an OOM condition via unbounded allocations.
	  Mitigation: emitDrift is non-blocking; full buffer => drop + counter + alert.
	  The congestion latch prevents callback storms.

	CWE-770: Slow Probe DoS
	  Risk: A hung probe blocks the poll goroutine indefinitely, causing other probes
	  to starve and miss drift.
	  Mitigation: context.WithTimeout wraps every Probe.Probe() call; the timeout
	  is configurable (ProbeTimeout, default 1s) and capped by the scheduler.
*/
package cerberus

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
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

// ATTACK VECTOR: CWE-440 (Expected Behavior Violation via Probe Panic)
// IMPACT: A panicking probe crashes the host process.
// MITIGATION EXPECTED: pollProbe's deferred recover converts panics to ChangeError events.
//
// awaitPanicRecovery drains the drift channel until a CERBERUS_PROBE_PANIC
// ChangeError event arrives or the deadline fires.
// WHY extracted: keeps TestSecurity_ProbePanic_Isolated below gocyclo=10.
func awaitPanicRecovery(t *testing.T, drifts <-chan DriftEvent) bool {
	t.Helper()
	timeout := time.After(200 * time.Millisecond)
	for {
		select {
		case drift := <-drifts:
			if drift.ChangeType == ChangeError && drift.Error != nil {
				if len(drift.Error.Error()) >= 22 && drift.Error.Error()[:22] == "[CERBERUS_PROBE_PANIC]" {
					return true
				}
			}
		case <-timeout:
			return false
		}
	}
}

func TestSecurity_ProbePanic_Isolated(t *testing.T) {
	t.Parallel()
	ctx := NewSecurityTestContext(t)

	c := New(Config{PollInterval: 10 * time.Millisecond, BufferSize: 8})

	panicProbe := &mockProbe{
		id:          "panic-probe",
		shouldPanic: true,
	}

	ctx.ExpectSecuritySuccess(c.RegisterProbe(panicProbe))
	ctx.ExpectSecuritySuccess(c.Start())
	defer func() { _ = c.Stop() }()

	if !awaitPanicRecovery(t, c.Drifts()) {
		t.Fatal("timeout: panic was not caught and converted to ChangeError within 200ms")
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
			name:   "Zero BufferSize",
			config: Config{BufferSize: 0},
			validate: func(t *testing.T, c Config) {
				if c.BufferSize != DefaultBufferSize {
					t.Errorf("expected default buffer size %d, got %d", DefaultBufferSize, c.BufferSize)
				}
			},
		},
		{
			name:   "Negative BufferSize",
			config: Config{BufferSize: -100},
			validate: func(t *testing.T, c Config) {
				if c.BufferSize != DefaultBufferSize {
					t.Errorf("expected default buffer size %d, got %d", DefaultBufferSize, c.BufferSize)
				}
			},
		},
		{
			name:   "Negative ProbeTimeout",
			config: Config{ProbeTimeout: -5 * time.Second},
			validate: func(t *testing.T, c Config) {
				if c.ProbeTimeout != DefaultProbeTimeout {
					t.Errorf("expected default probe timeout %v, got %v", DefaultProbeTimeout, c.ProbeTimeout)
				}
			},
		},
		{
			name:   "Zero CongestionThreshold",
			config: Config{CongestionThreshold: 0},
			validate: func(t *testing.T, c Config) {
				if c.CongestionThreshold != DefaultCongestionThreshold {
					t.Errorf("expected default congestion threshold %d, got %d", DefaultCongestionThreshold, c.CongestionThreshold)
				}
			},
		},
		{
			name:   "Negative CongestionThreshold",
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
	f.Add(64, int64(1*time.Second), int64(10))
	f.Add(-5, int64(-100), int64(-5))
	f.Add(0, int64(0), int64(0))

	f.Fuzz(func(t *testing.T, bufferSize int, probeTimeout int64, congestionThreshold int64) {
		cfg := Config{
			BufferSize:          bufferSize,
			ProbeTimeout:        time.Duration(probeTimeout),
			CongestionThreshold: congestionThreshold,
		}

		safeConfig := cfg.applyDefaults()

		// Verify no zero or negative values leaked through
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
	f.Add(int64(5 * time.Millisecond))   // Below MinPollInterval
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

// ATTACK VECTOR: CWE-400 (Resource Exhaustion via Drift Storm)
// IMPACT: Burst of drift events fills the channel, drops are silent, monitoring goes blind.
// MITIGATION EXPECTED: emitDrift is non-blocking; dropped events increment droppedCount;
// congestion callback fires exactly once per episode, not once per dropped event.
func TestSecurity_DriftStorm_DropsAccountedFor(t *testing.T) {
	t.Parallel()

	const bufSize = 4
	var alertFired int32

	c := New(Config{
		BufferSize:          bufSize,
		CongestionThreshold: 1,
		OnCongestion: func(_ int64) {
			// Must be called exactly once per episode, not per drop.
			// Incrementing an int32 under -race verifies no concurrent call.
			atomic.AddInt32(&alertFired, 1)
		},
	})

	// Emit 4*bufSize events without any consumer: all but bufSize should drop.
	const total = 4 * bufSize
	for range total {
		c.emitDrift(DriftEvent{ChangeType: ChangeDrift, Timestamp: time.Now()})
	}

	stats := c.Stats()
	if stats.DroppedCount == 0 {
		t.Fatal("expected dropped events, got 0")
	}
	if stats.DroppedCount+int64(len(c.drifts)) > total {
		t.Errorf("accounting error: dropped+buffered=%d > total=%d",
			stats.DroppedCount+int64(len(c.drifts)), total)
	}
	if alertFired != 1 {
		t.Errorf("congestion alert fired %d times, expected exactly 1", alertFired)
	}
}

// ATTACK VECTOR: CWE-770 (Slow Probe DoS)
// IMPACT: A hung probe blocks pollDueProbes indefinitely, starving other probes.
// MITIGATION EXPECTED: ProbeTimeout context causes the probe to unblock via ctx.Done().
// The watchdog continues polling other probes after the timeout.
func TestSecurity_SlowProbe_Timeout_DoesNotStarve(t *testing.T) {
	t.Parallel()

	const probeTimeout = 50 * time.Millisecond
	started := make(chan struct{}, 1)

	// slow never returns before its context is cancelled.
	slow := &callbackProbe{
		id: "slow-security-probe",
		rt: ResourceFile,
		fn: func(ctx context.Context) (State, error) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-ctx.Done() // blocks until ProbeTimeout fires
			return State{}, ctx.Err()
		},
	}

	// fast always returns immediately and signals how many times it was called.
	var fastCalls int32
	fast := &callbackProbe{
		id: "fast-security-probe",
		rt: ResourceFile,
		fn: func(_ context.Context) (State, error) {
			atomic.AddInt32(&fastCalls, 1)
			return State{Hash: 0xAB, ResourceID: "fast"}, nil
		},
	}

	c := New(Config{ProbeTimeout: probeTimeout})
	if err := c.RegisterProbe(slow); err != nil {
		t.Fatalf("RegisterProbe slow: %v", err)
	}
	if err := c.RegisterProbe(fast); err != nil {
		t.Fatalf("RegisterProbe fast: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := c.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}()

	// Wait for the slow probe to begin executing.
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("slow probe never started")
	}

	// The fast probe should still be polled while slow is blocked.
	// Give enough time for at least two fast poll cycles after slow times out.
	time.Sleep(probeTimeout + 100*time.Millisecond)

	if atomic.LoadInt32(&fastCalls) == 0 {
		t.Fatal("fast probe was never called — slow probe starved the scheduler")
	}
}

// ATTACK VECTOR: CWE-362 (Race Condition on Concurrent Register/Unregister)
// IMPACT: Race between probe map mutation and the poll loop reads corrupt state or panic.
// MITIGATION EXPECTED: probesMu RWMutex serialises all map accesses; -race flag confirms.
func TestSecurity_ConcurrentRegisterUnregister_NoRace(t *testing.T) {
	t.Parallel()

	c := New(Config{})
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := c.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}()

	const workers = 8
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func(idx int) {
			defer wg.Done()
			id := "race-probe-" + string(rune('A'+idx))
			p := &mockProbe{id: id}
			if err := c.RegisterProbe(p); err != nil {
				return // duplicate is not a race, just a logic error
			}
			time.Sleep(time.Millisecond)
			_ = c.UnregisterProbe(id)
		}(i)
	}
	wg.Wait()
}

// FuzzResourceTypeString verifies that ResourceType.String() never panics on
// arbitrary uint8 input — important because ResourceType is decoded from
// persisted state and could carry any value.
//
// ATTACK VECTOR: CWE-20 (Improper Input Validation — enum out of range)
// IMPACT: Unknown iota value causes an out-of-bounds array access and a panic.
// MITIGATION EXPECTED: String() bounds-checks before indexing resourceTypeNames.
func FuzzResourceTypeString(f *testing.F) {
	// Seeds: known valid values and potential out-of-bounds values.
	f.Add(uint8(0))
	f.Add(uint8(ResourceCerberus))
	f.Add(uint8(255))
	f.Add(uint8(ResourceCerberus + 1))

	f.Fuzz(func(t *testing.T, raw uint8) {
		rt := ResourceType(raw)
		// Must not panic, must return a non-empty string.
		s := rt.String()
		if s == "" {
			t.Errorf("String() returned empty for ResourceType(%d)", raw)
		}
	})
}

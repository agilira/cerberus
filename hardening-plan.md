# Hardening Plan & Threat Model for Cerberus
**Status:** APPROVED FOR HARDENING  
**Author:** Gemini CLI + AGILira Team  
**Date:** 2026-04-18  
**Target Subsystem:** Drift Detection Watchdog (ADR-010 companion)

---

## 1. Vision & Strategy
Cerberus is the sensory organ of the Themis OS. If Cerberus is compromised, blinded, or tricked, the entire security posture of the agent fails. This hardening plan focuses on **Fault Isolation**, **Injection Protection**, and **Adversarial Load Resilience**, mapping every interaction surface to strict CWE mitigations and fuzzing targets.

### Core Mandates:
1. **In Go we trust, everything else we verify.**
2. **Panic is not an option.** A single failing probe or malformed configuration must never halt the watchdog.
3. **Defense in Depth.** Multiple layers of validation for IDs, targets, and baselines.
4. **TDD & Fuzzing Mandatory.** All mitigations must be backed by `security_test.go` and adversarial fuzzing.

---

## 2. Comprehensive Attack Surface & Threat Model (CWE Mapping)

Cerberus interacts with external inputs through configurations, baseline files, and dynamic probe generation. The following table maps the complete attack surface:

| ID | Component | Attack Class | CWE | Attack Vector | Mitigation Expected |
|----|-----------|--------------|-----|---------------|---------------------|
| **H-01** | `cerberus.go` | Denial of Service | **CWE-440** | Panic in custom `Probe` implementations or `checkFn` callbacks. | Global `defer recover()` wrapper around `pollProbe` with error emission. |
| **H-02** | `factory.go` | Injection | **CWE-116** | Malicious `ProbeID` or `Target` containing control chars, used for log/DSN injection. | Strict sanitization of IDs and Resource targets at registration/creation. |
| **H-03** | `cerberus.go` | Resource Exhaustion | **CWE-400** | "Drift Storm" flooding `drifts` channel, causing OOM or congestion. | Per-probe Token Bucket rate limiting and congestion dropping. |
| **H-04** | `cerberus.go` | Denial of Service | **CWE-770** | "Slow Probe DoS" consuming worker threads/scheduling lag. | Context timeouts (`ProbeTimeout`) and Adaptive Circuit Breaker. |
| **H-05** | `signed_baseline.go` | Data Tampering | **CWE-354** | Tampering with baseline JSON payload or HMAC-SHA256 signature length/format. | Strict validation of hex lengths, constant-time comparison (`hmac.Equal`). |
| **H-06** | `sensitivity.go` | Improper Input Validation | **CWE-20** | Negative or ultra-low durations bypassing `MinPollInterval` causing CPU spin loops. | Hard clamp on `MinPollInterval` (10ms) and integer overflow checks. |
| **H-07** | `factory.go` | Resource Exhaustion | **CWE-770** | Malicious `Metadata` map with millions of keys causing OOM during hash or state generation. | Cap maximum keys/size in `Metadata` payload processing. |
| **H-08** | `cerberus.go` | Race Conditions | **CWE-362** | Concurrent read/writes on `lastState` or `SensitivityProfile` during dynamic updates. | Strict `sync.RWMutex` auditing and execution with `-race`. |

---

## 3. Adversarial Fuzzing Targets (NON-NEGOTIABLE)

Every boundary where Cerberus accepts data must be fuzzed. We do not test "happy paths"; we test for survival under garbage input.

### Target 1: The Engine Config (`cerberus.go`)
- **`FuzzCerberusInitialization(f *testing.F)`**: 
  - Inject negative, zero, or max-int values for `PollInterval`, `BufferSize`, `ProbeTimeout`, and `CongestionThreshold`.
  - *Goal*: Ensure `applyDefaults()` always produces a safe, non-panicking configuration and prevents CPU spin loops.

### Target 2: The Baseline Loader (`signed_baseline.go`)
- **`FuzzSignedBaselineVerification(f *testing.F)`**:
  - Inject malformed JSON payloads, extremely large JSONs, invalid hex signatures, and signatures of incorrect length.
  - *Goal*: Verify `VerifyBaseline` returns `false` or an error without panicking or allocating excessive memory (OOM).

### Target 3: The Probe Factory (`factory.go`)
- **`FuzzProbeDefinitionValidation(f *testing.F)`**:
  - Inject null bytes (`\x00`), emojis, overlong strings (10MB+), and directory traversal sequences (`../`) into `ID` and `Target`.
  - *Goal*: Ensure `def.Validate()` catches invalid inputs and prevents malicious IDs from being registered in internal maps.

### Target 4: The Sensitivity Profile (`sensitivity.go`)
- **`FuzzSensitivityIntervals(f *testing.F)`**:
  - Fuzz `SetInterval` with negative durations and durations exceeding 100 years.
  - *Goal*: Ensure `clampInterval` strictly enforces `MinPollInterval` and handles potential integer wrapping.

---

## 4. Security Testing Doctrine

Following the AGILira standard (as seen in `metis/internal/logging`), every package in Cerberus that interacts with external inputs or state must have a `security_test.go`. 

### Mandatory Structure for `security_test.go`:
1. **THREAT MODEL Comment Block:** The file must begin with a list of attack vectors and CWE references.
2. **SecurityTestContext:** Use a helper struct for `t.TempDir()`, `t.Cleanup()`, and explicit `ExpectSecurityError` / `ExpectSecuritySuccess` assertions.
3. **Specific Test Functions:** One function per attack class, clearly labeled:
   ```go
   // ATTACK VECTOR: CWE-116
   // IMPACT: Log spoofing or injection via maliciously crafted ProbeID...
   // MITIGATION EXPECTED: Sanitization applied, invalid characters rejected.
   func TestSecurity_ProbeID_InjectionNeutralized(t *testing.T) { ... }
   ```

---

## 5. Implementation Roadmap

### Phase 1: Engine Hardening & Fail-Safe Execution
- [ ] Implement `defer recover()` wrapper in `pollProbe()`.
- [ ] Implement `FuzzCerberusInitialization`.
- [ ] Ensure `applyDefaults()` sanitizes all extreme config limits.

### Phase 2: Factory & Input Sanitization
- [ ] Add strict `Validate()` logic in `ProbeDefinition` (alphanumeric ID bounds, Target length limits).
- [ ] Implement `FuzzProbeDefinitionValidation`.
- [ ] Cap `Metadata` payload size to prevent OOM.

### Phase 3: Cryptographic Baseline Resilience
- [ ] Implement `FuzzSignedBaselineVerification`.
- [ ] Ensure `canonicalStateJSON` handles edge-cases without panicking.

### Phase 4: Sensitivity & Scheduling Defense
- [ ] Implement `FuzzSensitivityIntervals`.
- [ ] Implement `TestSecurity_RaceConditions` using concurrent profile updates and probe polls.

---

## 6. Pre-Commit Security Oath
- [ ] Have I checked for nil pointers on every return?
- [ ] Is every channel operation guarded against deadlocks?
- [ ] Did I use `context.Context` for cancellation and timeouts?
- [ ] Are all test coverage ratios at least 3:1 (Test code vs Logic)?
- [ ] Do all tests pass with `go test -v -race`?

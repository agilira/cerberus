# Cerberus Integration Report — Metis Skills Subsystem (ADR-017)

**Date**: 2026-05-05
**Author**: Reviewing agent on behalf of Antonio Giordano
**Cerberus version reviewed**: post-beta, pre-sr-redteam
**Driver**: Metis skills subsystem (ADR-017) integration + auto-protect vision

---

## Executive summary

Cerberus is structurally well-designed for its stated mission (drift detection,
alert-only, CPU-light, AI-aware resource taxonomy). The library is the right
fit for the Metis kernel-wide drift-detection facility envisioned by ADR-001.

This report identifies **4 bugs** of varying severity, **3 architectural
limitations** that block the planned Metis integrations (ADR-017 hot-reload
watcher and the broader auto-protect vision), and **6 documentation drifts**.
None of the findings are structural reversals — every issue has a small, local
fix.

The single critical blocker is **B.1 (register/unregister forbidden while
running)**: as currently designed, every consumer that needs dynamic probe
lifecycle management (which is the entire ADR-017 watcher topology and every
auto-protect flow) cannot use Cerberus without a Stop→Register→Start cycle.
Removing that guard is ~15 LOC plus a test inversion.

We propose a 5-PR sequence (Section §6) to land all fixes in dependency order,
each PR scoped small enough to review in one sitting.

---

## 1. Bugs found

### B.1 — Register/Unregister forbidden while running (CRITICAL)

**Location**: `cerberus.go:189-191` and `cerberus.go:213-215`

```go
func (c *Cerberus) RegisterProbe(probe Probe) error {
    if probe == nil {
        return errors.New(ErrCodeNilProbe, "probe cannot be nil")
    }
    if c.running.Load() {
        return errors.New(ErrCodeProbeWhileRun, "cannot register probe while running")
    }
    ...
}
```

The guard is reinforced by an explicit test pinning the behaviour as
intentional: `TestRegisterProbe_WhileRunning` in `cerberus_test.go:112` asserts
the error.

**Why this is wrong (or at least no longer fits the use cases)**:

The internal data structures already support concurrent access:
- `probesMu` (RWMutex) protects the probes map
- `lastStateMu` (RWMutex) protects baseline state
- `scheduler.mu` (Mutex) protects the priority queue
- `RegisterProbe` calls `c.scheduler.ScheduleNow(id)` which is mutex-protected
- `UnregisterProbe` calls `c.scheduler.Remove(id)` which is mutex-protected

So the `running.Load()` guard is not a *correctness* requirement. It is a
*design choice* that prevents the API surface from supporting hot-add/remove,
likely chosen at the time when the only intended use case was static probe
registration at boot.

**Why the constraint blocks every realistic consumer**:

1. **Metis ADR-017 §3.7.3 (skills watcher)**: the two-probe topology requires
   that when the Layer 1 directory probe detects a new SKILL.md file, the
   loader registers a Layer 2 file probe for that file at runtime. When a file
   is deleted, the corresponding Layer 2 probe must be unregistered. A
   Stop→Register→Start cycle on every filesystem event would (a) re-emit
   ChangeCreate for every other probe, (b) lose drift events buffered in the
   channel, (c) reset the baseline of every other probe.
2. **Metis auto-protect vision**: `mts agent create xxx` registers a probe
   on the new agent's YAML at runtime. The daemon is already running. Same
   for `mts secret store`, `mts skill install`, etc.
3. **Any drift-detection tool with user-driven addition of monitored
   resources** (the `cerberus_protect_path` tool surface) is structurally
   blocked.

**Reproduction**:

```go
c := cerberus.New(cerberus.Config{})
_ = c.Start()
err := c.RegisterProbe(myProbe)
// err.Code == "CERBERUS_PROBE_WHILE_RUNNING"
```

**Proposed fix**:

Drop the `c.running.Load()` guard from both `RegisterProbe` and
`UnregisterProbe`. Keep all other validation (nil check, duplicate check,
not-found check). The internal mutexes carry the thread-safety invariant.

```go
func (c *Cerberus) RegisterProbe(probe Probe) error {
    if probe == nil {
        return errors.New(ErrCodeNilProbe, "probe cannot be nil")
    }
    c.probesMu.Lock()
    defer c.probesMu.Unlock()

    id := probe.ID()
    if _, exists := c.probes[id]; exists {
        return errors.New(ErrCodeDuplicateProbe, "probe with ID already exists").
            WithContext("probe_id", id)
    }
    c.probes[id] = probe
    c.scheduler.ScheduleNow(id)
    return nil
}

func (c *Cerberus) UnregisterProbe(id string) error {
    c.probesMu.Lock()
    defer c.probesMu.Unlock()

    if _, exists := c.probes[id]; !exists {
        return errors.New(ErrCodeProbeNotFound, "probe not found").
            WithContext("probe_id", id)
    }
    delete(c.probes, id)
    c.scheduler.Remove(id)
    c.lastStateMu.Lock()
    delete(c.lastState, id)
    c.lastStateMu.Unlock()
    return nil
}
```

The `ErrCodeProbeWhileRun` constant should remain in the codebase (other
operations may want to use it in the future) but cease to be returned by
Register/Unregister.

**Race-window concern**:

There IS one subtle race in `pollDueProbes` (`cerberus.go:336-354`) once
mid-run unregister is allowed. The loop body:

```go
for _, probeID := range dueProbeIDs {
    c.probesMu.RLock()
    probe, exists := c.probes[probeID]
    c.probesMu.RUnlock()
    if !exists { continue }   // <-- already handles concurrent Unregister
    c.pollProbe(probe)
    interval := c.sensitivityProfile.GetInterval(probe.ResourceType())
    nextPoll := start.Add(interval)
    c.scheduler.Schedule(probeID, nextPoll)  // <-- re-adds even if Unregistered after exists check
}
```

If a probe is unregistered between the `exists` check and the `Schedule` call,
the probe gets re-added to the scheduler with stale state. The fix is one of:

(a) Keep the read-lock held across the entire loop body (simple, slight
    contention increase).
(b) Re-check existence before Schedule:
    ```go
    c.probesMu.RLock()
    _, stillExists := c.probes[probeID]
    c.probesMu.RUnlock()
    if stillExists {
        c.scheduler.Schedule(probeID, nextPoll)
    }
    ```
(c) Take a write lock on `probesMu` during Unregister AND clean the scheduler
    inside the same critical section, then ensure `pollDueProbes` reads
    consistent state.

Option (b) is the smallest delta and matches the existing "tolerate
concurrent unregister" pattern.

**Tests to add**:

- `TestRegisterProbe_WhileRunning_Succeeds` (invert the existing test)
- `TestUnregisterProbe_WhileRunning_Succeeds`
- `TestRegisterProbe_ConcurrentWithPolling` — race test with `go test -race`,
  spawning 10 goroutines that register/unregister while the loop is polling.
  Goal: zero data race + consistent final probe count.
- `TestUnregisterProbe_DuringPoll_DoesNotResurrect` — unregister between
  PopDue and Schedule; assert the probe is not re-added to the scheduler.

**Effort estimate**: 1-2 hours (code + 4 tests + race verification).

**Severity**: CRITICAL — blocks every dynamic-lifecycle consumer.

---

### B.2 — `HealthCheck.LastPollTime` returns `time.Now()` (MEDIUM)

**Location**: `cerberus.go:494-511`

```go
func (c *Cerberus) HealthCheck() HealthStatus {
    ...
    return HealthStatus{
        IsHealthy:      isHealthy,
        IsRunning:      c.running.Load(),
        ProbeCount:     probeCount,
        DroppedEvents:  dropped,
        BufferCapacity: c.config.BufferSize,
        BufferUsed:     len(c.drifts),
        LastPollTime:   time.Now(), // Approximate
    }
}
```

The `LastPollTime` field is declared as `time.Time` (`cerberus.go:122`) and
is intended (per the field name and dashboard semantics) to report when the
last poll cycle completed. Returning `time.Now()` makes the field meaningless:
a dashboard checking "was the last poll within the last 5 seconds?" always
sees fresh data, even when the poll loop is wedged.

The atomic `c.lastPollTime` (`cerberus.go:161`) does exist but stores a
`time.Duration` (the duration of the last poll cycle) — cast as `int64`. It
is updated at `cerberus.go:358`:

```go
c.lastPollTime.Store(int64(time.Since(start)))
```

So there are two semantic ambiguities:
1. The atomic field name is `lastPollTime` but its content is "duration of
   last poll".
2. The HealthCheck field name is `LastPollTime` (`time.Time`) but its content
   is "current wall clock".

**Proposed fix**:

Decide whether the field should be a duration or a timestamp, then make both
sides consistent. Recommendation: split into TWO fields.

```go
type HealthStatus struct {
    ...
    LastPollAt       time.Time     // Wall clock of last poll cycle completion
    LastPollDuration time.Duration // How long the last poll cycle took
}

// In Cerberus struct:
type Cerberus struct {
    ...
    lastPollAt       atomic.Int64  // UnixNano timestamp of last poll completion
    lastPollDuration atomic.Int64  // ns duration of last poll cycle
}

// In pollDueProbes:
if pollCount > 0 {
    c.pollCount.Add(1)
    c.lastPollDuration.Store(int64(time.Since(start)))
    c.lastPollAt.Store(time.Now().UnixNano())
}

// In HealthCheck:
return HealthStatus{
    ...
    LastPollAt:       time.Unix(0, c.lastPollAt.Load()),
    LastPollDuration: time.Duration(c.lastPollDuration.Load()),
}
```

The same split should propagate to `Stats` (currently has only `LastPollTime
time.Duration`).

**Tests to add**:

- `TestHealthCheck_LastPollAt_AfterFirstPoll` — register a probe, run for 50ms,
  call HealthCheck, assert `LastPollAt` is within the last 50ms.
- `TestHealthCheck_LastPollAt_StaleWhenStopped` — start, run, stop; wait 1s;
  call HealthCheck; assert `LastPollAt` is 1s in the past (the field is NOT
  updated during the idle period, which is the whole point).
- `TestHealthCheck_LastPollDuration_PositiveAfterPoll` — verify the duration
  field tracks the actual cycle time.

**Effort estimate**: 1 hour.

**Severity**: MEDIUM — correctness bug; dashboards that monitor freshness
always see "fresh" even when the poll loop is wedged or stopped.

---

### B.3 — `lastPollAt` map is dead code (LOW, perf)

**Location**: `cerberus.go:146-147, 175, 367-369`

The map and its mutex are declared, initialised, written on every probe poll,
and never read by any production code path. Confirmed via:

```bash
$ grep -n "lastPollAt" cerberus/*.go | grep -v _test
cerberus.go:146:	lastPollAt   map[string]time.Time
cerberus.go:147:	lastPollAtMu sync.RWMutex
cerberus.go:175:		lastPollAt:         make(map[string]time.Time),
cerberus.go:367:	c.lastPollAtMu.Lock()
cerberus.go:368:	c.lastPollAt[probeID] = time.Now()
cerberus.go:369:	c.lastPollAtMu.Unlock()
```

Zero readers anywhere in the package.

**Why this is harmful (beyond aesthetics)**:

- Allocates an entry per probe on every poll cycle (map grows monotonically
  for the lifetime of each probe).
- Acquires a write-lock on `lastPollAtMu` on every probe poll, contending with
  any future reader if added (but there are no readers, so this is pure
  overhead today).
- Confuses code review: a reader assumes the field has a purpose and may
  attempt to consume it incorrectly.

**Proposed fix**: delete the field, the mutex, the initialisation, and the
write block. If a future feature needs "when did probe X last poll", the
information can be derived from the priority queue's `nextPoll - interval`
or added back as a deliberate atomic field at that time.

If B.2 is fixed by adding a per-Cerberus `lastPollAt atomic.Int64` (singular,
last completion time of the WHOLE cycle), do not confuse it with this dead
per-probe map. The two are semantically different.

**Tests to add**: none (deletion only). Run existing tests to confirm no
regression.

**Effort estimate**: 15 minutes.

**Severity**: LOW — performance + code clarity; no functional bug.

---

### B.4 — `congestionAlerted` is one-shot for the lifetime of the process (MEDIUM)

**Location**: `cerberus.go:162, 456-465`

```go
congestionAlerted atomic.Bool  // line 162
...
// In emitDrift:
if dropped >= c.config.CongestionThreshold {
    if c.congestionAlerted.CompareAndSwap(false, true) {
        if c.config.OnCongestion != nil {
            c.config.OnCongestion(dropped)
        }
    }
}
```

The `CompareAndSwap(false, true)` returns true exactly once across the
lifetime of the Cerberus instance. There is no reset path anywhere in the
package.

The comment at `cerberus.go:458` says `// Only alert once per congestion
episode`. There is no separate concept of "episode" — the boolean is set
once, never cleared, so "episode" effectively means "process lifetime".

**Why this is wrong**:

A long-running daemon experiencing a transient congestion event (say, a
brief surge in drift events during deployment) trips the alert ONCE. After
the surge ends and the buffer drains, the alert is silently disarmed for
the rest of the process lifetime. A second, completely unrelated congestion
event hours later goes silent. Operations / SOC dashboards relying on
`OnCongestion` to detect "monitoring blind spots" would miss every event
after the first one.

For a GRC / compliance-grade monitoring system (which is the README's
stated positioning), a single missed congestion event is a documented
blind spot in the audit trail.

**Proposed fix — option A (drain-based reset)**:

Reset `congestionAlerted` when the buffer drops back to a healthy level for
N consecutive ticks. The simplest implementation:

```go
// In pollDueProbes (or a separate health-check goroutine):
if len(c.drifts) == 0 && c.congestionAlerted.Load() {
    c.congestionAlerted.Store(false)
}
```

This re-arms the alert once the buffer has fully drained. A second congestion
event then re-fires `OnCongestion`.

**Proposed fix — option B (cooldown-based reset)**:

```go
// New field:
congestionAlertedAt atomic.Int64 // UnixNano of last alert

const CongestionResetCooldown = 30 * time.Second

// In emitDrift congestion branch:
now := time.Now().UnixNano()
last := c.congestionAlertedAt.Load()
if now-last >= int64(CongestionResetCooldown) {
    if c.config.OnCongestion != nil {
        c.config.OnCongestion(dropped)
    }
    c.congestionAlertedAt.Store(now)
}
```

Option A is conceptually cleaner ("alert when degraded, re-arm when healthy");
Option B avoids the per-tick check. We recommend **A** because it directly
encodes the operational intent.

**Tests to add**:

- `TestCongestion_RefiresAfterDrain` — fill the buffer, observe alert, drain
  the buffer (consume all events), trigger congestion again, assert second
  alert fires.
- `TestCongestion_DoesNotRefireWhileStillCongested` — sustained congestion
  must NOT spam alerts; only one per drained-then-re-congested cycle.

**Effort estimate**: 1-2 hours.

**Severity**: MEDIUM — observability / GRC compliance gap.

---

## 2. Architectural limitations (Metis-driven feature requests)

### F.1 — Multi-consumer drift dispatch (NICE-TO-HAVE)

**Driver**: ADR-001 mandates Cerberus as a daemon-wide singleton in Metis.
At least four packages will need to consume drift events:
- `internal/skills` — drift on SKILL.md and on the skills root directory
- `internal/agent/sdk` (future) — drift on registered agent YAMLs
- `internal/config` (future) — drift on config.yaml / policy.yaml / secrets.yaml
- `internal/workflow` (future) — drift on workflow JSON files

Today, `Cerberus.Drifts() <-chan DriftEvent` returns a single channel with a
single consumer. Two consumers reading the same channel race; events are
delivered to whoever wins each receive.

**Proposed approach** — DOES NOT require Cerberus changes:

Metis will implement a `DriftDispatcher` in `internal/cerberus/` (Metis-side
package) that owns `cerberus.Drifts()`, reads in a single goroutine, and
fans out to per-subsystem handlers keyed by probe-ID prefix or resource type.
This keeps Cerberus minimal and shifts the routing concern to the consumer.

We flag this here because the COLLEAGUE may have considered adding a
`Subscribe(filter func(DriftEvent) bool) <-chan DriftEvent` API. We
recommend **NOT** adding that to Cerberus for now — the consumer-side
dispatcher is simpler, more testable, and avoids per-subscriber backpressure
semantics that are non-trivial to get right.

**No upstream change requested.** This section is informational so that the
colleague doesn't add a Subscribe API thinking Metis needs it — Metis does
not.

---

### F.2 — Synchronous probe execution serialises K probes (MEDIUM-FUTURE)

**Location**: `cerberus.go:336-354` (`pollDueProbes` loop body)

Probes due simultaneously are polled in series, each taking up to
`ProbeTimeout` (default 1s). With K critical-sensitivity probes (100ms
interval) all due at the same tick, the worst-case batch time is K × 1s.
During that batch, subsequent ticks land on a busy `pollDueProbes`, and Go's
ticker drops queued ticks (buffer of 1).

For Metis Phase 1.0 use cases (Medium/Low sensitivity probes, 1-10 second
intervals), this is **not** a problem. Flagging because a future user who
sets up many critical-sensitivity probes (say, 50 secret-file probes at
100ms) will hit a serialisation cliff that is invisible until the load
materialises.

**Proposed fix (future work, not Phase 1.0)**:

Worker pool. A bounded number of worker goroutines (configurable, default 4
or `runtime.NumCPU()`) consume from a probe-due channel. `pollDueProbes`
becomes a fan-out:

```go
type Cerberus struct {
    ...
    workerCount int
    probeQueue  chan Probe  // bounded, sized = workerCount * 2
}

// In Start:
for i := 0; i < c.workerCount; i++ {
    go c.probeWorker()
}

// In pollDueProbes:
for _, probeID := range dueProbeIDs {
    ...
    select {
    case c.probeQueue <- probe:
    default:
        // queue full — log + skip; the next tick will pick it up
    }
}
```

Test additions: `TestPollLoop_ParallelProbes_RespectsBudget`,
`TestPollLoop_SlowProbeDoesNotBlockOthers`.

**Effort estimate** (when prioritised): half a day.

**Severity**: MEDIUM-FUTURE — not a Phase 1.0 blocker; flag for the
post-1.0 scaling pass.

---

### F.3 — Stop() force-abandons after 5s with no diagnostics (LOW)

**Location**: `cerberus.go:254-271`

```go
func (c *Cerberus) Stop() error {
    ...
    select {
    case <-c.doneCh:
        // Clean shutdown
    case <-time.After(5 * time.Second):
        // Timeout - force stop
    }

    c.running.Store(false)
    return nil
}
```

If a probe is stuck in a CPU-bound loop ignoring its context, `pollDueProbes`
never returns, `pollLoop` never observes `stopCh`, `doneCh` never closes.
After 5 seconds, `Stop()` returns nil (clean) but the poll goroutine and the
stuck probe goroutine leak.

**Proposed fix**:

Return a non-nil error when the timeout is hit, so the caller knows the
shutdown was not clean:

```go
const StopTimeout = 5 * time.Second

func (c *Cerberus) Stop() error {
    if !c.running.Load() {
        return errors.New(ErrCodeNotRunning, "cerberus is not running")
    }
    close(c.stopCh)
    select {
    case <-c.doneCh:
        c.running.Store(false)
        return nil
    case <-time.After(StopTimeout):
        c.running.Store(false)
        return errors.New("CERBERUS_STOP_TIMEOUT",
            "poll loop did not finish within timeout — possibly stuck probe")
    }
}
```

Optional enhancement: log which probe was running when the timeout fired
(track current-probe-id in a `currentProbeID atomic.Pointer[string]` field
set/cleared around `c.pollProbe(probe)`).

**Tests to add**:

- `TestStop_CleanShutdown_NoError` — happy path, no probes hung.
- `TestStop_StuckProbe_ReturnsTimeout` — register a probe that ignores ctx
  and sleeps 10s; assert Stop returns the timeout error within ~5s.

**Effort estimate**: 1 hour.

**Severity**: LOW — operational hygiene; helps debug daemons that fail to
shut down cleanly.

---

### F.4 — Audit-grade drift event metadata (NICE-TO-HAVE)

**Driver**: Metis emits every Cerberus drift event into the signed audit log
with AI Act §13 weighting. The current `DriftEvent` struct is sufficient for
Metis's needs as long as the consumer (Metis dispatcher) provides:
- timestamp ✅ (`Event.Timestamp`)
- probe ID ✅ (`Event.ProbeID`)
- resource ID ✅ (`Event.ResourceID`)
- resource type ✅ (`Event.ResourceType`)
- change type ✅ (`Event.ChangeType`)
- prev/curr hash ✅ (`Event.PrevHash`, `Event.CurrHash`)
- error ✅ (`Event.Error`)

**No upstream change requested.** Information only — the existing
`DriftEvent` shape is adequate for audit emission.

One *minor* suggestion: add a `Sensitivity Sensitivity` field to `DriftEvent`
so consumers don't have to round-trip through the SensitivityProfile to
weight events. This is purely ergonomic; can wait.

---

## 3. Documentation drift

### D.1 — README claim "RegisterProbe() Safe during operation" is false

**Location**: `README.md:426`

```
- ✅ `RegisterProbe()` / `UnregisterProbe()` - Safe during operation
```

The current code returns `ErrCodeProbeWhileRun`. This claim becomes TRUE only
after B.1 is fixed. Update once B.1 lands.

### D.2 — `ResourceCustom` positioning differs README vs code

**Location**: `README.md:186` lists `ResourceCustom` as the LAST entry (after
all AI-specific resource types and `ResourceCerberus`). `probe.go:36` has it
in the MIDDLE (between `ResourceEndpoint` and the AI-specific block).

Cosmetic but confusing: a reader following the README struct order to
implement a switch statement will produce code that looks different from
existing usages. Reorder the README to match `probe.go` order.

### D.3 — `PollInterval` "deprecated" claim

**Location**: `README.md:122`

```
| `PollInterval` | `time.Duration` | 500ms | Base polling interval (deprecated with SensitivityProfile) |
```

The code at `cerberus.go:46-49` still describes `PollInterval` as a
first-class option (`SOVEREIGNTY: Let policy/user decide CPU vs detection
speed tradeoff`) and uses it via `applyDefaults` (line 86). It is NOT actually
deprecated — `pollLoop` uses `MinPollInterval` (the package constant) as base
tick, not the config value. So the config field is essentially unused at this
point.

Clarify in BOTH README and the code comment whether `PollInterval` is:
- (a) deprecated and ignored — then remove from `applyDefaults` and add a
  `// Deprecated:` doc comment.
- (b) functional — then explain when it is used (it currently isn't).

### D.4 — Quick Start example uses unused `PollInterval`

**Location**: `README.md:91-96`

```go
watchdog := cerberus.New(cerberus.Config{
    PollInterval: 500 * time.Millisecond,
    BufferSize:   64,
})
```

If D.3 resolves to "deprecated", remove from the Quick Start example and use
`SensitivityProfile` for the demo.

### D.5 — Doc claims `RegisterGenerator` is "Thread-safe: can be called during runtime"

**Location**: `factory.go:106-112`

```go
// RegisterGenerator registers a generator for a resource type
// Thread-safe: can be called during runtime
func (f *ProbeFactory) RegisterGenerator(rt ResourceType, gen ProbeGenerator) {
    f.mu.Lock()
    defer f.mu.Unlock()
    f.generators[rt] = gen
}
```

This IS thread-safe (correct claim). But notice the asymmetry with
`RegisterProbe` which makes the opposite claim and refuses runtime calls.
Once B.1 lands, the API surface becomes consistent (both can be called during
runtime). Until then, the asymmetry is jarring for readers.

### D.6 — `CongestionThreshold` default discrepancy

**Location**: `cerberus.go:22` declares `DefaultCongestionThreshold = 10`.
`README.md:128` says default is 10. ✅ aligned. But `cerberus.go:72` field
comment says `Default: 10` while the HealthCheck calculation uses `dropped <
c.config.CongestionThreshold` which means the threshold is the cap of "still
healthy"; the README should clarify that 10 means "alert AT 10 dropped
events", not "alert ABOVE 10".

Trivial wording fix.

---

## 4. Concerns NOT requesting fixes (informational)

### N.1 — `pollProbe` synchronous panic recovery is correctly implemented

The CWE-440 mitigation at `cerberus.go:379-388` is well done. Confirmed via
`TestSecurity_ProbePanic_Isolated` in `security_test.go:54`. No change
needed.

### N.2 — Signed baseline implementation looks solid

`signed_baseline.go` uses `hmac.Equal` for constant-time comparison
(`signed_baseline.go:87`). Canonical JSON via sorted keys. No timing-attack
surface visible. `key < 16 bytes` guard at line 38 is good.

One micro-nit: the `LoadSignedBaseline` API (line 121) requires the caller
to construct the `*SignedBaseline` value, which means deserialising from
disk happens before signature verification. If the deserialisation step
itself is malicious-input-sensitive (it isn't with stdlib `encoding/json`,
but worth flagging), the signature check arrives too late. Not an issue
with the current implementation; just a note.

### N.3 — Priority queue implementation is clean

`priority_queue.go` is textbook `container/heap` usage. The `entries` map
provides O(1) lookup-by-id, the heap provides O(log n) schedule/extract.
No issues found.

### N.4 — Sensitivity profile API is well-shaped

`SensitivityProfile.GetInterval` priority order (custom interval > custom
sensitivity > default-for-resource) is sensible and matches the README. The
`MinPollInterval = 10ms` clamp prevents pathological CPU usage. Clone()
provides safe forking.

---

## 5. Test additions checklist

Per AGILira testing doctrine (TDD red→green, race-on, fuzz where possible),
each fix above should land with the listed tests. Cumulative checklist:

| # | Test | For | Notes |
|---|------|-----|-------|
| 1 | `TestRegisterProbe_WhileRunning_Succeeds` | B.1 | Invert existing test |
| 2 | `TestUnregisterProbe_WhileRunning_Succeeds` | B.1 | New |
| 3 | `TestRegisterProbe_ConcurrentWithPolling` | B.1 | Race test, 10 goroutines |
| 4 | `TestUnregisterProbe_DuringPoll_DoesNotResurrect` | B.1 | Pin the (b) fix |
| 5 | `TestHealthCheck_LastPollAt_AfterFirstPoll` | B.2 | Within last 50ms |
| 6 | `TestHealthCheck_LastPollAt_StaleWhenStopped` | B.2 | Pin staleness |
| 7 | `TestHealthCheck_LastPollDuration_PositiveAfterPoll` | B.2 | Duration field |
| 8 | (No new test for B.3 — deletion only, existing tests cover) | B.3 | — |
| 9 | `TestCongestion_RefiresAfterDrain` | B.4 | Critical regression net |
| 10 | `TestCongestion_DoesNotRefireWhileStillCongested` | B.4 | Anti-spam |
| 11 | `TestStop_StuckProbe_ReturnsTimeout` | F.3 | (Optional, F.3 is LOW) |

All tests should run with `-race` and pass on `-count=10` to catch flakes.

---

## 6. Suggested PR sequence

Order is dependency-driven:

| PR | Scope | Files touched | Effort | Severity |
|----|-------|---------------|--------|----------|
| 1  | B.1 — drop while-running guard + Schedule re-check | cerberus.go, cerberus_test.go | 1-2h | CRITICAL |
| 2  | B.3 — delete `lastPollAt` dead code | cerberus.go | 15min | LOW |
| 3  | B.2 — split LastPollAt + LastPollDuration in HealthCheck/Stats | cerberus.go, README.md, related tests | 1h | MEDIUM |
| 4  | B.4 — congestion alert reset on drain | cerberus.go, self_health_test.go | 1-2h | MEDIUM |
| 5  | F.3 — Stop() returns timeout error + currentProbeID tracking | cerberus.go, cerberus_test.go | 1h | LOW |
| 6  | Doc drift sweep — D.1 through D.6 | README.md, code comments | 30min | LOW |

PR 1 is the unblocker. PRs 2-6 are independent and can land in any order
once PR 1 is merged.

**F.2 (worker pool)** is deliberately NOT in this sequence; it is a
post-Phase-1.0 enhancement when actual scaling pressure materialises.

---

## 7. Metis-side integration plan (informational)

Once PR 1 above lands, the Metis side can proceed with:

1. `internal/cerberus/` package — daemon-wide Cerberus singleton, lifecycle
   hooks, and DriftDispatcher (the F.1 consumer-side dispatcher).
2. `internal/skills/` Layer 1 + Layer 2 probes per ADR-017 §3.7.
3. Audit-event ordinals for cerberus drift (slice 1.0.G); 5 new events
   reserved:
   - `EventCerberusDriftDetected`
   - `EventCerberusProbeRegistered`
   - `EventCerberusProbeUnregistered`
   - `EventCerberusProbeError`
   - `EventCerberusCongestion`
4. Auto-protect wiring (post-Phase-1.0): agent SDK persistence registers
   `ResourceAgentConfig` probe on every agent YAML write; same pattern for
   future workflow / secret / skill writes.
5. Tool surface (post-Phase-1.0): `cerberus_probe_list`,
   `cerberus_probe_status`, `cerberus_protect_path`,
   `cerberus_unprotect_path` — all `SafeSurfaces: [cli, tui, eos]` only
   (never chat — prompt-injection disarm risk).

---

## 8. Glossary

- **ADR-001 (Metis)**: cerberus integration policy: alert-only, recovery
  delegated to operator (no auto-recovery in Metis).
- **ADR-017 (Metis)**: skills subsystem; specifies the two-probe topology
  (directory + per-file) using cerberus as the watcher.
- **AI Act §13**: EU regulation requiring auditable record reconstruction
  for AI agent decisions; drives the high-severity ordinal classification
  for security-relevant cerberus events.
- **DriftDispatcher**: Metis-side fan-out goroutine that owns
  `cerberus.Drifts()` and routes events by probe-ID prefix.
- **Auto-protect**: Metis convention where every kernel feature that creates
  user-facing artifacts (agents, workflows, skills, secrets) auto-registers
  a cerberus probe to detect tampering.

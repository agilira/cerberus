# Cerberus

Lightweight drift detection watchdog for security-critical Go applications.

Cerberus polls registered probes at configurable intervals and emits a
`DriftEvent` when the state hash of a resource changes. It detects — it
never acts. What to do with a drift event is the caller's responsibility.

License: MPL-2.0
Requires: Go 1.22+

---

## Design principles

- **Detect, never act.** Side effects belong outside the watchdog.
- **Zero surprise dependencies.** Only `github.com/agilira/go-errors`.
- **CPU-light.** One base ticker goroutine; probes scheduled via a priority
  queue (`O(log n)` reschedule per probe, `O(k)` work per tick).
- **Panic-safe.** A panicking probe emits `ChangeError` and does not crash
  the host process (CWE-440 mitigation).
- **Hot registration.** `RegisterProbe` and `UnregisterProbe` are safe to
  call while the watchdog is running.
- **Context-aware.** Every probe call is bounded by a configurable
  `ProbeTimeout`; a hung probe times out instead of starving others
  (CWE-770 mitigation).

---

## Installation

```
go get github.com/agilira/cerberus
```

---

## Quick start

```go
watchdog := cerberus.New(cerberus.Config{
    BufferSize:   64,
    ProbeTimeout: time.Second,
    OnStateChange: func(id string, prev, curr *cerberus.State) {
        // Persist curr to external storage for restart recovery.
        db.SaveState(id, curr)
    },
})

// Restore baseline from a previous run (optional).
watchdog.LoadBaseline(db.LoadAllStates())

if err := watchdog.RegisterProbe(myFileProbe); err != nil {
    log.Fatal(err)
}
if err := watchdog.Start(); err != nil {
    log.Fatal(err)
}
defer func() {
    if err := watchdog.Stop(); err != nil {
        // ErrCodeStopTimeout means a probe did not finish within 5s.
        log.Println("cerberus stop:", err)
    }
}()

for event := range watchdog.Drifts() {
    fmt.Printf("drift: %s changed [%s]\n", event.ResourceID, event.ChangeType)
}
```

---

## Configuration

All fields are optional. `New` applies safe defaults for any zero value.

| Field | Type | Default | Notes |
|---|---|---|---|
| `BufferSize` | `int` | 64 | Capacity of the drift event channel. Size for peak burst rate. |
| `ProbeTimeout` | `time.Duration` | 1s | Maximum time one probe may run. Exceeded -> context cancelled. |
| `SensitivityProfile` | `*SensitivityProfile` | auto | Per-resource poll intervals. Nil -> `DefaultSensitivityForResource`. |
| `OnStateChange` | `StateChangeHandler` | nil | Called on every state transition (including first poll). |
| `CongestionThreshold` | `int64` | 10 | Dropped-event count that fires `OnCongestion`. Resets on drain. |
| `OnCongestion` | `CongestionHandler` | nil | Called once per congestion episode, not once per drop. |
| `EmitCongestionEvent` | `bool` | false | Emit a `ChangeError` DriftEvent on congestion (opt-in). |

`PollInterval` is accepted for backward compatibility but has no effect. Use
`SensitivityProfile` to control polling frequency.

---

## The Probe interface

```go
type Probe interface {
    ID()           string
    ResourceType() ResourceType
    Probe(ctx context.Context) (State, error)
}
```

Probes must be:

- **Idempotent** — safe to call repeatedly without side effects.
- **Context-aware** — respect `ctx.Done()` for clean cancellation.
- **Fast** — aim well under the configured `ProbeTimeout`.
- **Thread-safe** — may be called from the watchdog goroutine concurrently
  with other probes in future worker-pool extensions.

Example: file probe

```go
type FileProbe struct{ path string }

func (p *FileProbe) ID() string                        { return "file:" + p.path }
func (p *FileProbe) ResourceType() cerberus.ResourceType { return cerberus.ResourceFile }

func (p *FileProbe) Probe(ctx context.Context) (cerberus.State, error) {
    select {
    case <-ctx.Done():
        return cerberus.State{}, ctx.Err()
    default:
    }
    info, err := os.Stat(p.path)
    if err != nil {
        return cerberus.State{}, err
    }
    h := fnv.New64a()
    fmt.Fprintf(h, "%d%d%s", info.ModTime().UnixNano(), info.Size(), info.Mode())
    return cerberus.State{
        ResourceID: p.path,
        Hash:       h.Sum64(),
        Timestamp:  time.Now(),
    }, nil
}
```

---

## Resource types

| Constant | String | Default sensitivity |
|---|---|---|
| `ResourceFile` | `file` | Medium - 1s |
| `ResourcePort` | `port` | High - 500ms |
| `ResourceProcess` | `process` | High - 500ms |
| `ResourceLog` | `log` | Low - 5s |
| `ResourceContainer` | `container` | Medium - 1s |
| `ResourceCertificate` | `certificate` | Critical - 100ms |
| `ResourceDNS` | `dns` | Medium - 1s |
| `ResourceIAMPolicy` | `iam_policy` | Critical - 100ms |
| `ResourceNetworkRule` | `network_rule` | High - 500ms |
| `ResourceSecret` | `secret` | Critical - 100ms |
| `ResourceService` | `service` | Medium - 1s |
| `ResourceEndpoint` | `endpoint` | Medium - 1s |
| `ResourceCustom` | `custom` | Medium - 1s |
| `ResourceModelWeight` | `model_weight` | Critical - 100ms |
| `ResourcePromptTemplate` | `prompt_template` | High - 500ms |
| `ResourceEnvVar` | `env_var` | High - 500ms |
| `ResourceAgentConfig` | `agent_config` | Critical - 100ms |
| `ResourceCerberus` | `cerberus` | Medium - 1s |

Custom intervals override the sensitivity-based default:

```go
profile := cerberus.NewSensitivityProfile()
profile.SetInterval(cerberus.ResourceFile, 250*time.Millisecond)
profile.SetSensitivity(cerberus.ResourceSecret, cerberus.SensitivityCritical)

watchdog := cerberus.New(cerberus.Config{SensitivityProfile: profile})
```

The absolute minimum interval is `MinPollInterval = 10ms`; values below this
are clamped automatically.

---

## Drift events

```go
type DriftEvent struct {
    ProbeID      string
    ResourceID   string
    ResourceType ResourceType
    ChangeType   ChangeType   // ChangeCreate | ChangeDrift | ChangeError | ...
    PrevHash     uint64
    CurrHash     uint64
    Timestamp    time.Time
    Error        error        // non-nil when ChangeType == ChangeError
}
```

`ChangeCreate` is emitted on the first poll for a probe (no previous state).
`ChangeDrift` is emitted when the hash differs from the previous poll.
`ChangeError` is emitted when the probe returns an error or panics.

---

## Dynamic probe generation

`ProbeFactory` builds probes at runtime from `ProbeDefinition` values without
stopping the watchdog:

```go
factory := cerberus.NewProbeFactory()
factory.RegisterGenerator(cerberus.ResourceFile, func(ctx context.Context, def cerberus.ProbeDefinition) (cerberus.Probe, error) {
    return NewFileProbe(def.Target), nil
})

defs := []cerberus.ProbeDefinition{
    {ID: "file:/etc/passwd", ResourceType: cerberus.ResourceFile, Target: "/etc/passwd"},
}
probes, errs := factory.CreateProbesFromDefinitions(ctx, defs)
for i, p := range probes {
    if errs[i] != nil {
        continue
    }
    _ = watchdog.RegisterProbe(p)
}
```

`ProbeDefinition.Validate()` enforces `^[a-zA-Z0-9_\-\.]+$` on IDs and
rejects null bytes, path separators, and oversized values (CWE-116).

---

## Baseline integrity

Persisted state can be signed with HMAC-SHA256 to detect tampering:

```go
key := []byte("32-byte-secret-key-for-production!")

// Before shutdown - sign and persist.
signed, err := cerberus.SignBaseline(watchdog.ExportState(), key)
saveToFile(signed)

// On startup - verify before loading.
loaded := loadFromFile()
ok, err := cerberus.VerifyBaseline(loaded, key)
if err != nil || !ok {
    log.Fatal("baseline tampered - refusing to load")
}
watchdog.LoadBaseline(loaded.States)
```

`VerifyBaseline` uses `hmac.Equal` for constant-time comparison (CWE-354).

---

## Statistics and health

```go
stats := watchdog.Stats()
// stats.PollCount, stats.DriftCount, stats.DroppedCount
// stats.LastPollAt (time.Time), stats.LastPollDuration (time.Duration)
// stats.IsRunning, stats.ProbeCount, stats.BaselineCount

health := watchdog.HealthCheck()
// health.IsHealthy, health.IsRunning, health.ProbeCount
// health.DroppedEvents, health.BufferCapacity, health.BufferUsed
// health.LastPollAt, health.LastPollDuration
```

`HealthStatus.IsHealthy` is false when `DroppedEvents >= CongestionThreshold`.

---

## Congestion

When the drift channel is full, `emitDrift` drops the event and increments
`Stats.DroppedCount`. When dropped events reach `CongestionThreshold`:

1. `OnCongestion` is called exactly once per congestion episode.
2. The latch resets automatically when the next event is successfully
   enqueued and the buffer is no longer at capacity.
3. A subsequent burst fires `OnCongestion` again.

Recommended: always provide an `OnCongestion` handler and monitor
`Stats.DroppedCount` in your health dashboard.

---

## Stop behaviour

`Stop()` signals the poll loop to exit and waits up to 5 seconds. If a probe
is stuck (ignores context cancellation, e.g. a blocked syscall), `Stop()`
returns `ErrCodeStopTimeout` but still marks the watchdog as stopped. The
caller decides whether to treat this as fatal.

```go
if err := watchdog.Stop(); err != nil {
    // At least one probe did not finish cleanly.
    log.Printf("cerberus stop: %v", err)
}
```

---

## Security

The following threat vectors are covered by `security_test.go`:

| CWE | Vector | Mitigation |
|---|---|---|
| CWE-440 | Probe panic | `recover()` in `pollProbe`; converted to `ChangeError`. |
| CWE-20 | Invalid config (negative intervals, zero buffers) | `applyDefaults()` clamps all fields. |
| CWE-116 | Injection via probe IDs (newlines, null bytes, path separators) | `ProbeDefinition.Validate()` enforces strict charset. |
| CWE-354 | Baseline tampering | HMAC-SHA256 + constant-time compare in `VerifyBaseline`. |
| CWE-400 | Drift storm / buffer flood | Non-blocking channel + drop counter + congestion latch. |
| CWE-770 | Slow probe DoS | Per-probe `context.WithTimeout`; timed-out probes emit `ChangeError`. |
| CWE-362 | Race on concurrent register/unregister | `probesMu` RWMutex + double-check before reschedule. |

---

## Thread safety

All public methods are safe to call concurrently. Specifically:

- `RegisterProbe` and `UnregisterProbe` may be called while the watchdog is
  running. The probe map is protected by `probesMu` (RWMutex).
- `Stats()` and `HealthCheck()` use lock-free atomic reads.
- `Drifts()` returns a read-only channel; multiple consumers are safe.
- `SensitivityProfile` operations are protected by an internal RWMutex.

---

## Copyright

Copyright (c) 2025 AGILira - A. Giordano
SPDX-License-Identifier: MPL-2.0

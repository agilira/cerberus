# Cerberus

**Lightweight Drift Detection Watchdog for Themis Security OS**

[![Go Version](https://img.shields.io/badge/Go-1.25-blue.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MPL--2.0-green.svg)](../LICENSE)
[![Coverage](https://img.shields.io/badge/Coverage-85%25-brightgreen.svg)]()

---

## Overview

Cerberus is a high-performance, CPU-efficient drift detection engine designed for security-critical environments. Named after the three-headed guardian of the underworld, Cerberus watches your infrastructure and **barks** (emits events) when state changes occur—but never acts. Action is delegated to Themis OS.

### Design Philosophy

| Principle | Description |
|-----------|-------------|
| **Separation of Concerns** | Cerberus detects. Themis decides. Reflex acts. |
| **CPU-Light Polling** | Ticker-based scheduling, no spin loops. |
| **Sensitivity Profiles** | Per-resource polling intervals (secrets at 100ms, logs at 5s). |
| **Dynamic Probes** | Runtime probe generation from WorldModel—no recompilation. |
| **Context-Aware Probes** | All probes accept `context.Context` for timeout/cancellation. |
| **Self-Health Monitoring** | Congestion detection and health checks. |
| **State Persistence Hooks** | `OnStateChange`, `LoadBaseline`, `ExportState` for external persistence. |
| **Zero Dependencies** | Only `github.com/agilira/go-errors` for structured errors. |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CERBERUS ENGINE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   Probe      │    │   Probe      │    │   Probe      │      │
│  │   (File)     │    │   (Port)     │    │   (Secret)   │      │
│  │   1s poll    │    │   500ms poll │    │   100ms poll │      │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘      │
│         │                   │                   │               │
│         └───────────────────┼───────────────────┘               │
│                             ▼                                   │
│                 ┌───────────────────────┐                       │
│                 │   SensitivityProfile  │                       │
│                 │   (per-resource)      │                       │
│                 └───────────┬───────────┘                       │
│                             ▼                                   │
│                 ┌───────────────────────┐                       │
│                 │      Poll Loop        │                       │
│                 │   (10ms base tick)    │                       │
│                 └───────────┬───────────┘                       │
│                             ▼                                   │
│                 ┌───────────────────────┐                       │
│                 │    DriftEvent Chan    │◄── Non-blocking       │
│                 │    (buffered)         │    (drops on full)    │
│                 └───────────┬───────────┘                       │
│                             │                                   │
└─────────────────────────────┼───────────────────────────────────┘
                              ▼
                 ┌───────────────────────┐
                 │     THEMIS OS         │
                 │  Policy → RBAC →      │
                 │  WorldModel → Reflex  │
                 └───────────────────────┘
```

---

## Quick Start

### Installation

```bash
go get github.com/agilira/cerberus
```

### Basic Usage

```go
package main

import (
    "fmt"
    "time"
    
    "github.com/agilira/cerberus"
)

func main() {
    // Create watchdog with default configuration
    watchdog := cerberus.New(cerberus.Config{
        PollInterval: 500 * time.Millisecond,
        BufferSize:   64,
    })
    
    // Register a file probe
    probe := NewFileProbe("/etc/passwd")
    watchdog.RegisterProbe(probe)
    
    // Start watching
    watchdog.Start()
    defer watchdog.Stop()
    
    // Consume drift events
    for drift := range watchdog.Drifts() {
        fmt.Printf("Drift detected: %s changed (%s)\n", 
            drift.ResourceID, drift.ChangeType)
    }
}
```

---

## Configuration

### Config Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `PollInterval` | `time.Duration` | 500ms | Base polling interval (deprecated with SensitivityProfile) |
| `BufferSize` | `int` | 64 | DriftEvent channel buffer size |
| `SensitivityProfile` | `*SensitivityProfile` | auto | Per-resource polling intervals |
| `ProbeTimeout` | `time.Duration` | 1s | Max time to wait for a single probe |
| `OnStateChange` | `StateChangeHandler` | nil | Called on every state change (for persistence) |
| `CongestionThreshold` | `int` | 10 | Dropped events threshold for congestion alert |
| `OnCongestion` | `CongestionHandler` | nil | Called when congestion threshold exceeded |
| `EmitCongestionEvent` | `bool` | false | Emit self-drift event on congestion |

### Sensitivity Levels

Cerberus supports four sensitivity levels with default intervals:

| Level | Interval | Use Case |
|-------|----------|----------|
| `SensitivityCritical` | 100ms | Secrets, certificates, IAM policies |
| `SensitivityHigh` | 500ms | Ports, processes, network rules |
| `SensitivityMedium` | 1s | Files, containers, services |
| `SensitivityLow` | 5s | Logs, metrics, non-critical data |

### Custom Sensitivity Profile

```go
// Create custom profile
profile := cerberus.NewSensitivityProfile()

// Override defaults
profile.SetSensitivity(cerberus.ResourceSecret, cerberus.SensitivityCritical)
profile.SetSensitivity(cerberus.ResourceFile, cerberus.SensitivityHigh)

// Or set exact intervals
profile.SetInterval(cerberus.ResourcePort, 250*time.Millisecond)

// Apply to watchdog
watchdog := cerberus.New(cerberus.Config{
    SensitivityProfile: profile,
})
```

---

## Resource Types

Cerberus supports monitoring of diverse infrastructure resources:

| Resource Type | Description | Default Sensitivity |
|---------------|-------------|---------------------|
| `ResourceFile` | File system objects | Medium (1s) |
| `ResourcePort` | Network ports | High (500ms) |
| `ResourceProcess` | Running processes | High (500ms) |
| `ResourceSecret` | Secrets/credentials | Critical (100ms) |
| `ResourceCertificate` | TLS/SSL certificates | Critical (100ms) |
| `ResourceContainer` | Docker/K8s containers | Medium (1s) |
| `ResourceService` | System services | Medium (1s) |
| `ResourceDNS` | DNS records | Medium (1s) |
| `ResourceIAMPolicy` | IAM/RBAC policies | Critical (100ms) |
| `ResourceNetworkRule` | Firewall rules | High (500ms) |
| `ResourceLog` | Log files | Low (5s) |
| `ResourceEndpoint` | API endpoints | Medium (1s) |
| `ResourceModelWeight` | AI model weights | Critical (100ms) |
| `ResourcePromptTemplate` | LLM prompt templates | High (500ms) |
| `ResourceEnvVar` | Environment variables | High (500ms) |
| `ResourceAgentConfig` | AI agent configs | Critical (100ms) |
| `ResourceCerberus` | Self-health monitoring | Medium (1s) |
| `ResourceCustom` | User-defined | Medium (1s) |

---

## Implementing Probes

### Probe Interface

```go
type Probe interface {
    // ID returns the unique identifier for this probe
    ID() string
    
    // ResourceType returns the type of resource being monitored
    ResourceType() ResourceType
    
    // Probe executes the check and returns current state.
    // The context provides timeout and cancellation support.
    Probe(ctx context.Context) (State, error)
}
```

### Example: File Probe

```go
type FileProbe struct {
    path string
}

func NewFileProbe(path string) *FileProbe {
    return &FileProbe{path: path}
}

func (p *FileProbe) ID() string {
    return "file:" + p.path
}

func (p *FileProbe) ResourceType() cerberus.ResourceType {
    return cerberus.ResourceFile
}

func (p *FileProbe) Probe(ctx context.Context) (cerberus.State, error) {
    // Respect context cancellation
    select {
    case <-ctx.Done():
        return cerberus.State{}, ctx.Err()
    default:
    }

    info, err := os.Stat(p.path)
    if err != nil {
        return cerberus.State{}, err
    }
    
    // Compute hash from file metadata
    hash := computeHash(info.ModTime(), info.Size(), info.Mode())
    
    return cerberus.State{
        ResourceID: p.path,
        Hash:       hash,
        Timestamp:  time.Now(),
        Metadata: map[string]string{
            "size": strconv.FormatInt(info.Size(), 10),
            "mode": info.Mode().String(),
        },
    }, nil
}
```

---

## Dynamic Probe Generation

### ProbeFactory

For enterprise deployments, probes can be generated dynamically from configuration or WorldModel entities:

```go
// Create factory
factory := cerberus.NewProbeFactory()

// Register generators for each resource type
factory.RegisterGenerator(cerberus.ResourceFile, func(ctx context.Context, def cerberus.ProbeDefinition) (cerberus.Probe, error) {
    return cerberus.NewGenericProbe(def, func(ctx context.Context, target string) (uint64, error) {
        // Check file and return hash
        return checkFileHash(target)
    }), nil
})

// Create probes from definitions (e.g., from WorldModel)
definitions := []cerberus.ProbeDefinition{
    {ID: "file:/etc/passwd", ResourceType: cerberus.ResourceFile, Target: "/etc/passwd"},
    {ID: "port:22", ResourceType: cerberus.ResourcePort, Target: "22"},
}

probes, errs := factory.CreateProbesFromDefinitions(ctx, definitions)
```

### Integration with WorldModel

```go
// Extract probe definitions from WorldModel entities
entities := worldModel.QueryEntities(ctx, query)

var entityLikes []orchestrator.EntityLike
for _, e := range entities {
    entityLikes = append(entityLikes, wrapEntity(e))
}

definitions := orchestrator.ExtractProbeDefinitions(entityLikes)
probes, _ := factory.CreateProbesFromDefinitions(ctx, definitions)

for _, probe := range probes {
    watchdog.RegisterProbe(probe)
}
```

---

## Drift Events

### DriftEvent Structure

```go
type DriftEvent struct {
    ProbeID      string       // Probe that detected the drift
    ResourceID   string       // Resource identifier
    ResourceType ResourceType // Type of resource
    ChangeType   ChangeType   // What changed
    PrevHash     uint64       // Previous state hash
    CurrHash     uint64       // Current state hash
    Timestamp    time.Time    // When detected
    Error        error        // Error if ChangeError
}
```

### Change Types

| Type | Description |
|------|-------------|
| `ChangeNone` | No change detected |
| `ChangeCreate` | Resource first discovered (initial state) |
| `ChangeModify` | Resource modified |
| `ChangeDelete` | Resource deleted |
| `ChangeDrift` | State hash changed (generic drift) |
| `ChangeError` | Probe execution failed |

---

## Statistics and Monitoring

```go
stats := watchdog.Stats()

fmt.Printf("Polls: %d\n", stats.PollCount)
fmt.Printf("Drifts: %d\n", stats.DriftCount)
fmt.Printf("Dropped: %d\n", stats.DroppedCount)
fmt.Printf("Probes: %d\n", stats.ProbeCount)
fmt.Printf("Baselines: %d\n", stats.BaselineCount)
fmt.Printf("Last Poll: %v\n", stats.LastPollTime)
fmt.Printf("Running: %v\n", stats.IsRunning)
```

### Health Check

Monitor Cerberus self-health:

```go
health := watchdog.HealthCheck()

fmt.Printf("Healthy: %v\n", health.Healthy)
fmt.Printf("Probes: %d\n", health.ProbeCount)
fmt.Printf("Running: %v\n", health.Running)
fmt.Printf("Congested: %v\n", health.Congested)
fmt.Printf("Dropped: %d\n", health.DroppedCount)
```

---

## State Persistence

Cerberus provides hooks for external state persistence, enabling recovery after restart.

### State Change Hook

```go
watchdog := cerberus.New(cerberus.Config{
    OnStateChange: func(probeID string, prev *cerberus.State, curr cerberus.State) {
        // Persist to database, file, or external service
        db.SaveState(probeID, curr)
    },
})
```

### Load Baseline on Startup

```go
// Load persisted baseline from external storage
baseline := map[string]cerberus.State{
    "file:/etc/passwd": {ResourceID: "/etc/passwd", Hash: 12345},
    "port:22":          {ResourceID: "22", Hash: 67890},
}

watchdog.LoadBaseline(baseline)
watchdog.Start()
```

### Export Current State

```go
// Export current baseline for persistence
currentState := watchdog.ExportState()

// Save to external storage
json.Marshal(currentState)
```

---

## Congestion Alerts

Cerberus can alert when the event buffer is filling up:

```go
watchdog := cerberus.New(cerberus.Config{
    CongestionThreshold: 5,
    OnCongestion: func(droppedCount int64) {
        alerting.Fire("cerberus_congestion", map[string]any{
            "dropped": droppedCount,
        })
    },
    EmitCongestionEvent: true, // Also emit as DriftEvent
})

---

## Thread Safety

Cerberus is fully thread-safe:

- ✅ `RegisterProbe()` / `UnregisterProbe()` - Safe during operation
- ✅ `Start()` / `Stop()` - Idempotent
- ✅ `Drifts()` channel - Safe for concurrent consumption
- ✅ `Stats()` - Lock-free atomic reads
- ✅ `SensitivityProfile` - RWMutex-protected updates

---

## Best Practices

### 1. Size Your Buffer

```go
// High-frequency environments: larger buffer
cerberus.New(cerberus.Config{BufferSize: 256})

// Low-frequency: smaller is fine
cerberus.New(cerberus.Config{BufferSize: 32})
```

### 2. Monitor Dropped Events

```go
go func() {
    ticker := time.NewTicker(1 * time.Minute)
    for range ticker.C {
        stats := watchdog.Stats()
        if stats.DroppedCount > 0 {
            log.Warn("events dropped", "count", stats.DroppedCount)
        }
    }
}()
```

### 3. Use Appropriate Sensitivity

```go
// Don't over-poll non-critical resources
profile.SetSensitivity(cerberus.ResourceLog, cerberus.SensitivityLow)

// Critical resources get fast polling
profile.SetSensitivity(cerberus.ResourceSecret, cerberus.SensitivityCritical)
```

### 4. Graceful Shutdown

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

if err := watchdog.Stop(); err != nil {
    log.Error("shutdown failed", "error", err)
}
```

---

## Performance

### Benchmarks

| Metric | Value |
|--------|-------|
| Base tick overhead | ~10μs per tick |
| Probe scheduling | O(n) per tick |
| Memory per probe | ~200 bytes |
| Channel operations | Non-blocking |

### CPU Efficiency

Cerberus uses ticker-based polling, NOT spin loops:

```go
// ✅ What Cerberus does (CPU-light)
ticker := time.NewTicker(10 * time.Millisecond)
for range ticker.C {
    pollDueProbes()
}

// ❌ What Cerberus does NOT do (CPU-heavy)
for {
    pollAllProbes()  // No sleep = 100% CPU
}
```

---

## Integration with Themis OS

Cerberus integrates with Themis via the `CerberusAdapter`:

```go
adapter := orchestrator.NewCerberusAdapter(orchestrator.CerberusAdapterConfig{
    SensitivityProfile: profile,
    Handler: func(ctx context.Context, event cerberus.DriftEvent) error {
        // Route to Themis decision pipeline
        return orchestrator.ProcessDrift(ctx, event)
    },
    Logger:      logger,
    AuditEngine: auditEngine,
})

adapter.RegisterProbe(probe)
adapter.Start()
```

---

## License

Copyright (c) 2025 AGILira - A. Giordano

Licensed under the Mozilla Public License 2.0 (MPL-2.0).

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## Security

For security issues, please email security@agilira.com.

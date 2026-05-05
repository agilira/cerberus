// Package cerberus implements a lightweight, CPU-efficient drift detection watchdog.
//
// # Design Principles
//
// Cerberus detects — it never acts. Every state change is emitted as a [DriftEvent]
// on a buffered channel; what to do with that information is the caller's concern.
// This separation keeps Cerberus auditable, testable, and safe to embed in any
// security-critical process without hidden side effects.
//
// Additional design constraints:
//   - Zero external dependencies beyond github.com/agilira/go-errors.
//   - CPU-light: one base ticker goroutine; probes polled via a priority queue.
//   - Context-aware: every probe call is bounded by a configurable ProbeTimeout.
//   - Panic-safe: a panicking probe emits ChangeError and does NOT crash the host.
//   - Thread-safe: [RegisterProbe] and [UnregisterProbe] are safe to call while
//     the watchdog is running.
//
// # Quick start
//
//	watchdog := cerberus.New(cerberus.Config{
//	    BufferSize:   64,
//	    ProbeTimeout: time.Second,
//	    OnStateChange: func(id string, prev, curr *cerberus.State) {
//	        // persist curr to external storage for restart recovery
//	    },
//	})
//
//	if err := watchdog.RegisterProbe(myProbe); err != nil {
//	    log.Fatal(err)
//	}
//	if err := watchdog.Start(); err != nil {
//	    log.Fatal(err)
//	}
//	defer func() {
//	    if err := watchdog.Stop(); err != nil {
//	        log.Println("cerberus stop:", err) // may be ErrCodeStopTimeout
//	    }
//	}()
//
//	for event := range watchdog.Drifts() {
//	    handleDrift(event)
//	}
//
// # Configuration
//
// [Config] controls all runtime behaviour. Passing a zero value is safe — defaults
// are applied by [New] via Config.applyDefaults():
//
//   - BufferSize (default 64): capacity of the drift event channel.
//   - ProbeTimeout (default 1s): maximum time a single probe may run.
//   - CongestionThreshold (default 10): dropped-event count that triggers [Config.OnCongestion].
//   - SensitivityProfile: per-resource polling intervals (see [SensitivityProfile]).
//
// # Probes
//
// Any type that satisfies the [Probe] interface can be registered. The interface
// is intentionally minimal:
//
//	type Probe interface {
//	    ID()           string
//	    ResourceType() ResourceType
//	    Probe(context.Context) (State, error)
//	}
//
// Probes are polled at the interval returned by [SensitivityProfile.GetInterval]
// for their [ResourceType]. The default intervals range from 100ms
// ([SensitivityCritical]) to 5s ([SensitivityLow]).
//
// # Dynamic probes
//
// [ProbeFactory] generates probes at runtime from [ProbeDefinition] values.
// Register a generator per [ResourceType], then call CreateProbesFromDefinitions
// to build a batch without restarting the watchdog.
//
// # State persistence and restart recovery
//
// Cerberus is stateless by design. Persistence is opt-in:
//   - [Config.OnStateChange]: called on every state transition; persist the new state.
//   - [Cerberus.LoadBaseline]: restore a saved state map before calling [Cerberus.Start].
//   - [Cerberus.ExportState]: snapshot the current in-memory state for persistence.
//
// # Baseline integrity
//
// [SignBaseline] and [VerifyBaseline] provide HMAC-SHA256 protection for persisted
// state. Tampered baselines are rejected before they can influence drift decisions.
//
// # Self-health
//
// [Cerberus.HealthCheck] returns [HealthStatus] with live congestion metrics,
// probe count, and the timestamp/duration of the last poll cycle. [Cerberus.Stats]
// returns cumulative counters for dashboards and alerting.
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0
package cerberus

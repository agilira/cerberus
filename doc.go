// cerberus: Lightweight drift detection watchdog for Themis Security OS
//
// Philosophy:
// - Detect, don't act (SOC separation of concerns)
// - CPU-light polling (ticker + sleep, no spin loops)
// - Zero external dependencies beyond go-errors
// - Pluggable probes for any resource type
// - Thread-safe, race-free design
// - Context-aware probes with timeout support
// - Self-health monitoring and congestion alerts
// - State persistence hooks for restart recovery
//
// Cerberus watches system state via configurable Probes and barks (emits DriftEvents)
// when drift is detected. It does NOT take action - that's Themis OS's job via
// Policy → RBAC → WorldModel → Reconciler → Reflex chain.
//
// # Configuration
//
// Key configuration options:
//   - PollInterval: Base polling frequency (default 500ms)
//   - BufferSize: Drift channel buffer (default 64)
//   - ProbeTimeout: Max probe execution time (default 1s)
//   - SensitivityProfile: Per-resource polling intervals
//   - OnStateChange: Hook for state persistence
//   - CongestionThreshold: Dropped events trigger for alert (default 10)
//   - OnCongestion: Handler for congestion alerts
//
// # Resource Types
//
// Cerberus supports diverse resource monitoring including:
//   - Infrastructure: File, Port, Process, Service, Container
//   - Security: Secret, Certificate, IAMPolicy, NetworkRule
//   - AI-Specific: ModelWeight, PromptTemplate, EnvVar, AgentConfig
//   - Meta: Cerberus (self-health monitoring)
//
// # State Persistence
//
// For restart recovery, use the persistence hooks:
//   - OnStateChange: Called on every probe state change
//   - LoadBaseline: Restore state from external storage
//   - ExportState: Export current state for persistence
//
// Example Usage:
//
//	watchdog := cerberus.New(cerberus.Config{
//	    PollInterval:        500 * time.Millisecond,
//	    BufferSize:          64,
//	    ProbeTimeout:        1 * time.Second,
//	    CongestionThreshold: 10,
//	    OnStateChange: func(probeID string, prev *State, curr State) {
//	        db.SaveState(probeID, curr)
//	    },
//	})
//
//	// Restore baseline from persistence
//	watchdog.LoadBaseline(db.LoadAllStates())
//
//	// Register probes
//	watchdog.RegisterProbe(myFileProbe)
//	watchdog.RegisterProbe(myPortProbe)
//
//	// Start watching
//	watchdog.Start()
//	defer watchdog.Stop()
//
//	// Consume drift events (Themis OS handles these)
//	for drift := range watchdog.Drifts() {
//	    orchestrator.HandleDrift(drift)
//	}
//
//	// Check health
//	health := watchdog.HealthCheck()
//	if !health.Healthy {
//	    log.Warn("Cerberus degraded", "congested", health.Congested)
//	}
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira fragment
// SPDX-License-Identifier: MPL-2.0
package cerberus

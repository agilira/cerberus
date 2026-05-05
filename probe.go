// probe.go: Probe interface and types for Cerberus watchdog
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package cerberus

import (
	"context"
	"errors"
	"time"
)

// Error sentinels for probe operations
var (
	ErrProbeFailure = errors.New("probe execution failed")
	ErrProbeTimeout = errors.New("probe execution timed out")
)

// ResourceType identifies what kind of resource a probe monitors
type ResourceType uint8

const (
	ResourceFile ResourceType = iota
	ResourcePort
	ResourceProcess
	ResourceLog
	ResourceContainer
	ResourceCertificate
	ResourceDNS
	ResourceIAMPolicy
	ResourceNetworkRule
	ResourceSecret
	ResourceService
	ResourceEndpoint
	ResourceCustom

	// AI-Specific Resources (Sovereign Agentic OS)
	ResourceModelWeight    // LLM model weights - detect tampering
	ResourcePromptTemplate // System prompts - detect prompt injection
	ResourceEnvVar         // Environment variables - detect agent hijacking
	ResourceAgentConfig    // Agent configuration - critical for sovereignty

	// Meta-Resources (Self-Health)
	ResourceCerberus // Cerberus itself (congestion, health)
)

// resourceTypeNames maps ResourceType constants (iota-ordered) to their
// canonical string representation. The lookup is O(1) and keeps cyclomatic
// complexity of String() at 1 regardless of how many types are added.
// WHY not a switch: a 19-branch switch is untestable at each branch; a table
// is verified by a single bounds check and one array lookup.
var resourceTypeNames = [...]string{
	ResourceFile:           "file",
	ResourcePort:           "port",
	ResourceProcess:        "process",
	ResourceLog:            "log",
	ResourceContainer:      "container",
	ResourceCertificate:    "certificate",
	ResourceDNS:            "dns",
	ResourceIAMPolicy:      "iam_policy",
	ResourceNetworkRule:    "network_rule",
	ResourceSecret:         "secret",
	ResourceService:        "service",
	ResourceEndpoint:       "endpoint",
	ResourceCustom:         "custom",
	ResourceModelWeight:    "model_weight",
	ResourcePromptTemplate: "prompt_template",
	ResourceEnvVar:         "env_var",
	ResourceAgentConfig:    "agent_config",
	ResourceCerberus:       "cerberus",
}

// String returns the canonical string representation of the resource type.
func (r ResourceType) String() string {
	if int(r) < len(resourceTypeNames) {
		return resourceTypeNames[r]
	}
	return "unknown"
}

// ChangeType identifies what kind of change was detected
type ChangeType uint8

const (
	ChangeNone ChangeType = iota
	ChangeCreate
	ChangeModify
	ChangeDelete
	ChangeDrift // State differs from expected
	ChangeError // Probe error
)

// String returns human-readable change type name
func (c ChangeType) String() string {
	switch c {
	case ChangeNone:
		return "none"
	case ChangeCreate:
		return "create"
	case ChangeModify:
		return "modify"
	case ChangeDelete:
		return "delete"
	case ChangeDrift:
		return "drift"
	case ChangeError:
		return "error"
	default:
		return "unknown"
	}
}

// State represents the current state of a monitored resource
type State struct {
	ResourceID string    // Unique identifier for the resource
	Hash       uint64    // Hash of current state for fast comparison
	Timestamp  time.Time // When this state was captured
	Metadata   any       // Optional: additional state info for detailed diff
}

// DriftEvent represents a detected drift that Cerberus barks about
type DriftEvent struct {
	ProbeID      string       // Which probe detected this
	ResourceID   string       // What resource drifted
	ResourceType ResourceType // Type of resource
	ChangeType   ChangeType   // What kind of change
	PrevHash     uint64       // Previous state hash
	CurrHash     uint64       // Current state hash
	Timestamp    time.Time    // When detected
	Error        error        // If ChangeType == ChangeError
}

// Probe interface that all resource monitors must implement
// Probes are responsible for:
// 1. Fetching current state of a resource
// 2. Computing a hash for fast comparison
// 3. Returning any errors encountered
//
// Probes should be:
// - Idempotent (safe to call repeatedly)
// - Thread-safe (may be called from multiple goroutines)
// - Fast (polling happens frequently)
// - Pure (no side effects)
// - Context-aware (respect timeouts and cancellation)
type Probe interface {
	// ID returns unique identifier for this probe
	ID() string

	// ResourceType returns what kind of resource this probe monitors
	ResourceType() ResourceType

	// Probe fetches current state and returns it
	// Must be thread-safe, idempotent, and respect context cancellation
	// Context will have a deadline set by Cerberus (ProbeTimeout config)
	Probe(ctx context.Context) (State, error)
}

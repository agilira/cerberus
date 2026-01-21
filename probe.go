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

// String returns human-readable resource type name
func (r ResourceType) String() string {
	switch r {
	case ResourceFile:
		return "file"
	case ResourcePort:
		return "port"
	case ResourceProcess:
		return "process"
	case ResourceLog:
		return "log"
	case ResourceContainer:
		return "container"
	case ResourceCertificate:
		return "certificate"
	case ResourceDNS:
		return "dns"
	case ResourceIAMPolicy:
		return "iam_policy"
	case ResourceNetworkRule:
		return "network_rule"
	case ResourceSecret:
		return "secret"
	case ResourceService:
		return "service"
	case ResourceEndpoint:
		return "endpoint"
	case ResourceCustom:
		return "custom"
	// AI-Specific Resources
	case ResourceModelWeight:
		return "model_weight"
	case ResourcePromptTemplate:
		return "prompt_template"
	case ResourceEnvVar:
		return "env_var"
	case ResourceAgentConfig:
		return "agent_config"
	// Meta-Resources
	case ResourceCerberus:
		return "cerberus"
	default:
		return "unknown"
	}
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

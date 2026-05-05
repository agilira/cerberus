// factory.go: Dynamic Probe factory for runtime probe generation
//
// ProbeFactory enables runtime creation of probes from definitions.
// This allows Themis OS to generate probes automatically based on:
//   - WorldModel entities (files, ports, processes, secrets, etc.)
//   - Policy rules (what to monitor, sensitivity levels)
//
// No recompilation needed - probes are generated dynamically.
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package cerberus

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"
)

// ProbeGenerator creates a Probe from a ProbeDefinition
// Different generators handle different resource types (file, port, etc.)
type ProbeGenerator func(ctx context.Context, def ProbeDefinition) (Probe, error)

// ProbeDefinition describes a probe to be created at runtime
// This is the interface between WorldModel entities and Cerberus probes
type ProbeDefinition struct {
	// ID is the unique identifier for the probe
	ID string `json:"id"`

	// ResourceType determines which generator to use
	ResourceType ResourceType `json:"resource_type"`

	// Target is the resource-specific target (path, port, etc.)
	Target string `json:"target"`

	// Sensitivity overrides default sensitivity for this probe
	Sensitivity *Sensitivity `json:"sensitivity,omitempty"`

	// Metadata contains resource-specific configuration
	Metadata map[string]string `json:"metadata,omitempty"`
}

var (
	// validIDRegex strictly limits IDs to alphanumeric, dash, underscore, and dot
	validIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)
)

// Maximum constraints for adversarial protection — used as defaults in ValidationLimits.
// Override per-factory via NewProbeFactoryWithLimits instead of changing these constants.
const (
	MaxProbeIDLength     = 128
	MaxProbeTargetLength = 1024
	MaxMetadataKeys      = 50
	MaxMetadataValueLen  = 1024
)

// ValidationLimits configures the bounds enforced by ProbeDefinition.ValidateWith.
// All defaults are intentionally conservative to prevent adversarial payloads.
// If your workload requires larger metadata (e.g. LLM prompt configs), raise
// only the specific field you need; leave the others at their defaults.
type ValidationLimits struct {
	// MaxIDLength is the maximum byte length of a ProbeDefinition.ID.
	MaxIDLength int
	// MaxTargetLength is the maximum byte length of ProbeDefinition.Target.
	MaxTargetLength int
	// MaxMetadataKeys is the maximum number of keys in ProbeDefinition.Metadata.
	MaxMetadataKeys int
	// MaxMetadataValueLen is the maximum byte length of any single metadata value.
	MaxMetadataValueLen int
}

// DefaultValidationLimits returns conservative limits aligned with the package constants.
// These are the same values enforced by the zero-config Validate() method.
func DefaultValidationLimits() ValidationLimits {
	return ValidationLimits{
		MaxIDLength:         MaxProbeIDLength,
		MaxTargetLength:     MaxProbeTargetLength,
		MaxMetadataKeys:     MaxMetadataKeys,
		MaxMetadataValueLen: MaxMetadataValueLen,
	}
}

// Validate checks the ProbeDefinition against the package-default limits.
// For custom limits use ValidateWith.
func (d ProbeDefinition) Validate() error {
	return d.ValidateWith(DefaultValidationLimits())
}

// ValidateWith checks the ProbeDefinition against caller-supplied limits.
// Useful when the operator has legitimately higher bounds (e.g. AI metadata)
// while still blocking obviously adversarial inputs.
func (d ProbeDefinition) ValidateWith(lim ValidationLimits) error {
	if d.ID == "" {
		return fmt.Errorf("probe definition ID cannot be empty")
	}
	if len(d.ID) > lim.MaxIDLength {
		return fmt.Errorf("probe definition ID exceeds maximum length of %d", lim.MaxIDLength)
	}
	if !validIDRegex.MatchString(d.ID) {
		return fmt.Errorf("probe definition ID contains invalid characters: must match ^[a-zA-Z0-9_\\-\\.]+$")
	}

	if d.Target == "" {
		return fmt.Errorf("probe definition target cannot be empty")
	}
	if len(d.Target) > lim.MaxTargetLength {
		return fmt.Errorf("probe definition target exceeds maximum length of %d", lim.MaxTargetLength)
	}

	if d.Metadata != nil {
		if len(d.Metadata) > lim.MaxMetadataKeys {
			return fmt.Errorf("probe metadata exceeds maximum allowed keys (%d)", lim.MaxMetadataKeys)
		}
		for k, v := range d.Metadata {
			if len(v) > lim.MaxMetadataValueLen {
				return fmt.Errorf("probe metadata value for key %q exceeds maximum length (%d)", k, lim.MaxMetadataValueLen)
			}
		}
	}

	return nil
}

// ProbeFactory creates probes dynamically from definitions
// Thread-safe for concurrent registration and creation
type ProbeFactory struct {
	mu         sync.RWMutex
	generators map[ResourceType]ProbeGenerator
	limits     ValidationLimits
}

// NewProbeFactory creates a ProbeFactory with default validation limits.
func NewProbeFactory() *ProbeFactory {
	return &ProbeFactory{
		generators: make(map[ResourceType]ProbeGenerator),
		limits:     DefaultValidationLimits(),
	}
}

// NewProbeFactoryWithLimits creates a ProbeFactory with caller-supplied validation limits.
// Use this when the default limits are too restrictive for your workload (e.g. large AI
// metadata payloads). Only raise the specific field you need; leave the others at their
// defaults by starting from DefaultValidationLimits() and overriding fields.
func NewProbeFactoryWithLimits(limits ValidationLimits) *ProbeFactory {
	return &ProbeFactory{
		generators: make(map[ResourceType]ProbeGenerator),
		limits:     limits,
	}
}

// RegisterGenerator registers a generator for a resource type
// Thread-safe: can be called during runtime
func (f *ProbeFactory) RegisterGenerator(rt ResourceType, gen ProbeGenerator) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.generators[rt] = gen
}

// HasGenerator checks if a generator is registered for a resource type
func (f *ProbeFactory) HasGenerator(rt ResourceType) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.generators[rt]
	return ok
}

// CreateProbe creates a single probe from a definition
func (f *ProbeFactory) CreateProbe(ctx context.Context, def ProbeDefinition) (Probe, error) {
	if err := def.ValidateWith(f.limits); err != nil {
		return nil, fmt.Errorf("invalid probe definition: %w", err)
	}

	f.mu.RLock()
	gen, ok := f.generators[def.ResourceType]
	f.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no generator registered for resource type: %v", def.ResourceType)
	}

	return gen(ctx, def)
}

// CreateProbesFromDefinitions creates multiple probes from definitions
// Returns successful probes and any errors encountered
// Partial success is supported - some probes may fail while others succeed
func (f *ProbeFactory) CreateProbesFromDefinitions(ctx context.Context, defs []ProbeDefinition) ([]Probe, []error) {
	probes := make([]Probe, 0, len(defs))
	errors := make([]error, 0)

	for _, def := range defs {
		probe, err := f.CreateProbe(ctx, def)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to create probe %q: %w", def.ID, err))
			continue
		}
		probes = append(probes, probe)
	}

	return probes, errors
}

// =============================================================================
// GENERIC PROBE IMPLEMENTATION
// =============================================================================

// GenericProbe is a runtime-generated probe that uses a check function
// This allows probes to be created without writing custom types
type GenericProbe struct {
	def     ProbeDefinition
	checkFn func(ctx context.Context, target string) (uint64, error)
}

// NewGenericProbe creates a new generic probe with a custom check function
func NewGenericProbe(def ProbeDefinition, checkFn func(ctx context.Context, target string) (uint64, error)) *GenericProbe {
	return &GenericProbe{
		def:     def,
		checkFn: checkFn,
	}
}

// ID returns the probe's unique identifier
func (p *GenericProbe) ID() string {
	return p.def.ID
}

// ResourceType returns the type of resource being monitored
func (p *GenericProbe) ResourceType() ResourceType {
	return p.def.ResourceType
}

// Probe executes the check function and returns the current state
func (p *GenericProbe) Probe(ctx context.Context) (State, error) {
	var hash uint64
	var err error

	if p.checkFn != nil {
		hash, err = p.checkFn(ctx, p.def.Target)
		if err != nil {
			return State{}, err
		}
	}

	return State{
		ResourceID: p.def.ID,
		Hash:       hash,
		Timestamp:  time.Now(),
		Metadata:   p.def.Metadata,
	}, nil
}

// Target returns the probe's target (file path, port, etc.)
func (p *GenericProbe) Target() string {
	return p.def.Target
}

// Definition returns the original probe definition
func (p *GenericProbe) Definition() ProbeDefinition {
	return p.def
}

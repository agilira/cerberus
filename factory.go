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

// Validate checks that the ProbeDefinition is valid
func (d ProbeDefinition) Validate() error {
	if d.ID == "" {
		return fmt.Errorf("probe definition ID cannot be empty")
	}
	if d.Target == "" {
		return fmt.Errorf("probe definition target cannot be empty")
	}
	return nil
}

// ProbeFactory creates probes dynamically from definitions
// Thread-safe for concurrent registration and creation
type ProbeFactory struct {
	mu         sync.RWMutex
	generators map[ResourceType]ProbeGenerator
}

// NewProbeFactory creates a new ProbeFactory
func NewProbeFactory() *ProbeFactory {
	return &ProbeFactory{
		generators: make(map[ResourceType]ProbeGenerator),
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
	if err := def.Validate(); err != nil {
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

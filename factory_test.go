// factory_test.go: Tests for dynamic Probe factory
//
// TDD: Tests first, then implementation.
// The factory generates probes from external entity definitions (like WorldModel).
// No recompilation needed - probes are generated at runtime.
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package cerberus

import (
	"context"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// UNIT TESTS
// =============================================================================

func TestNewProbeFactory(t *testing.T) {
	f := NewProbeFactory()
	if f == nil {
		t.Fatal("NewProbeFactory returned nil")
	}
}

func TestProbeFactory_RegisterGenerator(t *testing.T) {
	f := NewProbeFactory()

	gen := func(ctx context.Context, def ProbeDefinition) (Probe, error) {
		return &genericProbe{def: def}, nil
	}

	f.RegisterGenerator(ResourceFile, gen)

	// Verify generator is registered
	if !f.HasGenerator(ResourceFile) {
		t.Error("expected generator to be registered for ResourceFile")
	}
}

func TestProbeFactory_CreateProbe(t *testing.T) {
	f := NewProbeFactory()

	gen := func(ctx context.Context, def ProbeDefinition) (Probe, error) {
		return &genericProbe{def: def}, nil
	}
	f.RegisterGenerator(ResourceFile, gen)

	def := ProbeDefinition{
		ID:           "test-file-probe",
		ResourceType: ResourceFile,
		Target:       "/etc/passwd",
		Metadata:     map[string]string{"owner": "root"},
	}

	probe, err := f.CreateProbe(context.Background(), def)
	if err != nil {
		t.Fatalf("CreateProbe failed: %v", err)
	}

	if probe.ID() != "test-file-probe" {
		t.Errorf("expected ID=test-file-probe, got %s", probe.ID())
	}
	if probe.ResourceType() != ResourceFile {
		t.Errorf("expected ResourceType=File, got %v", probe.ResourceType())
	}
}

func TestProbeFactory_CreateProbe_NoGenerator(t *testing.T) {
	f := NewProbeFactory()

	def := ProbeDefinition{
		ID:           "orphan-probe",
		ResourceType: ResourcePort, // No generator registered
		Target:       "22",
	}

	_, err := f.CreateProbe(context.Background(), def)
	if err == nil {
		t.Error("expected error when no generator registered")
	}
}

func TestProbeFactory_CreateProbesFromDefinitions(t *testing.T) {
	f := NewProbeFactory()

	gen := func(ctx context.Context, def ProbeDefinition) (Probe, error) {
		return &genericProbe{def: def}, nil
	}
	f.RegisterGenerator(ResourceFile, gen)
	f.RegisterGenerator(ResourcePort, gen)

	defs := []ProbeDefinition{
		{ID: "file-1", ResourceType: ResourceFile, Target: "/etc/passwd"},
		{ID: "file-2", ResourceType: ResourceFile, Target: "/etc/shadow"},
		{ID: "port-22", ResourceType: ResourcePort, Target: "22"},
	}

	probes, errs := f.CreateProbesFromDefinitions(context.Background(), defs)

	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(errs), errs)
	}
	if len(probes) != 3 {
		t.Errorf("expected 3 probes, got %d", len(probes))
	}
}

func TestProbeFactory_CreateProbesFromDefinitions_PartialFailure(t *testing.T) {
	f := NewProbeFactory()

	gen := func(ctx context.Context, def ProbeDefinition) (Probe, error) {
		return &genericProbe{def: def}, nil
	}
	f.RegisterGenerator(ResourceFile, gen)
	// No generator for ResourcePort

	defs := []ProbeDefinition{
		{ID: "file-1", ResourceType: ResourceFile, Target: "/etc/passwd"},
		{ID: "port-22", ResourceType: ResourcePort, Target: "22"}, // Will fail
	}

	probes, errs := f.CreateProbesFromDefinitions(context.Background(), defs)

	if len(probes) != 1 {
		t.Errorf("expected 1 successful probe, got %d", len(probes))
	}
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
}

// =============================================================================
// PROBE DEFINITION TESTS
// =============================================================================

func TestProbeDefinition_Validate(t *testing.T) {
	tests := []struct {
		name    string
		def     ProbeDefinition
		wantErr bool
	}{
		{
			name:    "valid",
			def:     ProbeDefinition{ID: "test", ResourceType: ResourceFile, Target: "/path"},
			wantErr: false,
		},
		{
			name:    "empty_id",
			def:     ProbeDefinition{ID: "", ResourceType: ResourceFile, Target: "/path"},
			wantErr: true,
		},
		{
			name:    "empty_target",
			def:     ProbeDefinition{ID: "test", ResourceType: ResourceFile, Target: ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.def.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// GENERIC PROBE TESTS (runtime-generated)
// =============================================================================

func TestGenericProbe_ID(t *testing.T) {
	p := &genericProbe{def: ProbeDefinition{ID: "my-probe"}}
	if p.ID() != "my-probe" {
		t.Errorf("expected ID=my-probe, got %s", p.ID())
	}
}

func TestGenericProbe_ResourceType(t *testing.T) {
	p := &genericProbe{def: ProbeDefinition{ResourceType: ResourceSecret}}
	if p.ResourceType() != ResourceSecret {
		t.Errorf("expected ResourceType=Secret, got %v", p.ResourceType())
	}
}

func TestGenericProbe_Probe(t *testing.T) {
	called := false
	checkFn := func(ctx context.Context, target string) (uint64, error) {
		called = true
		return 12345, nil
	}

	p := &genericProbe{
		def:     ProbeDefinition{ID: "check-probe", Target: "/test"},
		checkFn: checkFn,
	}

	state, err := p.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe() failed: %v", err)
	}
	if !called {
		t.Error("expected checkFn to be called")
	}
	if state.Hash != 12345 {
		t.Errorf("expected Hash=12345, got %d", state.Hash)
	}
}

// =============================================================================
// CONCURRENCY TESTS
// =============================================================================

func TestProbeFactory_ConcurrentCreate(t *testing.T) {
	f := NewProbeFactory()

	gen := func(ctx context.Context, def ProbeDefinition) (Probe, error) {
		time.Sleep(1 * time.Millisecond) // Simulate work
		return &genericProbe{def: def}, nil
	}
	f.RegisterGenerator(ResourceFile, gen)

	var wg sync.WaitGroup
	errs := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			def := ProbeDefinition{
				ID:           "probe-" + string(rune('a'+id%26)),
				ResourceType: ResourceFile,
				Target:       "/test",
			}
			_, err := f.CreateProbe(context.Background(), def)
			if err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent create failed: %v", err)
	}
}

func TestProbeFactory_ConcurrentRegisterAndCreate(t *testing.T) {
	f := NewProbeFactory()

	gen := func(ctx context.Context, def ProbeDefinition) (Probe, error) {
		return &genericProbe{def: def}, nil
	}

	var wg sync.WaitGroup

	// Register generators concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(rt ResourceType) {
			defer wg.Done()
			f.RegisterGenerator(rt, gen)
		}(ResourceType(i))
	}

	// Create probes concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			def := ProbeDefinition{
				ID:           "probe-" + string(rune('a'+id)),
				ResourceType: ResourceFile,
				Target:       "/test",
			}
			// May fail if generator not yet registered - that's ok
			_, _ = f.CreateProbe(context.Background(), def)
		}(i)
	}

	wg.Wait()
	// No race conditions = test passes
}

// =============================================================================
// MOCK GENERIC PROBE (for testing)
// =============================================================================

type genericProbe struct {
	def     ProbeDefinition
	checkFn func(ctx context.Context, target string) (uint64, error)
}

func (p *genericProbe) ID() string {
	return p.def.ID
}

func (p *genericProbe) ResourceType() ResourceType {
	return p.def.ResourceType
}

func (p *genericProbe) Probe(ctx context.Context) (State, error) {
	var hash uint64
	if p.checkFn != nil {
		var err error
		hash, err = p.checkFn(ctx, p.def.Target)
		if err != nil {
			return State{}, err
		}
	} else {
		hash = 12345 // Default stable hash
	}

	return State{
		ResourceID: p.def.ID,
		Hash:       hash,
		Timestamp:  time.Now(),
		Metadata:   p.def.Metadata,
	}, nil
}

// =============================================================================
// VALIDATION LIMITS TESTS
// =============================================================================

// TestValidationLimits_DefaultsMatchConstants ensures DefaultValidationLimits()
// is in sync with the exported constants so callers who start from the defaults
// and tweak a single field get the expected base values.
func TestValidationLimits_DefaultsMatchConstants(t *testing.T) {
	lim := DefaultValidationLimits()
	if lim.MaxIDLength != MaxProbeIDLength {
		t.Errorf("MaxIDLength: got %d, want %d", lim.MaxIDLength, MaxProbeIDLength)
	}
	if lim.MaxTargetLength != MaxProbeTargetLength {
		t.Errorf("MaxTargetLength: got %d, want %d", lim.MaxTargetLength, MaxProbeTargetLength)
	}
	if lim.MaxMetadataKeys != MaxMetadataKeys {
		t.Errorf("MaxMetadataKeys: got %d, want %d", lim.MaxMetadataKeys, MaxMetadataKeys)
	}
	if lim.MaxMetadataValueLen != MaxMetadataValueLen {
		t.Errorf("MaxMetadataValueLen: got %d, want %d", lim.MaxMetadataValueLen, MaxMetadataValueLen)
	}
}

// TestValidateWith_CustomMetadataLimit verifies that a factory created with
// raised metadata limits accepts definitions that would be rejected by the
// default factory. This is the primary use-case for NewProbeFactoryWithLimits:
// large AI workloads where metadata payloads exceed the conservative defaults.
func TestValidateWith_CustomMetadataLimit(t *testing.T) {
	// Build a def with 60 metadata keys — over the default of 50.
	def := ProbeDefinition{
		ID:       "ai-probe",
		Target:   "/model/weights",
		Metadata: make(map[string]string, 60),
	}
	for i := range 60 {
		def.Metadata["key-"+string(rune('a'+i%26))+string(rune('0'+i%10))] = "value"
	}

	// Default factory must reject it.
	defaultFactory := NewProbeFactory()
	if err := def.ValidateWith(defaultFactory.limits); err == nil {
		t.Fatal("default factory should reject >50 metadata keys")
	}

	// Custom factory with raised limit must accept it.
	lim := DefaultValidationLimits()
	lim.MaxMetadataKeys = 100
	customFactory := NewProbeFactoryWithLimits(lim)
	if err := def.ValidateWith(customFactory.limits); err != nil {
		t.Errorf("custom factory rejected a valid definition: %v", err)
	}
}

// TestNewProbeFactoryWithLimits_CreateProbe verifies the full path through
// CreateProbe, not just the limit struct. The factory must use its configured
// limits when validating each definition.
func TestNewProbeFactoryWithLimits_CreateProbe(t *testing.T) {
	gen := func(ctx context.Context, def ProbeDefinition) (Probe, error) {
		return &genericProbe{def: def}, nil
	}

	// A definition with a 200-character ID — over the default MaxProbeIDLength of 128.
	longID := ""
	for range 200 {
		longID += "a"
	}
	def := ProbeDefinition{ID: longID, ResourceType: ResourceFile, Target: "/tmp/f"}

	// Default factory must refuse it.
	defaultF := NewProbeFactory()
	defaultF.RegisterGenerator(ResourceFile, gen)
	if _, err := defaultF.CreateProbe(context.Background(), def); err == nil {
		t.Fatal("default factory should reject ID > 128 chars")
	}

	// Custom factory with larger ID limit must accept it.
	lim := DefaultValidationLimits()
	lim.MaxIDLength = 256
	customF := NewProbeFactoryWithLimits(lim)
	customF.RegisterGenerator(ResourceFile, gen)
	if _, err := customF.CreateProbe(context.Background(), def); err != nil {
		t.Errorf("custom factory rejected valid long ID: %v", err)
	}
}

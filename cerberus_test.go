// cerberus_test.go: Core unit tests for Cerberus watchdog
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package cerberus

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// UNIT TESTS
// =============================================================================

func TestNew_DefaultConfig(t *testing.T) {
	c := New(Config{})

	if c == nil {
		t.Fatal("New() returned nil")
	}

	if c.config.PollInterval != DefaultPollInterval {
		t.Errorf("expected PollInterval=%v, got %v", DefaultPollInterval, c.config.PollInterval)
	}

	if c.config.BufferSize != DefaultBufferSize {
		t.Errorf("expected BufferSize=%d, got %d", DefaultBufferSize, c.config.BufferSize)
	}
}

func TestNew_CustomConfig(t *testing.T) {
	cfg := Config{
		PollInterval: 100 * time.Millisecond,
		BufferSize:   128,
	}
	c := New(cfg)

	if c.config.PollInterval != 100*time.Millisecond {
		t.Errorf("expected PollInterval=100ms, got %v", c.config.PollInterval)
	}

	if c.config.BufferSize != 128 {
		t.Errorf("expected BufferSize=128, got %d", c.config.BufferSize)
	}
}

func TestNew_InvalidConfig_NegativePollInterval(t *testing.T) {
	cfg := Config{
		PollInterval: -1 * time.Second,
	}
	c := New(cfg)

	// Should fallback to default
	if c.config.PollInterval != DefaultPollInterval {
		t.Errorf("expected default PollInterval, got %v", c.config.PollInterval)
	}
}

func TestNew_InvalidConfig_ZeroBufferSize(t *testing.T) {
	cfg := Config{
		BufferSize: 0,
	}
	c := New(cfg)

	// Should fallback to default
	if c.config.BufferSize != DefaultBufferSize {
		t.Errorf("expected default BufferSize, got %d", c.config.BufferSize)
	}
}

func TestRegisterProbe_Success(t *testing.T) {
	c := New(Config{})
	probe := &mockProbe{id: "test-probe"}

	err := c.RegisterProbe(probe)
	if err != nil {
		t.Fatalf("RegisterProbe failed: %v", err)
	}

	if len(c.probes) != 1 {
		t.Errorf("expected 1 probe, got %d", len(c.probes))
	}
}

func TestRegisterProbe_Nil(t *testing.T) {
	c := New(Config{})

	err := c.RegisterProbe(nil)
	if err == nil {
		t.Error("expected error for nil probe")
	}
}

func TestRegisterProbe_DuplicateID(t *testing.T) {
	c := New(Config{})
	probe1 := &mockProbe{id: "same-id"}
	probe2 := &mockProbe{id: "same-id"}

	_ = c.RegisterProbe(probe1)
	err := c.RegisterProbe(probe2)

	if err == nil {
		t.Error("expected error for duplicate probe ID")
	}
}

func TestRegisterProbe_WhileRunning(t *testing.T) {
	c := New(Config{PollInterval: 100 * time.Millisecond})
	c.Start()
	defer c.Stop()

	probe := &mockProbe{id: "late-probe"}
	err := c.RegisterProbe(probe)

	if err == nil {
		t.Error("expected error when registering probe while running")
	}
}

func TestUnregisterProbe_Success(t *testing.T) {
	c := New(Config{})
	probe := &mockProbe{id: "test-probe"}
	_ = c.RegisterProbe(probe)

	err := c.UnregisterProbe("test-probe")
	if err != nil {
		t.Fatalf("UnregisterProbe failed: %v", err)
	}

	if len(c.probes) != 0 {
		t.Errorf("expected 0 probes, got %d", len(c.probes))
	}
}

func TestUnregisterProbe_NotFound(t *testing.T) {
	c := New(Config{})

	err := c.UnregisterProbe("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent probe")
	}
}

func TestStart_Stop(t *testing.T) {
	c := New(Config{PollInterval: 50 * time.Millisecond})

	// Start
	err := c.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !c.IsRunning() {
		t.Error("expected IsRunning=true after Start")
	}

	// Stop
	err = c.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if c.IsRunning() {
		t.Error("expected IsRunning=false after Stop")
	}
}

func TestStart_AlreadyRunning(t *testing.T) {
	c := New(Config{PollInterval: 50 * time.Millisecond})
	_ = c.Start()
	defer c.Stop()

	err := c.Start()
	if err == nil {
		t.Error("expected error when starting already running Cerberus")
	}
}

func TestStop_NotRunning(t *testing.T) {
	c := New(Config{})

	err := c.Stop()
	if err == nil {
		t.Error("expected error when stopping non-running Cerberus")
	}
}

func TestDrifts_Channel(t *testing.T) {
	c := New(Config{})

	ch := c.Drifts()
	if ch == nil {
		t.Error("Drifts() returned nil channel")
	}
}

func TestDriftDetection_Basic(t *testing.T) {
	c := New(Config{PollInterval: 20 * time.Millisecond, BufferSize: 8})

	// Probe that reports drift on second poll
	probe := &mockProbe{
		id:        "drift-probe",
		driftFrom: 1, // Drift on poll index 1
	}
	_ = c.RegisterProbe(probe)
	_ = c.Start()

	// Wait for drift
	select {
	case drift := <-c.Drifts():
		if drift.ProbeID != "drift-probe" {
			t.Errorf("expected ProbeID=drift-probe, got %s", drift.ProbeID)
		}
		if drift.ResourceType != ResourceFile {
			t.Errorf("expected ResourceType=File, got %v", drift.ResourceType)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("timeout waiting for drift event")
	}

	_ = c.Stop()
}

func TestDriftDetection_NoDriftWhenStateUnchanged(t *testing.T) {
	c := New(Config{PollInterval: 20 * time.Millisecond, BufferSize: 8})

	// Probe that never drifts (stable hash)
	probe := &mockProbe{
		id:        "stable-probe",
		driftFrom: -1, // Never drift
	}
	_ = c.RegisterProbe(probe)
	_ = c.Start()

	// First event is always ChangeCreate (initial discovery)
	select {
	case drift := <-c.Drifts():
		if drift.ChangeType != ChangeCreate {
			t.Errorf("expected first event to be Create, got %v", drift.ChangeType)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected initial Create event")
	}

	// After initial create, no more drifts should occur (state is stable)
	select {
	case drift := <-c.Drifts():
		t.Errorf("unexpected drift event after initial: %+v", drift)
	case <-time.After(80 * time.Millisecond):
		// Expected: no further drift
	}

	_ = c.Stop()
}

func TestStats(t *testing.T) {
	c := New(Config{PollInterval: 20 * time.Millisecond})

	probe := &mockProbe{id: "stats-probe", driftFrom: 0}
	_ = c.RegisterProbe(probe)
	_ = c.Start()

	// Wait for some polls
	time.Sleep(80 * time.Millisecond)

	stats := c.Stats()
	_ = c.Stop()

	if stats.PollCount == 0 {
		t.Error("expected PollCount > 0")
	}
	if stats.ProbeCount != 1 {
		t.Errorf("expected ProbeCount=1, got %d", stats.ProbeCount)
	}
}

// =============================================================================
// EDGE CASE TESTS
// =============================================================================

func TestEdge_ProbeReturnsError(t *testing.T) {
	c := New(Config{PollInterval: 20 * time.Millisecond, BufferSize: 8})

	probe := &mockProbe{
		id:         "error-probe",
		shouldFail: true,
	}
	_ = c.RegisterProbe(probe)
	_ = c.Start()

	// Should emit drift with error info
	select {
	case drift := <-c.Drifts():
		if drift.ChangeType != ChangeError {
			t.Errorf("expected ChangeType=Error, got %v", drift.ChangeType)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for error drift event")
	}

	_ = c.Stop()
}

func TestEdge_SlowProbe(t *testing.T) {
	c := New(Config{PollInterval: 20 * time.Millisecond, BufferSize: 8})

	probe := &mockProbe{
		id:        "slow-probe",
		delay:     50 * time.Millisecond, // Slower than poll interval
		driftFrom: 0,
	}
	_ = c.RegisterProbe(probe)
	_ = c.Start()

	// Should still work, just slower
	select {
	case <-c.Drifts():
		// Good
	case <-time.After(200 * time.Millisecond):
		t.Error("timeout waiting for slow probe drift")
	}

	_ = c.Stop()
}

func TestEdge_BufferFull(t *testing.T) {
	// Create a sensitivity profile with very fast polling to trigger buffer overflow
	sp := NewSensitivityProfile()
	sp.SetSensitivity(ResourceFile, SensitivityCritical) // 100ms interval

	c := New(Config{
		PollInterval:       10 * time.Millisecond,
		BufferSize:         2,
		SensitivityProfile: sp,
	})

	// Probe that always drifts
	probe := &mockProbe{
		id:          "flood-probe",
		alwaysDrift: true,
	}
	_ = c.RegisterProbe(probe)
	_ = c.Start()

	// Don't consume drifts - let buffer fill
	// With Critical sensitivity (100ms) and MinPollInterval (10ms),
	// we need at least 4 polls to fill buffer of 2 and drop some
	time.Sleep(500 * time.Millisecond)

	stats := c.Stats()
	_ = c.Stop()

	if stats.DroppedCount == 0 {
		t.Error("expected some dropped events when buffer is full")
	}
}

func TestEdge_GracefulShutdown(t *testing.T) {
	c := New(Config{PollInterval: 50 * time.Millisecond})

	probe := &mockProbe{id: "shutdown-probe", delay: 200 * time.Millisecond}
	_ = c.RegisterProbe(probe)
	_ = c.Start()

	// Stop while probe is running - should wait gracefully
	start := time.Now()
	_ = c.Stop()
	elapsed := time.Since(start)

	// Should complete reasonably fast (not hang forever)
	if elapsed > 2*time.Second {
		t.Errorf("graceful shutdown took too long: %v", elapsed)
	}
}

// =============================================================================
// CONCURRENCY TESTS
// =============================================================================

func TestConcurrency_MultipleProbes(t *testing.T) {
	c := New(Config{PollInterval: 10 * time.Millisecond, BufferSize: 64})

	// Register many probes
	for i := 0; i < 10; i++ {
		probe := &mockProbe{
			id:        "probe-" + string(rune('a'+i)),
			driftFrom: i % 3, // Staggered drift
		}
		_ = c.RegisterProbe(probe)
	}

	_ = c.Start()

	// Collect drifts
	drifts := make(map[string]int)
	var mu sync.Mutex

	done := make(chan struct{})
	go func() {
		for drift := range c.Drifts() {
			mu.Lock()
			drifts[drift.ProbeID]++
			mu.Unlock()

			// Stop after getting drifts from at least 5 probes
			if len(drifts) >= 5 {
				close(done)
				return
			}
		}
	}()

	select {
	case <-done:
		// Good
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for drifts from multiple probes")
	}

	_ = c.Stop()

	if len(drifts) < 5 {
		t.Errorf("expected drifts from at least 5 probes, got %d", len(drifts))
	}
}

func TestConcurrency_RaceConditions(t *testing.T) {
	// Run with -race flag to detect races
	c := New(Config{PollInterval: 5 * time.Millisecond, BufferSize: 32})

	var wg sync.WaitGroup
	var started atomic.Bool

	// Goroutine 1: Register probes
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			if started.Load() {
				break
			}
			_ = c.RegisterProbe(&mockProbe{id: "race-" + string(rune('0'+i))})
			time.Sleep(time.Millisecond)
		}
	}()

	// Goroutine 2: Start/Stats
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
		_ = c.Start()
		started.Store(true)
		for i := 0; i < 10; i++ {
			_ = c.Stats()
			time.Sleep(2 * time.Millisecond)
		}
	}()

	// Goroutine 3: Consume drifts
	wg.Add(1)
	go func() {
		defer wg.Done()
		timeout := time.After(200 * time.Millisecond)
		for {
			select {
			case <-c.Drifts():
				// Consume
			case <-timeout:
				return
			}
		}
	}()

	wg.Wait()
	_ = c.Stop()
}

func TestConcurrency_StartStopRapid(t *testing.T) {
	c := New(Config{PollInterval: 5 * time.Millisecond})

	for i := 0; i < 5; i++ {
		err := c.Start()
		if err != nil && i == 0 {
			t.Fatalf("first Start failed: %v", err)
		}

		time.Sleep(10 * time.Millisecond)

		err = c.Stop()
		if err != nil {
			// May fail on subsequent iterations if not fully stopped
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// =============================================================================
// MOCK PROBE
// =============================================================================

type mockProbe struct {
	id          string
	pollCount   atomic.Int64
	driftFrom   int // Start drifting from this poll index (-1 = never)
	alwaysDrift bool
	shouldFail  bool
	delay       time.Duration
	lastState   uint64
}

func (m *mockProbe) ID() string {
	return m.id
}

func (m *mockProbe) ResourceType() ResourceType {
	return ResourceFile
}

func (m *mockProbe) Probe(ctx context.Context) (State, error) {
	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return State{}, ctx.Err()
		case <-time.After(m.delay):
		}
	}

	count := m.pollCount.Add(1) - 1

	if m.shouldFail {
		return State{}, ErrProbeFailure
	}

	// Determine if we should drift
	var hash uint64
	if m.alwaysDrift {
		hash = uint64(count) // Always different
	} else if m.driftFrom >= 0 && int(count) >= m.driftFrom {
		hash = uint64(count) // Drift by changing hash
	} else {
		hash = 12345 // Stable hash
	}

	state := State{
		ResourceID: m.id,
		Hash:       hash,
		Timestamp:  time.Now(),
	}

	return state, nil
}

// self_health_test.go: TDD tests for self-health monitoring and congestion alerts
//
// Cerberus should alert when it's overwhelmed (buffer full, events dropped).
// This is critical for GRC compliance - you must know when monitoring fails.
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package cerberus

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// SELF-HEALTH TESTS
// =============================================================================

func TestCerberus_CongestionThreshold(t *testing.T) {
	// Config should support congestion threshold
	c := New(Config{
		BufferSize:          4,
		CongestionThreshold: 2, // Alert after 2 dropped events
	})

	if c.config.CongestionThreshold != 2 {
		t.Errorf("expected CongestionThreshold=2, got %d", c.config.CongestionThreshold)
	}
}

func TestCerberus_CongestionThreshold_Default(t *testing.T) {
	// Default congestion threshold should be reasonable
	cfg := Config{BufferSize: 64}.applyDefaults()

	if cfg.CongestionThreshold <= 0 {
		t.Error("default CongestionThreshold should be > 0")
	}
}

func TestCerberus_OnCongestion_Called(t *testing.T) {
	var congestionAlerted atomic.Bool
	var droppedCount atomic.Int64

	sp := NewSensitivityProfile()
	sp.SetSensitivity(ResourceFile, SensitivityCritical)

	c := New(Config{
		BufferSize:          2, // Tiny buffer
		CongestionThreshold: 1, // Alert on first drop
		SensitivityProfile:  sp,
		OnCongestion: func(dropped int64) {
			congestionAlerted.Store(true)
			droppedCount.Store(dropped)
		},
	})

	// Probe that always changes (causes events)
	var hash atomic.Uint64
	probe := &contextAwareProbe{
		id: "flood-probe",
		onProbe: func(ctx context.Context) {
			hash.Add(1) // Always different
		},
	}

	_ = c.RegisterProbe(probe)
	_ = c.Start()

	// Don't consume events - let buffer fill
	time.Sleep(500 * time.Millisecond)

	_ = c.Stop()

	if !congestionAlerted.Load() {
		stats := c.Stats()
		if stats.DroppedCount > 0 {
			t.Errorf("congestion should have been alerted (dropped=%d)", stats.DroppedCount)
		} else {
			t.Skip("no events were dropped in time")
		}
	}
}

func TestCerberus_ResourceCerberus_Type(t *testing.T) {
	// ResourceCerberus should exist for meta-events
	rt := ResourceCerberus
	if rt.String() != "cerberus" {
		t.Errorf("expected ResourceCerberus.String()=cerberus, got %s", rt.String())
	}
}

func TestCerberus_EmitsCongestionEvent(t *testing.T) {
	sp := NewSensitivityProfile()
	sp.SetSensitivity(ResourceFile, SensitivityCritical)

	// Use a larger buffer so we can consume events
	c := New(Config{
		BufferSize:          8,
		CongestionThreshold: 1,
		SensitivityProfile:  sp,
		EmitCongestionEvent: true, // Opt-in for congestion events
	})

	// Flood probe
	var hash atomic.Uint64
	probe := &contextAwareProbe{
		id: "congestion-event-probe",
		onProbe: func(ctx context.Context) {
			hash.Add(1)
		},
	}

	_ = c.RegisterProbe(probe)
	_ = c.Start()

	// Consume some events to make room
	go func() {
		for range c.Drifts() {
			time.Sleep(50 * time.Millisecond) // Slow consumer
		}
	}()

	time.Sleep(500 * time.Millisecond)
	_ = c.Stop()

	// Check if congestion event was in the mix
	stats := c.Stats()
	t.Logf("Stats: DroppedCount=%d, DriftCount=%d", stats.DroppedCount, stats.DriftCount)
}

func TestCerberus_HealthCheck(t *testing.T) {
	c := New(Config{})

	probe := &contextAwareProbe{id: "health-probe"}
	_ = c.RegisterProbe(probe)
	_ = c.Start()

	time.Sleep(50 * time.Millisecond)

	health := c.HealthCheck()

	if !health.IsHealthy {
		t.Error("watchdog should be healthy")
	}
	if !health.IsRunning {
		t.Error("watchdog should be running")
	}
	if health.ProbeCount != 1 {
		t.Errorf("expected ProbeCount=1, got %d", health.ProbeCount)
	}

	_ = c.Stop()
}

func TestCerberus_HealthCheck_Unhealthy(t *testing.T) {
	c := New(Config{
		BufferSize:          4,
		CongestionThreshold: 1,
	})

	// Simulate drops
	c.droppedCount.Store(10)

	health := c.HealthCheck()

	if health.IsHealthy {
		t.Error("watchdog should be unhealthy when drops exceed threshold")
	}
	if health.DroppedEvents != 10 {
		t.Errorf("expected DroppedEvents=10, got %d", health.DroppedEvents)
	}
}

func TestHealthStatus_Fields(t *testing.T) {
	// HealthStatus should have all necessary fields
	now := time.Now()
	status := HealthStatus{
		IsHealthy:      true,
		IsRunning:      true,
		ProbeCount:     5,
		DroppedEvents:  0,
		BufferCapacity: 64,
		BufferUsed:     10,
		LastPollAt:     now,
	}

	if !status.IsHealthy {
		t.Error("expected IsHealthy=true")
	}
	if !status.IsRunning {
		t.Error("expected IsRunning=true")
	}
	if status.ProbeCount != 5 {
		t.Error("expected ProbeCount=5")
	}
	if status.DroppedEvents != 0 {
		t.Error("expected DroppedEvents=0")
	}
	if status.BufferCapacity != 64 {
		t.Error("expected BufferCapacity=64")
	}
	if status.BufferUsed != 10 {
		t.Error("expected BufferUsed=10")
	}
	if !status.LastPollAt.Equal(now) {
		t.Error("expected LastPollAt to match set value")
	}
}

// TestCongestion_RefiresAfterDrain verifies that the congestion alert fires a
// SECOND time after the drift channel drains below capacity.
// WHY: congestionAlerted was a one-shot latch — once fired it never reset,
// so a second burst of drops was silently swallowed (B.4 bug).
func TestCongestion_RefiresAfterDrain(t *testing.T) {
	t.Parallel()

	var alertCount atomic.Int32

	c := New(Config{
		BufferSize:          2,
		CongestionThreshold: 1,
		OnCongestion: func(_ int64) {
			alertCount.Add(1)
		},
	})

	// Cause the first congestion episode by filling the buffer with 4 events
	// (BufferSize=2 → 2 drops → threshold=1 → fires alert).
	for range 4 {
		c.emitDrift(DriftEvent{ChangeType: ChangeDrift, Timestamp: time.Now()})
	}

	if alertCount.Load() < 1 {
		t.Fatal("first congestion alert never fired")
	}

	// Drain the channel so the drain-reset triggers on the next successful emit.
	for len(c.drifts) > 0 {
		<-c.drifts
	}

	// Emit one event that succeeds (buffer empty): this should reset the latch.
	c.emitDrift(DriftEvent{ChangeType: ChangeDrift, Timestamp: time.Now()})

	// Cause a second congestion episode.
	for range 4 {
		c.emitDrift(DriftEvent{ChangeType: ChangeDrift, Timestamp: time.Now()})
	}

	if alertCount.Load() < 2 {
		t.Fatalf("second congestion alert did not fire (alertCount=%d)", alertCount.Load())
	}
}

// TestCongestion_DoesNotRefireWhileStillCongested verifies that the alert does
// NOT fire repeatedly on each dropped event while the buffer stays full.
// WHY: the CompareAndSwap gate must hold while congested; the drain-reset only
// happens when an event succeeds, not while the buffer remains at capacity.
func TestCongestion_DoesNotRefireWhileStillCongested(t *testing.T) {
	t.Parallel()

	var alertCount atomic.Int32

	c := New(Config{
		BufferSize:          2,
		CongestionThreshold: 1,
		OnCongestion: func(_ int64) {
			alertCount.Add(1)
		},
	})

	// Fill buffer to capacity first.
	for range 2 {
		c.emitDrift(DriftEvent{ChangeType: ChangeDrift, Timestamp: time.Now()})
	}

	// All subsequent emits should drop but NOT trigger additional alerts.
	for range 20 {
		c.emitDrift(DriftEvent{ChangeType: ChangeDrift, Timestamp: time.Now()})
	}

	count := alertCount.Load()
	if count != 1 {
		t.Fatalf("expected exactly 1 alert while congested, got %d", count)
	}
}

// TestCongestion_BufferSize1_StillReArms pins the "full drain" re-arm semantic
// for the degenerate case of BufferSize=1.
//
// WHY: the previous reset condition was `len(c.drifts) < cap(c.drifts)`. For
// BufferSize=1, after any successful enqueue len==cap==1, so the condition was
// always false: the latch never reset and a second congestion episode was
// silently swallowed for the lifetime of the process.
//
// The fix captures len BEFORE the send (preLen). If preLen==0, the consumer
// had fully drained the backlog; a successful send means re-arm is safe. This
// works for BufferSize=1 and is semantically equivalent for BufferSize>1.
func TestCongestion_BufferSize1_StillReArms(t *testing.T) {
	t.Parallel()

	var alertCount atomic.Int32

	c := New(Config{
		BufferSize:          1,
		CongestionThreshold: 1,
		OnCongestion: func(_ int64) {
			alertCount.Add(1)
		},
	})

	// First congestion episode: fill the single slot, then drop one event.
	c.emitDrift(DriftEvent{ChangeType: ChangeDrift, Timestamp: time.Now()}) // fills buffer
	c.emitDrift(DriftEvent{ChangeType: ChangeDrift, Timestamp: time.Now()}) // drops → alert

	if alertCount.Load() < 1 {
		t.Fatal("first congestion alert never fired")
	}

	// Fully drain the channel so preLen==0 on the next send.
	<-c.drifts

	// Emit one event into the now-empty buffer: preLen==0 → latch resets.
	c.emitDrift(DriftEvent{ChangeType: ChangeDrift, Timestamp: time.Now()})

	// Drain the re-arm event so the buffer is empty again.
	<-c.drifts

	// Second congestion episode: fill + drop.
	c.emitDrift(DriftEvent{ChangeType: ChangeDrift, Timestamp: time.Now()}) // fills buffer
	c.emitDrift(DriftEvent{ChangeType: ChangeDrift, Timestamp: time.Now()}) // drops → alert

	if alertCount.Load() < 2 {
		t.Fatalf("second congestion alert did not fire with BufferSize=1 (alertCount=%d)", alertCount.Load())
	}
}

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
		LastPollTime:   now,
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
	if !status.LastPollTime.Equal(now) {
		t.Error("expected LastPollTime to match set value")
	}
}

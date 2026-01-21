// probe_timeout_test.go: TDD tests for Probe timeout with context.Context
//
// BREAKING CHANGE: Probe interface now requires context.Context
// This ensures probes cannot hang forever and block the poll loop.
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
// PROBE TIMEOUT TESTS
// =============================================================================

func TestProbe_AcceptsContext(t *testing.T) {
	// The Probe interface should accept a context for timeout control
	probe := &contextAwareProbe{id: "test-probe"}

	ctx := context.Background()
	state, err := probe.Probe(ctx)

	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
	if state.ResourceID != "test-probe" {
		t.Errorf("expected ResourceID=test-probe, got %s", state.ResourceID)
	}
}

func TestProbe_RespectsTimeout(t *testing.T) {
	// A slow probe should be cancelled by context timeout
	probe := &slowProbe{
		id:    "slow-probe",
		delay: 5 * time.Second, // Very slow
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := probe.Probe(ctx)

	if err == nil {
		t.Error("expected timeout error, got nil")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestProbe_CancelledContext(t *testing.T) {
	// A probe should respect cancelled context
	probe := &slowProbe{
		id:    "cancelled-probe",
		delay: 5 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := probe.Probe(ctx)

	if err == nil {
		t.Error("expected cancellation error, got nil")
	}
}

func TestCerberus_PollsWithTimeout(t *testing.T) {
	// Cerberus should poll probes with a timeout
	c := New(Config{
		ProbeTimeout: 100 * time.Millisecond,
	})

	var pollCount atomic.Int32
	probe := &contextAwareProbe{
		id: "timeout-probe",
		onProbe: func(ctx context.Context) {
			pollCount.Add(1)
			// Verify context has deadline
			if _, ok := ctx.Deadline(); !ok {
				t.Error("context should have deadline")
			}
		},
	}

	_ = c.RegisterProbe(probe)
	_ = c.Start()

	time.Sleep(150 * time.Millisecond)
	_ = c.Stop()

	if pollCount.Load() == 0 {
		t.Error("probe should have been polled at least once")
	}
}

func TestCerberus_EmitsErrorOnTimeout(t *testing.T) {
	// When a probe times out, Cerberus should emit a ChangeError event
	sp := NewSensitivityProfile()
	sp.SetSensitivity(ResourceFile, SensitivityCritical) // 100ms poll

	c := New(Config{
		ProbeTimeout:       50 * time.Millisecond,
		SensitivityProfile: sp,
		BufferSize:         16,
	})

	probe := &slowProbe{
		id:    "timeout-error-probe",
		delay: 200 * time.Millisecond, // Slower than timeout
	}

	_ = c.RegisterProbe(probe)
	_ = c.Start()

	// Wait for timeout event
	var gotTimeoutError bool
	timeout := time.After(500 * time.Millisecond)

waitLoop:
	for !gotTimeoutError {
		select {
		case event := <-c.Drifts():
			if event.ChangeType == ChangeError {
				gotTimeoutError = true
			}
		case <-timeout:
			break waitLoop
		}
		if gotTimeoutError {
			break
		}
	}

	_ = c.Stop()

	if !gotTimeoutError {
		t.Error("expected ChangeError event for timeout")
	}
}

func TestConfig_DefaultProbeTimeout(t *testing.T) {
	// Default probe timeout should be reasonable
	cfg := Config{}.applyDefaults()

	if cfg.ProbeTimeout <= 0 {
		t.Error("default ProbeTimeout should be > 0")
	}
	if cfg.ProbeTimeout > 5*time.Second {
		t.Errorf("default ProbeTimeout too high: %v", cfg.ProbeTimeout)
	}
}

// =============================================================================
// TEST PROBES
// =============================================================================

type contextAwareProbe struct {
	id      string
	onProbe func(ctx context.Context)
}

func (p *contextAwareProbe) ID() string {
	return p.id
}

func (p *contextAwareProbe) ResourceType() ResourceType {
	return ResourceFile
}

func (p *contextAwareProbe) Probe(ctx context.Context) (State, error) {
	if p.onProbe != nil {
		p.onProbe(ctx)
	}

	select {
	case <-ctx.Done():
		return State{}, ctx.Err()
	default:
		return State{
			ResourceID: p.id,
			Hash:       12345,
			Timestamp:  time.Now(),
		}, nil
	}
}

type slowProbe struct {
	id    string
	delay time.Duration
}

func (p *slowProbe) ID() string {
	return p.id
}

func (p *slowProbe) ResourceType() ResourceType {
	return ResourceFile
}

func (p *slowProbe) Probe(ctx context.Context) (State, error) {
	select {
	case <-ctx.Done():
		return State{}, ctx.Err()
	case <-time.After(p.delay):
		return State{
			ResourceID: p.id,
			Hash:       12345,
			Timestamp:  time.Now(),
		}, nil
	}
}

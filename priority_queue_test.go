// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package cerberus

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestCerberus_PollLoop_Scalability verifies O(1) poll performance with priority queue.
//
// SOLUTION VERIFIED: Using a min-heap priority queue sorted by next poll time.
// Only pop probes that are due: O(k log n) where k = probes actually due.
// When no probes are due: O(1) - just peek at heap root.
//
// Previously this was O(n) because pollDueProbes() iterated ALL probes.
func TestCerberus_PollLoop_Scalability(t *testing.T) {
	// Create Cerberus with fast tick
	c := New(Config{
		PollInterval: 10 * time.Millisecond,
		ProbeTimeout: 100 * time.Millisecond,
		BufferSize:   1000,
	})

	// Register 1000 probes with varying intervals
	// Most probes have SLOW intervals (1 second), only a few are FAST (10ms)
	const totalProbes = 100

	for i := 0; i < totalProbes; i++ {
		_ = c.RegisterProbe(&scalabilityProbe{
			id:      string(rune('A'+i/26)) + string(rune('a'+i%26)),
			resType: ResourceCustom,
		})
	}

	// Start and let it run
	if err := c.Start(); err != nil {
		t.Fatalf("Failed to start: %v", err)
	}

	// Run for 500ms
	time.Sleep(500 * time.Millisecond)

	_ = c.Stop()

	stats := c.Stats()
	t.Logf("Poll count: %d", stats.PollCount)
	t.Logf("Last poll duration: %v", time.Duration(c.lastPollDuration.Load()))
	t.Logf("Registered probes: %d", stats.ProbeCount)

	// Measure actual scaling behavior
	t.Run("ScalingBehavior", func(t *testing.T) {
		testScalingBehavior(t)
	})
}

// testScalingBehavior compares poll time with different probe counts
// Key insight: O(n) happens when checking ALL probes each tick
// With priority queue, if NO probes are due, we do O(1) work
func testScalingBehavior(t *testing.T) {
	probeCounts := []int{100, 500, 1000}
	var times []time.Duration

	for _, count := range probeCounts {
		c := New(Config{
			PollInterval: 10 * time.Millisecond,
			ProbeTimeout: 50 * time.Millisecond,
			BufferSize:   100,
		})

		// All probes are scheduled for the FUTURE (1 minute from now)
		// This simulates steady-state: probes were polled, now waiting for interval
		for i := 0; i < count; i++ {
			probe := &scalabilityProbe{
				id:      string(rune('A'+i/26)) + string(rune('a'+i%26)) + string(rune('0'+i%10)),
				resType: ResourceCustom,
			}
			_ = c.RegisterProbe(probe)
			// Reschedule to 1 minute in the future (not due)
			c.scheduler.Schedule(probe.ID(), time.Now().Add(time.Minute))
		}

		// Measure poll cycle time when NO probes are due
		// Old O(n): must check all probes even if none are due
		// New O(log n): just peek at heap root, see it's not due, done
		start := time.Now()
		c.pollDueProbes()
		elapsed := time.Since(start)
		times = append(times, elapsed)

		t.Logf("Probes: %4d, Poll time (none due): %v", count, elapsed)
	}

	// With priority queue: time should be nearly constant (O(1) if none due)
	// With O(n) scan: time scales linearly
	if len(times) >= 2 {
		ratio := float64(times[len(times)-1]) / float64(times[0])
		t.Logf("Scaling ratio (1000/100 probes): %.2fx", ratio)

		// O(1) would show ~1x ratio, O(n) would show ~10x
		if ratio > 3.0 {
			t.Errorf("SCALING ISSUE: Poll time scales %.2fx with 10x more probes. "+
				"Expected O(1) when no probes due, got O(n) behavior. "+
				"Need priority queue optimization.", ratio)
		}
	}
}

// scalabilityProbe is a minimal probe for scalability testing
type scalabilityProbe struct {
	id        string
	resType   ResourceType
	pollCount atomic.Int64
}

func (p *scalabilityProbe) ID() string                 { return p.id }
func (p *scalabilityProbe) ResourceType() ResourceType { return p.resType }

func (p *scalabilityProbe) Probe(ctx context.Context) (State, error) {
	p.pollCount.Add(1)
	return State{
		ResourceID: p.id,
		Hash:       12345, // Stable hash
		Timestamp:  time.Now(),
	}, nil
}

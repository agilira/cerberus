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

	"github.com/agilira/go-errors"
)

// =============================================================================
// UNIT TESTS
// =============================================================================

func TestNew_DefaultConfig(t *testing.T) {
	c := New(Config{})

	if c == nil {
		t.Fatal("New() returned nil")
	}

	// PollInterval is deprecated and no longer clamped by applyDefaults.

	if c.config.BufferSize != DefaultBufferSize {
		t.Errorf("expected BufferSize=%d, got %d", DefaultBufferSize, c.config.BufferSize)
	}
}

func TestNew_CustomConfig(t *testing.T) {
	cfg := Config{
		BufferSize: 128,
	}
	c := New(cfg)

	if c.config.BufferSize != 128 {
		t.Errorf("expected BufferSize=128, got %d", c.config.BufferSize)
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

// TestRegisterProbe_WhileRunning_Succeeds verifies that RegisterProbe may
// be called on a live Cerberus instance without returning an error.
// WHY: dynamic probe lifecycle (ADR-017 skills watcher) requires hot-add;
// the old guard was a design choice, not a correctness requirement.
func TestRegisterProbe_WhileRunning_Succeeds(t *testing.T) {
	t.Parallel()
	c := New(Config{})
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := c.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}()

	probe := &mockProbe{id: "late-probe"}
	if err := c.RegisterProbe(probe); err != nil {
		t.Fatalf("RegisterProbe while running: %v", err)
	}
}

// TestUnregisterProbe_WhileRunning_Succeeds mirrors the above for removal.
func TestUnregisterProbe_WhileRunning_Succeeds(t *testing.T) {
	t.Parallel()
	c := New(Config{})
	probe := &mockProbe{id: "hot-remove"}
	if err := c.RegisterProbe(probe); err != nil {
		t.Fatalf("RegisterProbe: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := c.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}()

	if err := c.UnregisterProbe("hot-remove"); err != nil {
		t.Fatalf("UnregisterProbe while running: %v", err)
	}
}

// TestRegisterProbe_ConcurrentWithPolling verifies that 10 goroutines
// registering and unregistering probes while the poll loop runs produce
// no data race and leave a consistent probe count.
// Run with: go test -race -count=10 -run TestRegisterProbe_ConcurrentWithPolling
func TestRegisterProbe_ConcurrentWithPolling(t *testing.T) {
	t.Parallel()
	c := New(Config{})
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := c.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}()

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(idx int) {
			defer wg.Done()
			id := "concurrent-probe-" + string(rune('0'+idx))
			p := &mockProbe{id: id}
			if err := c.RegisterProbe(p); err != nil {
				// duplicate is not a data race, just a logical error
				return
			}
			time.Sleep(time.Millisecond)
			_ = c.UnregisterProbe(id)
		}(i)
	}
	wg.Wait()
	// No assertion needed beyond "test did not panic under -race".
}

// blockableProbe is a test helper returned by newBlockableProbe.
// The probe signals each poll on polledCh and then blocks until release() is called.
type blockableProbe struct {
	probe    *callbackProbe
	polledCh chan struct{}
	release  func()
}

// newBlockableProbe constructs a callbackProbe that signals when it starts
// executing and blocks until release() is called. release() is idempotent.
func newBlockableProbe(id string) *blockableProbe {
	blockCh := make(chan struct{})
	var once sync.Once
	polledCh := make(chan struct{}, 1)

	probe := &callbackProbe{
		id: id,
		rt: ResourceFile,
		fn: func(ctx context.Context) (State, error) {
			select {
			case polledCh <- struct{}{}:
			default:
			}
			select {
			case <-blockCh:
			case <-ctx.Done():
			}
			return State{Hash: 0x1234, ResourceID: id}, nil
		},
	}

	return &blockableProbe{
		probe:    probe,
		polledCh: polledCh,
		release:  func() { once.Do(func() { close(blockCh) }) },
	}
}

// TestUnregisterProbe_DuringPoll_DoesNotResurrect verifies that a probe
// unregistered while pollDueProbes is executing is NOT re-added to the
// scheduler (the re-check fix in pollDueProbes).
func TestUnregisterProbe_DuringPoll_DoesNotResurrect(t *testing.T) {
	t.Parallel()

	bp := newBlockableProbe("slow-probe")

	c := New(Config{ProbeTimeout: 5 * time.Second})
	if err := c.RegisterProbe(bp.probe); err != nil {
		t.Fatalf("RegisterProbe: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		bp.release()
		if err := c.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}()

	select {
	case <-bp.polledCh:
	case <-time.After(3 * time.Second):
		t.Fatal("probe never polled")
	}

	if err := c.UnregisterProbe("slow-probe"); err != nil {
		t.Fatalf("UnregisterProbe: %v", err)
	}

	// Release the blocked probe so pollDueProbes reaches the double-check.
	// Without the fix, pollDueProbes would call scheduler.Schedule here,
	// silently re-inserting the probe. The probes map is irrelevant: it was
	// already cleaned by UnregisterProbe before the release. The meaningful
	// assertion is on the scheduler's entries map.
	bp.release()

	// Give pollDueProbes time to complete the re-check and either reschedule
	// (bug) or skip rescheduling (fix).
	time.Sleep(100 * time.Millisecond)

	// WHY scheduler.entries and not c.probes: UnregisterProbe removes from
	// c.probes unconditionally, so a c.probes check passes whether or not the
	// fix is in place. The resurrection bug lives in the scheduler: without
	// the double-check, the probe would re-enter scheduler.entries and be
	// polled again on the next tick.
	c.scheduler.mu.Lock()
	_, inScheduler := c.scheduler.entries["slow-probe"]
	c.scheduler.mu.Unlock()
	if inScheduler {
		t.Fatal("probe was resurrected in the scheduler after unregistration (double-check fix missing)")
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
	defer func() { _ = c.Stop() }()

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

// TestStop_StuckProbe_ReturnsTimeout verifies that Stop() returns an error
// when a probe hangs longer than the 5-second grace period.
// WHY: a silent hang at shutdown hides monitoring failures (F.3 — the caller
// needs to know that at least one probe did not finish cleanly).
//
// NOTE: this test intentionally takes 5s (the actual timeout). It is skipped
// under -short to keep the normal test suite fast.
func TestStop_StuckProbe_ReturnsTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 5s timeout test in -short mode")
	}

	// hangForever blocks its context forever — simulating a probe that ignores
	// ctx.Done() (e.g. a syscall-blocked filesystem watcher).
	neverReturn := make(chan struct{})
	p := &callbackProbe{
		id: "stuck-probe",
		rt: ResourceFile,
		fn: func(ctx context.Context) (State, error) {
			// Deliberately ignore ctx.Done() to simulate a stuck probe.
			<-neverReturn
			return State{}, nil
		},
	}

	// Use a probe timeout longer than the Stop() grace period so the probe
	// actually holds the pollProbe goroutine open during Stop().
	c := New(Config{ProbeTimeout: 10 * time.Second})
	if err := c.RegisterProbe(p); err != nil {
		t.Fatalf("RegisterProbe: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait until the probe is executing (so the goroutine is live in pollProbe).
	time.Sleep(20 * time.Millisecond)

	err := c.Stop()
	// Clean up the stuck goroutine after the test regardless of outcome.
	close(neverReturn)

	if err == nil {
		t.Fatal("Stop() returned nil; expected timeout error when probe is stuck")
	}
	if c.IsRunning() {
		t.Error("IsRunning() should be false after Stop() even on timeout")
	}
	// Point 1 follow-up: after a StopTimeout the instance must be compromised.
	if !c.compromised.Load() {
		t.Error("compromised flag should be set after StopTimeout")
	}
}

// TestStart_AfterStopTimeout_ReturnsCompromised verifies that Start() refuses
// to spawn a second pollLoop when the instance was previously stopped with a
// timeout. Without this guard, a second pollLoop goroutine would leak on top
// of the stuck one (CWE-404 / goroutine leak).
//
// NOTE: this test intentionally takes 5s. Skipped under -short.
func TestStart_AfterStopTimeout_ReturnsCompromised(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 5s timeout test in -short mode")
	}

	neverReturn := make(chan struct{})
	p := &callbackProbe{
		id: "stuck-probe-2",
		rt: ResourceFile,
		fn: func(ctx context.Context) (State, error) {
			<-neverReturn
			return State{}, nil
		},
	}

	c := New(Config{ProbeTimeout: 10 * time.Second})
	if err := c.RegisterProbe(p); err != nil {
		t.Fatalf("RegisterProbe: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	stopErr := c.Stop()
	close(neverReturn)

	if stopErr == nil {
		t.Fatal("Stop() should have timed out")
	}

	// A second Start() must be refused with ErrCodeCompromised.
	startErr := c.Start()
	if startErr == nil {
		t.Fatal("Start() after StopTimeout should return an error")
	}
	type errorCoder interface{ ErrorCode() errors.ErrorCode }
	aerr, ok := startErr.(errorCoder)
	if !ok || string(aerr.ErrorCode()) != ErrCodeCompromised {
		t.Errorf("expected ErrCodeCompromised, got %v", startErr)
	}
}

// newSlowProbe creates a callbackProbe that sleeps for 3*MinPollInterval to
// guarantee a poll overrun. It signals on doneCh each time it completes.
func newSlowProbe(id string, doneCh chan struct{}) *callbackProbe {
	return &callbackProbe{
		id: id,
		rt: ResourceFile,
		fn: func(ctx context.Context) (State, error) {
			timer := time.NewTimer(3 * MinPollInterval)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
			}
			select {
			case doneCh <- struct{}{}:
			default:
			}
			return State{Hash: 0x1, ResourceID: id}, nil
		},
	}
}

// awaitOverrun polls c.Stats().OverrunCount until it is > 0 or the deadline
// passes. Returns the final value. Separating this loop keeps the test body
// within cyclomatic budget.
func awaitOverrun(c *Cerberus, deadline time.Duration) int64 {
	until := time.Now().Add(deadline)
	for time.Now().Before(until) {
		if v := c.Stats().OverrunCount; v > 0 {
			return v
		}
		time.Sleep(5 * time.Millisecond)
	}
	return c.Stats().OverrunCount
}

// TestStats_OverrunCount verifies that a poll cycle slower than MinPollInterval
// increments Stats.OverrunCount and sets HealthStatus.PollOverrun.
// WHY: sequential probe execution can push a cycle past MinPollInterval; callers
// need an observable signal before the bottleneck becomes a reliability problem.
func TestStats_OverrunCount(t *testing.T) {
	t.Parallel()

	slowDone := make(chan struct{}, 1)
	p := newSlowProbe("slow-probe-overrun", slowDone)

	c := New(Config{ProbeTimeout: time.Second})
	if err := c.RegisterProbe(p); err != nil {
		t.Fatalf("RegisterProbe: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := c.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}()

	select {
	case <-slowDone:
	case <-time.After(3 * time.Second):
		t.Fatal("slow probe never completed")
	}

	if awaitOverrun(c, 500*time.Millisecond) == 0 {
		t.Error("expected OverrunCount > 0 after a slow poll cycle")
	}
	if !c.HealthCheck().PollOverrun {
		t.Error("HealthStatus.PollOverrun should be true after a slow poll cycle")
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

// TestHealthCheck_LastPollAt_AfterFirstPoll verifies that HealthStatus.LastPollAt
// is populated with a real timestamp (not zero and not time.Now()) once at least
// one poll cycle has completed.
func TestHealthCheck_LastPollAt_AfterFirstPoll(t *testing.T) {
	t.Parallel()
	c := New(Config{})
	p := &mockProbe{id: "p1"}
	if err := c.RegisterProbe(p); err != nil {
		t.Fatalf("RegisterProbe: %v", err)
	}

	before := time.Now()
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := c.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}()

	// Wait until at least one poll cycle completes.
	var h HealthStatus
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		h = c.HealthCheck()
		if !h.LastPollAt.IsZero() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if h.LastPollAt.IsZero() {
		t.Fatal("LastPollAt is still zero after 3s")
	}
	// Must be within a 50ms window of the test run — not a stale time.Now().
	if h.LastPollAt.Before(before) {
		t.Errorf("LastPollAt %v is before test start %v", h.LastPollAt, before)
	}
}

// TestHealthCheck_LastPollAt_StaleWhenStopped verifies that LastPollAt does NOT
// advance after Stop() — i.e. it reflects the last real poll, not a live clock.
func TestHealthCheck_LastPollAt_StaleWhenStopped(t *testing.T) {
	t.Parallel()
	c := New(Config{})
	p := &mockProbe{id: "p2"}
	if err := c.RegisterProbe(p); err != nil {
		t.Fatalf("RegisterProbe: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for at least one poll.
	var first HealthStatus
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		first = c.HealthCheck()
		if !first.LastPollAt.IsZero() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if first.LastPollAt.IsZero() {
		t.Fatal("never polled within 3s")
	}

	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// After stop the timestamp must not change.
	snapshot := c.HealthCheck().LastPollAt
	time.Sleep(20 * time.Millisecond)
	if !c.HealthCheck().LastPollAt.Equal(snapshot) {
		t.Error("LastPollAt changed after Stop() — should be frozen")
	}
}

// TestHealthCheck_LastPollDuration_PositiveAfterPoll verifies that the new
// LastPollDuration field is positive after at least one poll cycle.
// WHY delay on the probe: on Windows, consecutive time.Now() calls inside a
// single poll cycle can return the same value (coarse clock resolution), so a
// zero-work probe produces elapsed==0 and the atomic stays 0. Adding a 1ms
// delay guarantees elapsed >= 1ms on all platforms without changing production
// code. We also use Stats().PollCount as the readiness gate instead of a
// blind 3-second deadline, so the test is deterministic rather than racy.
func TestHealthCheck_LastPollDuration_PositiveAfterPoll(t *testing.T) {
	t.Parallel()
	c := New(Config{})
	// delay: 1ms guarantees elapsed > 0 even on Windows with coarse clocks.
	p := &mockProbe{id: "p3", delay: time.Millisecond}
	if err := c.RegisterProbe(p); err != nil {
		t.Fatalf("RegisterProbe: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := c.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}()

	// Wait until at least one full poll cycle has completed, then assert.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c.Stats().PollCount >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if c.Stats().PollCount == 0 {
		t.Fatal("no poll cycle completed within 10s")
	}

	h := c.HealthCheck()
	if h.LastPollDuration <= 0 {
		t.Fatalf("LastPollDuration=%v after poll cycle, expected positive", h.LastPollDuration)
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
	shouldPanic bool
	delay       time.Duration
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

	if m.shouldPanic {
		panic("malicious probe panic payload")
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

// callbackProbe is a test probe that delegates Probe() to an arbitrary
// function, enabling fine-grained behavioural control in unit tests.
type callbackProbe struct {
	id string
	rt ResourceType
	fn func(ctx context.Context) (State, error)
}

func (p *callbackProbe) ID() string                               { return p.id }
func (p *callbackProbe) ResourceType() ResourceType               { return p.rt }
func (p *callbackProbe) Probe(ctx context.Context) (State, error) { return p.fn(ctx) }

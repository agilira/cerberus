// cerberus.go: Core implementation of Cerberus watchdog
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package cerberus

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agilira/go-errors"
)

// Default configuration values
const (
	DefaultPollInterval        = 500 * time.Millisecond
	DefaultBufferSize          = 64
	DefaultProbeTimeout        = 1 * time.Second
	DefaultCongestionThreshold = 10 // Alert after 10 dropped events
)

// Error codes for Cerberus operations
const (
	ErrCodeStopTimeout    = "CERBERUS_STOP_TIMEOUT"
	ErrCodeCompromised    = "CERBERUS_COMPROMISED"
	ErrCodeNilProbe       = "CERBERUS_NIL_PROBE"
	ErrCodeDuplicateProbe = "CERBERUS_DUPLICATE_PROBE"
	ErrCodeProbeNotFound  = "CERBERUS_PROBE_NOT_FOUND"
	ErrCodeAlreadyRunning = "CERBERUS_ALREADY_RUNNING"
	ErrCodeNotRunning     = "CERBERUS_NOT_RUNNING"
	ErrCodeProbeWhileRun  = "CERBERUS_PROBE_WHILE_RUNNING"
)

// StateChangeHandler is called when probe state changes
// prevState is nil on first poll (no previous state)
// This hook enables external persistence (WorldModel, disk, etc.)
type StateChangeHandler func(probeID string, prevState, newState *State)

// CongestionHandler is called when dropped events exceed threshold
// This is critical for GRC - you must know when monitoring fails
type CongestionHandler func(droppedCount int64)

// Config configures Cerberus behavior
type Config struct {
	// Deprecated: PollInterval is accepted for backward compatibility but has no
	// effect. Use SensitivityProfile to control polling frequency.
	PollInterval time.Duration

	// BufferSize is the drift event channel buffer size
	// Default: 64
	BufferSize int

	// ProbeTimeout is the maximum time a probe can take before being cancelled
	// Default: 1s
	// SAFETY: Prevents slow/hung probes from blocking the poll loop
	ProbeTimeout time.Duration

	// SensitivityProfile configures per-resource polling intervals
	// If nil, uses DefaultSensitivityForResource() for each probe
	// SOVEREIGNTY: Policy controls sensitivity, not code
	SensitivityProfile *SensitivityProfile

	// OnStateChange is called when any probe's state changes
	// Enables external persistence for baseline recovery after restart
	// SOVEREIGNTY: Cerberus is stateless, persistence is external
	OnStateChange StateChangeHandler

	// CongestionThreshold is the number of dropped events before alerting
	// Default: 10
	CongestionThreshold int64

	// OnCongestion is called when dropped events exceed threshold
	// Critical for GRC compliance - monitoring failures must be visible
	OnCongestion CongestionHandler

	// EmitCongestionEvent sends a DriftEvent when congestion occurs
	// Default: false (opt-in to avoid event flood)
	EmitCongestionEvent bool
}

// applyDefaults returns config with defaults applied for invalid values
func (c Config) applyDefaults() Config {
	if c.BufferSize <= 0 {
		c.BufferSize = DefaultBufferSize
	}
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = DefaultProbeTimeout
	}
	if c.SensitivityProfile == nil {
		c.SensitivityProfile = NewSensitivityProfile()
	}
	if c.CongestionThreshold <= 0 {
		c.CongestionThreshold = DefaultCongestionThreshold
	}
	return c
}

// Stats contains runtime statistics
type Stats struct {
	PollCount        int64         // Total polls executed
	DriftCount       int64         // Total drifts detected
	DroppedCount     int64         // Events dropped due to full buffer
	OverrunCount     int64         // Poll cycles that exceeded MinPollInterval (sequential bottleneck signal)
	ProbeCount       int           // Number of registered probes
	LastPollAt       time.Time     // Wall-clock time when the last poll cycle completed
	LastPollDuration time.Duration // Duration of the last poll cycle
	IsRunning        bool          // Whether watchdog is running
	BaselineCount    int           // Number of baseline entries loaded
}

// HealthStatus contains health check information
type HealthStatus struct {
	IsHealthy        bool          // True if watchdog is operating normally
	IsRunning        bool          // Whether watchdog is running
	ProbeCount       int           // Number of registered probes
	DroppedEvents    int64         // Number of dropped events
	BufferCapacity   int           // Size of drift event buffer
	BufferUsed       int           // Current buffer usage (approximate)
	LastPollAt       time.Time     // When last poll cycle completed (zero if never polled)
	LastPollDuration time.Duration // Duration of the last poll cycle
	PollOverrun      bool          // True if the last poll cycle exceeded MinPollInterval (sequential bottleneck)
}

// Cerberus is a lightweight drift detection watchdog
// It detects state changes but does NOT act on them.
// Themis OS handles the actual response via Policy/RBAC/Reflex.
type Cerberus struct {
	config Config

	// Sensitivity profile for per-resource polling intervals
	sensitivityProfile *SensitivityProfile

	// Probes registry
	probes   map[string]Probe
	probesMu sync.RWMutex

	// Priority queue scheduler for O(log n) poll scheduling
	scheduler *ProbeScheduler

	// Last known state per probe for drift detection
	lastState   map[string]State
	lastStateMu sync.RWMutex

	// Drift event channel (Themis OS consumes this)
	drifts chan DriftEvent

	// Control
	running atomic.Bool
	stopCh  chan struct{}
	doneCh  chan struct{}

	// Stats
	pollCount         atomic.Int64
	driftCount        atomic.Int64
	droppedCount      atomic.Int64
	lastPollAt        atomic.Int64 // unix nanoseconds of last poll-cycle completion
	lastPollDuration  atomic.Int64 // nanoseconds spent in last poll cycle
	congestionAlerted atomic.Bool  // Whether congestion alert was fired

	// WHY overrunCount: sequential probe execution means a large due-set can
	// push the poll cycle past MinPollInterval, causing the ticker to fire
	// before the previous cycle finishes. Callers that observe a rising
	// OverrunCount should reduce probe count, increase sensitivity intervals,
	// or plan a future worker-pool upgrade.
	overrunCount atomic.Int64

	// WHY compromised: if Stop() times out, the pollLoop goroutine is still
	// running. Allowing Start() after a timeout would spawn a second pollLoop
	// on the same channels, creating a goroutine leak. The compromised flag
	// prevents restart; the caller must create a new Cerberus instance.
	compromised atomic.Bool
}

// New creates a new Cerberus watchdog
func New(config Config) *Cerberus {
	cfg := config.applyDefaults()

	return &Cerberus{
		config:             cfg,
		sensitivityProfile: cfg.SensitivityProfile,
		probes:             make(map[string]Probe),
		scheduler:          NewProbeScheduler(),
		lastState:          make(map[string]State),
		drifts:             make(chan DriftEvent, cfg.BufferSize),
		stopCh:             make(chan struct{}),
		doneCh:             make(chan struct{}),
	}
}

// RegisterProbe adds a probe to the watchdog.
// Safe to call while running — the internal probesMu write-lock and the
// scheduler's own mutex provide all required concurrency protection.
// WHY no running-guard: the probes map and scheduler are mutex-protected;
// blocking mid-run registration would prevent dynamic lifecycle consumers
// (ADR-017 skills watcher, auto-protect) from working without a
// disruptive Stop→Register→Start cycle that resets all other probes.
func (c *Cerberus) RegisterProbe(probe Probe) error {
	if probe == nil {
		return errors.New(ErrCodeNilProbe, "probe cannot be nil")
	}

	c.probesMu.Lock()
	defer c.probesMu.Unlock()

	id := probe.ID()
	if _, exists := c.probes[id]; exists {
		return errors.New(ErrCodeDuplicateProbe, "probe with ID already exists").
			WithContext("probe_id", id)
	}

	c.probes[id] = probe
	c.scheduler.ScheduleNow(id)
	return nil
}

// UnregisterProbe removes a probe from the watchdog.
// Safe to call while running — same rationale as RegisterProbe.
// The scheduler removal and lastState cleanup are performed inside the
// probesMu write-lock so that pollDueProbes sees a consistent view.
func (c *Cerberus) UnregisterProbe(id string) error {
	c.probesMu.Lock()
	defer c.probesMu.Unlock()

	if _, exists := c.probes[id]; !exists {
		return errors.New(ErrCodeProbeNotFound, "probe not found").
			WithContext("probe_id", id)
	}

	delete(c.probes, id)
	c.scheduler.Remove(id)

	// Clean up baseline state so a future re-registration with the same
	// ID starts with a clean slate rather than a stale hash.
	c.lastStateMu.Lock()
	delete(c.lastState, id)
	c.lastStateMu.Unlock()

	return nil
}

// Start begins the polling loop.
// Returns ErrCodeCompromised if a previous Stop() timed out — in that case
// the pollLoop goroutine may still be running and this instance must not be
// restarted. Create a new Cerberus via New() instead.
func (c *Cerberus) Start() error {
	if c.compromised.Load() {
		return errors.New(ErrCodeCompromised,
			"cerberus instance is compromised: a previous Stop() timed out; "+
				"create a new instance via New() instead of restarting this one")
	}
	if c.running.Swap(true) {
		return errors.New(ErrCodeAlreadyRunning, "cerberus is already running")
	}

	// Reset control channels
	c.stopCh = make(chan struct{})
	c.doneCh = make(chan struct{})

	go c.pollLoop()

	return nil
}

// Stop halts the polling loop gracefully.
// Returns ErrCodeStopTimeout if the poll loop does not exit within 5 seconds.
// WHY: a stuck probe (network hang, broken filesystem) can block pollProbe
// indefinitely even with a timeout context if the probe ignores cancellation.
// Returning an error lets callers log or alert without a silent hang at shutdown.
func (c *Cerberus) Stop() error {
	if !c.running.Load() {
		return errors.New(ErrCodeNotRunning, "cerberus is not running")
	}

	close(c.stopCh)

	// Wait for poll loop to finish with timeout.
	// Mark stopped regardless of outcome so IsRunning() is truthful.
	var stopErr error
	select {
	case <-c.doneCh:
		// Clean shutdown.
	case <-time.After(5 * time.Second):
		// A probe is stuck and ignored context cancellation. Mark the instance
		// compromised so Start() refuses to spawn a second pollLoop goroutine
		// on top of the one that is still running (goroutine leak prevention).
		c.compromised.Store(true)
		stopErr = errors.New(ErrCodeStopTimeout, "poll loop did not stop within 5s; a probe may be stuck")
	}

	c.running.Store(false)
	return stopErr
}

// IsRunning returns whether the watchdog is active
func (c *Cerberus) IsRunning() bool {
	return c.running.Load()
}

// Drifts returns the channel where drift events are emitted
// Themis OS should consume this channel
func (c *Cerberus) Drifts() <-chan DriftEvent {
	return c.drifts
}

// pollAtToTime converts a stored unix-nanosecond value to a time.Time.
// Returns the zero value when val is 0 (i.e. no poll has completed yet),
// which lets callers distinguish "never polled" from the Unix epoch.
func pollAtToTime(val int64) time.Time {
	if val == 0 {
		return time.Time{}
	}
	return time.Unix(0, val)
}

// Stats returns runtime statistics
func (c *Cerberus) Stats() Stats {
	c.probesMu.RLock()
	probeCount := len(c.probes)
	c.probesMu.RUnlock()

	c.lastStateMu.RLock()
	baselineCount := len(c.lastState)
	c.lastStateMu.RUnlock()

	return Stats{
		PollCount:        c.pollCount.Load(),
		DriftCount:       c.driftCount.Load(),
		DroppedCount:     c.droppedCount.Load(),
		OverrunCount:     c.overrunCount.Load(),
		ProbeCount:       probeCount,
		LastPollAt:       pollAtToTime(c.lastPollAt.Load()),
		LastPollDuration: time.Duration(c.lastPollDuration.Load()),
		IsRunning:        c.running.Load(),
		BaselineCount:    baselineCount,
	}
}

// pollLoop is the main polling goroutine
// Uses a fast base tick (MinPollInterval) and checks each probe's interval
// This allows per-resource sensitivity without spinning
func (c *Cerberus) pollLoop() {
	defer close(c.doneCh)

	// Use minimum interval as base tick for responsive scheduling
	baseTick := MinPollInterval
	ticker := time.NewTicker(baseTick)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.pollDueProbes()
		}
	}
}

// pollDueProbes executes probes that are due based on their sensitivity interval
// Uses priority queue for O(k log n) complexity where k = probes actually due
func (c *Cerberus) pollDueProbes() {
	start := time.Now()
	pollCount := 0

	// Pop only probes that are due from the priority queue
	// O(k) where k = probes due, not O(n) where n = all probes
	dueProbeIDs := c.scheduler.PopDue(start)

	for _, probeID := range dueProbeIDs {
		// Get the probe from registry
		c.probesMu.RLock()
		probe, exists := c.probes[probeID]
		c.probesMu.RUnlock()

		if !exists {
			continue // Probe was unregistered
		}

		// Execute the probe
		c.pollProbe(probe)
		pollCount++

		// WHY re-check existence before rescheduling: UnregisterProbe may
		// have been called concurrently between the exists-check above and
		// here. Re-adding a removed probe to the scheduler would resurrect
		// it silently (CWE-362 race window). The extra RLock is cheap
		// compared to the correctness guarantee.
		c.probesMu.RLock()
		_, stillExists := c.probes[probeID]
		c.probesMu.RUnlock()
		if !stillExists {
			continue
		}

		// Reschedule for next poll based on sensitivity interval
		interval := c.sensitivityProfile.GetInterval(probe.ResourceType())
		nextPoll := start.Add(interval)
		c.scheduler.Schedule(probeID, nextPoll)
	}

	if pollCount > 0 {
		c.pollCount.Add(1)
		elapsed := time.Since(start)
		c.lastPollAt.Store(time.Now().UnixNano())
		c.lastPollDuration.Store(int64(elapsed))
		// WHY overrunCount: if a poll cycle takes longer than MinPollInterval the
		// ticker fires while we are still executing, which silently defers the
		// next cycle and skews drift timestamps. Counting overruns gives callers
		// an observable signal before it becomes a reliability problem.
		if elapsed > MinPollInterval {
			c.overrunCount.Add(1)
		}
	}
}

// pollProbe executes a single probe and checks for drift
func (c *Cerberus) pollProbe(probe Probe) {
	probeID := probe.ID()

	// Execute probe with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), c.config.ProbeTimeout)
	defer cancel()

	// Implement CWE-440 mitigation: Global panic isolation
	var state State
	var err error

	func() {
		defer func() {
			if r := recover(); r != nil {
				err = errors.New("CERBERUS_PROBE_PANIC", "probe execution panicked").
					WithContext("panic", r)
			}
		}()
		state, err = probe.Probe(ctx)
	}()

	if err != nil {
		// Probe error - emit error drift
		c.emitDrift(DriftEvent{
			ProbeID:      probeID,
			ResourceID:   probeID,
			ResourceType: probe.ResourceType(),
			ChangeType:   ChangeError,
			Timestamp:    time.Now(),
			Error:        err,
		})
		return
	}

	// Get previous state
	c.lastStateMu.RLock()
	prevState, hasPrev := c.lastState[probeID]
	c.lastStateMu.RUnlock()

	// Detect drift
	if hasPrev && prevState.Hash != state.Hash {
		// Call state change hook with both states
		if c.config.OnStateChange != nil {
			c.config.OnStateChange(probeID, &prevState, &state)
		}

		c.emitDrift(DriftEvent{
			ProbeID:      probeID,
			ResourceID:   state.ResourceID,
			ResourceType: probe.ResourceType(),
			ChangeType:   ChangeDrift,
			PrevHash:     prevState.Hash,
			CurrHash:     state.Hash,
			Timestamp:    time.Now(),
		})
	} else if !hasPrev {
		// First poll - call state change hook (prevState is nil)
		if c.config.OnStateChange != nil {
			c.config.OnStateChange(probeID, nil, &state)
		}

		// First poll - emit create (initial state capture)
		c.emitDrift(DriftEvent{
			ProbeID:      probeID,
			ResourceID:   state.ResourceID,
			ResourceType: probe.ResourceType(),
			ChangeType:   ChangeCreate,
			CurrHash:     state.Hash,
			Timestamp:    time.Now(),
		})
	}

	// Update last state
	c.lastStateMu.Lock()
	c.lastState[probeID] = state
	c.lastStateMu.Unlock()
}

// emitDrift sends a drift event to the channel.
// Non-blocking: drops event if buffer is full.
// WHY drain-reset: congestionAlerted is a one-shot latch that prevents alert
// storms while the buffer is full. We reset it when an event is successfully
// enqueued AND the buffer was empty before the send, meaning the consumer had
// fully caught up. This "full drain" semantic works correctly for any
// BufferSize >= 1, unlike the previous "len < cap" check which failed for
// BufferSize=1 (len always equals cap after any enqueue).
func (c *Cerberus) emitDrift(event DriftEvent) {
	// Capture occupancy before the send. If zero, the consumer has fully
	// drained the backlog; a successful send confirms re-arm is safe.
	preLen := len(c.drifts)
	select {
	case c.drifts <- event:
		c.driftCount.Add(1)
		// Reset the congestion latch only when the buffer was empty at send
		// time, signalling the consumer pareggiato.
		if c.congestionAlerted.Load() && preLen == 0 {
			c.congestionAlerted.Store(false)
		}
	default:
		// Buffer full — drop event and count.
		dropped := c.droppedCount.Add(1)

		// Fire the congestion callback exactly once per congestion episode.
		// The latch is cleared above when the buffer drains, allowing re-fire.
		if dropped >= c.config.CongestionThreshold {
			if c.congestionAlerted.CompareAndSwap(false, true) {
				if c.config.OnCongestion != nil {
					c.config.OnCongestion(dropped)
				}
			}
		}
	}
}

// LoadBaseline loads previously persisted state for restart recovery
// This allows Cerberus to detect drift that occurred while it was stopped
func (c *Cerberus) LoadBaseline(baseline map[string]State) {
	c.lastStateMu.Lock()
	defer c.lastStateMu.Unlock()

	for probeID, state := range baseline {
		c.lastState[probeID] = state
	}
}

// ExportState returns current state for external persistence
// Use this to save state before shutdown for restart recovery
func (c *Cerberus) ExportState() map[string]State {
	c.lastStateMu.RLock()
	defer c.lastStateMu.RUnlock()

	exported := make(map[string]State, len(c.lastState))
	for id, state := range c.lastState {
		exported[id] = state
	}
	return exported
}

// HealthCheck returns current health status
// Use for monitoring dashboards and alerting
func (c *Cerberus) HealthCheck() HealthStatus {
	c.probesMu.RLock()
	probeCount := len(c.probes)
	c.probesMu.RUnlock()

	dropped := c.droppedCount.Load()
	isHealthy := dropped < c.config.CongestionThreshold

	lastDuration := time.Duration(c.lastPollDuration.Load())

	return HealthStatus{
		IsHealthy:        isHealthy,
		IsRunning:        c.running.Load(),
		ProbeCount:       probeCount,
		DroppedEvents:    dropped,
		BufferCapacity:   c.config.BufferSize,
		BufferUsed:       len(c.drifts),
		LastPollAt:       pollAtToTime(c.lastPollAt.Load()),
		LastPollDuration: lastDuration,
		PollOverrun:      lastDuration > MinPollInterval,
	}
}

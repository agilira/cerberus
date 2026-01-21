// state_hooks_test.go: TDD tests for state change hooks (persistence support)
//
// Hooks allow external systems (like WorldModel) to persist Cerberus state
// without coupling Cerberus to specific storage backends.
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
// STATE HOOKS TESTS
// =============================================================================

func TestCerberus_OnStateChange_Called(t *testing.T) {
	var hookCalled atomic.Int32
	var mu sync.Mutex
	var capturedStates []State

	c := New(Config{
		OnStateChange: func(probeID string, prevState, newState *State) {
			hookCalled.Add(1)
			mu.Lock()
			if newState != nil {
				capturedStates = append(capturedStates, *newState)
			}
			mu.Unlock()
		},
	})

	probe := &contextAwareProbe{id: "hook-probe"}
	_ = c.RegisterProbe(probe)
	_ = c.Start()

	time.Sleep(100 * time.Millisecond)
	_ = c.Stop()

	if hookCalled.Load() == 0 {
		t.Error("OnStateChange hook should have been called")
	}

	mu.Lock()
	if len(capturedStates) == 0 {
		t.Error("expected at least one state to be captured")
	}
	mu.Unlock()
}

func TestCerberus_OnStateChange_PrevStateNilOnFirst(t *testing.T) {
	var firstCall atomic.Bool
	var prevWasNil atomic.Bool

	c := New(Config{
		OnStateChange: func(probeID string, prevState, newState *State) {
			if firstCall.CompareAndSwap(false, true) {
				prevWasNil.Store(prevState == nil)
			}
		},
	})

	probe := &contextAwareProbe{id: "first-probe"}
	_ = c.RegisterProbe(probe)
	_ = c.Start()

	time.Sleep(100 * time.Millisecond)
	_ = c.Stop()

	if !prevWasNil.Load() {
		t.Error("prevState should be nil on first poll")
	}
}

func TestCerberus_OnStateChange_PrevStateSetOnSecond(t *testing.T) {
	sp := NewSensitivityProfile()
	sp.SetSensitivity(ResourceFile, SensitivityCritical)

	var callCount atomic.Int32
	var secondPrevNotNil atomic.Bool

	c := New(Config{
		SensitivityProfile: sp,
		OnStateChange: func(probeID string, prevState, newState *State) {
			count := callCount.Add(1)
			if count == 2 && prevState != nil {
				secondPrevNotNil.Store(true)
			}
		},
	})

	// Probe that changes state
	var hash atomic.Uint64
	probe := &contextAwareProbe{
		id: "changing-probe",
		onProbe: func(ctx context.Context) {
			hash.Add(1)
		},
	}

	_ = c.RegisterProbe(probe)
	_ = c.Start()

	time.Sleep(300 * time.Millisecond) // Allow 2+ polls
	_ = c.Stop()

	if callCount.Load() < 2 {
		t.Skip("not enough polls in time")
	}

	if !secondPrevNotNil.Load() {
		t.Error("prevState should not be nil on second poll")
	}
}

func TestCerberus_LoadBaseline(t *testing.T) {
	// Test loading initial baseline state (for restart recovery)
	c := New(Config{})

	baseline := map[string]State{
		"file:/etc/passwd": {
			ResourceID: "/etc/passwd",
			Hash:       12345,
			Timestamp:  time.Now().Add(-1 * time.Hour),
		},
		"port:22": {
			ResourceID: "22",
			Hash:       67890,
			Timestamp:  time.Now().Add(-1 * time.Hour),
		},
	}

	c.LoadBaseline(baseline)

	// Verify baseline was loaded
	stats := c.Stats()
	if stats.BaselineCount != 2 {
		t.Errorf("expected BaselineCount=2, got %d", stats.BaselineCount)
	}
}

func TestCerberus_LoadBaseline_DetectsDriftOnStart(t *testing.T) {
	sp := NewSensitivityProfile()
	sp.SetSensitivity(ResourceFile, SensitivityCritical)

	c := New(Config{
		SensitivityProfile: sp,
		BufferSize:         16,
	})

	// Load baseline with old hash
	baseline := map[string]State{
		"drift-detect-probe": {
			ResourceID: "drift-detect-probe",
			Hash:       11111, // Old hash
			Timestamp:  time.Now().Add(-1 * time.Hour),
		},
	}
	c.LoadBaseline(baseline)

	// Probe returns different hash
	probe := &contextAwareProbe{id: "drift-detect-probe"}
	_ = c.RegisterProbe(probe)
	_ = c.Start()

	// Should detect drift (hash 11111 != 12345)
	var gotDrift bool
	select {
	case event := <-c.Drifts():
		if event.ChangeType == ChangeDrift {
			gotDrift = true
			if event.PrevHash != 11111 {
				t.Errorf("expected PrevHash=11111, got %d", event.PrevHash)
			}
			if event.CurrHash != 12345 {
				t.Errorf("expected CurrHash=12345, got %d", event.CurrHash)
			}
		}
	case <-time.After(300 * time.Millisecond):
		t.Error("timeout waiting for drift event")
	}

	_ = c.Stop()

	if !gotDrift {
		t.Error("should have detected drift from baseline")
	}
}

func TestCerberus_ExportState(t *testing.T) {
	c := New(Config{})

	probe := &contextAwareProbe{id: "export-probe"}
	_ = c.RegisterProbe(probe)
	_ = c.Start()

	time.Sleep(100 * time.Millisecond)
	_ = c.Stop()

	// Export current state for persistence
	state := c.ExportState()

	if len(state) == 0 {
		t.Error("ExportState should return current state")
	}

	if _, ok := state["export-probe"]; !ok {
		t.Error("expected export-probe state to be exported")
	}
}

// =============================================================================
// SIGNED BASELINE TESTS (A. HMAC Protection)
// =============================================================================

func TestSignedBaseline_SignAndVerify(t *testing.T) {
	key := []byte("test-secret-key-32-bytes-long!!")

	baseline := map[string]State{
		"probe-1": {Hash: 12345, Timestamp: time.Now()},
		"probe-2": {Hash: 67890, Timestamp: time.Now()},
	}

	// Sign the baseline
	signed, err := SignBaseline(baseline, key)
	if err != nil {
		t.Fatalf("SignBaseline failed: %v", err)
	}

	if signed.Signature == "" {
		t.Error("Signature should not be empty")
	}

	// Verify should succeed
	valid, err := VerifyBaseline(signed, key)
	if err != nil {
		t.Fatalf("VerifyBaseline failed: %v", err)
	}
	if !valid {
		t.Error("Baseline should be valid")
	}
}

func TestSignedBaseline_TamperedData_Fails(t *testing.T) {
	key := []byte("test-secret-key-32-bytes-long!!")

	baseline := map[string]State{
		"probe-1": {Hash: 12345, Timestamp: time.Now()},
	}

	signed, err := SignBaseline(baseline, key)
	if err != nil {
		t.Fatalf("SignBaseline failed: %v", err)
	}

	// Tamper with the data (attacker modifies baseline to hide traces)
	signed.States["probe-1"] = State{Hash: 99999, Timestamp: time.Now()}

	// Verification should fail
	valid, err := VerifyBaseline(signed, key)
	if err != nil {
		t.Fatalf("VerifyBaseline should not error, got: %v", err)
	}
	if valid {
		t.Error("Tampered baseline should NOT be valid")
	}
}

func TestSignedBaseline_WrongKey_Fails(t *testing.T) {
	signKey := []byte("original-key-32-bytes-long!!!!!!")
	wrongKey := []byte("attacker-key-32-bytes-long!!!!!!")

	baseline := map[string]State{
		"probe-1": {Hash: 12345, Timestamp: time.Now()},
	}

	signed, err := SignBaseline(baseline, signKey)
	if err != nil {
		t.Fatalf("SignBaseline failed: %v", err)
	}

	// Verification with wrong key should fail
	valid, err := VerifyBaseline(signed, wrongKey)
	if err != nil {
		t.Fatalf("VerifyBaseline should not error, got: %v", err)
	}
	if valid {
		t.Error("Baseline verified with wrong key should NOT be valid")
	}
}

func TestCerberus_LoadSignedBaseline_ValidSignature(t *testing.T) {
	key := []byte("test-secret-key-32-bytes-long!!")

	baseline := map[string]State{
		"probe-1": {Hash: 12345, Timestamp: time.Now()},
	}

	signed, _ := SignBaseline(baseline, key)

	c := New(Config{})

	// LoadSignedBaseline should succeed with valid signature
	err := c.LoadSignedBaseline(signed, key)
	if err != nil {
		t.Errorf("LoadSignedBaseline failed: %v", err)
	}

	// Verify state was loaded
	exported := c.ExportState()
	if len(exported) != 1 {
		t.Errorf("Expected 1 state, got %d", len(exported))
	}
}

func TestCerberus_LoadSignedBaseline_InvalidSignature_Rejected(t *testing.T) {
	key := []byte("test-secret-key-32-bytes-long!!")

	baseline := map[string]State{
		"probe-1": {Hash: 12345, Timestamp: time.Now()},
	}

	signed, _ := SignBaseline(baseline, key)

	// Tamper with signature
	signed.Signature = "tampered-signature"

	c := New(Config{})

	// LoadSignedBaseline should REJECT tampered baseline
	err := c.LoadSignedBaseline(signed, key)
	if err == nil {
		t.Error("LoadSignedBaseline should reject tampered baseline")
	}

	// State should NOT be loaded
	exported := c.ExportState()
	if len(exported) != 0 {
		t.Error("Tampered baseline should not be loaded")
	}
}

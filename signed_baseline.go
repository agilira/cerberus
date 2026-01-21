// signed_baseline.go: HMAC-signed baseline for tamper protection
//
// Protects against attackers modifying baseline files to hide their traces.
// Uses HMAC-SHA256 to ensure integrity of persisted state.
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0

package cerberus

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// SignedBaseline holds probe states with cryptographic signature.
// This protects against attackers modifying persisted baselines
// to hide unauthorized changes made while Cerberus was stopped.
type SignedBaseline struct {
	// States is the probe state map being protected
	States map[string]State `json:"states"`

	// Signature is the HMAC-SHA256 signature of canonical state JSON
	Signature string `json:"signature"`

	// Version allows future format changes
	Version int `json:"version"`
}

// SignBaseline creates a signed baseline from probe states.
// The key should be the same HMAC key used by the audit system
// (typically from config.SigningKey) for consistent security.
func SignBaseline(states map[string]State, key []byte) (*SignedBaseline, error) {
	if len(key) < 16 {
		return nil, fmt.Errorf("cerberus: signing key must be at least 16 bytes")
	}

	signed := &SignedBaseline{
		States:  states,
		Version: 1,
	}

	// Compute signature over canonical JSON
	canonical, err := canonicalStateJSON(states)
	if err != nil {
		return nil, fmt.Errorf("cerberus: canonicalize states: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	signed.Signature = hex.EncodeToString(mac.Sum(nil))

	return signed, nil
}

// VerifyBaseline verifies the HMAC signature of a signed baseline.
// Returns true if the signature is valid, false if tampered.
func VerifyBaseline(signed *SignedBaseline, key []byte) (bool, error) {
	if signed == nil {
		return false, fmt.Errorf("cerberus: signed baseline is nil")
	}
	if signed.Signature == "" {
		return false, fmt.Errorf("cerberus: baseline has no signature")
	}

	// Decode existing signature
	existingSig, err := hex.DecodeString(signed.Signature)
	if err != nil {
		return false, nil // Invalid hex = tampered
	}

	// Recompute signature
	canonical, err := canonicalStateJSON(signed.States)
	if err != nil {
		return false, fmt.Errorf("cerberus: canonicalize states: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	expected := mac.Sum(nil)

	// Constant-time comparison to prevent timing attacks
	return hmac.Equal(existingSig, expected), nil
}

// canonicalStateJSON produces deterministic JSON for signing.
// Keys are sorted to ensure consistent ordering.
func canonicalStateJSON(states map[string]State) ([]byte, error) {
	// Sort probe IDs for deterministic ordering
	probeIDs := make([]string, 0, len(states))
	for id := range states {
		probeIDs = append(probeIDs, id)
	}
	sort.Strings(probeIDs)

	// Build ordered structure
	type stateEntry struct {
		ProbeID string `json:"probe_id"`
		Hash    uint64 `json:"hash"`
		// Note: Timestamp intentionally excluded - only hash matters for integrity
	}

	entries := make([]stateEntry, len(probeIDs))
	for i, id := range probeIDs {
		entries[i] = stateEntry{
			ProbeID: id,
			Hash:    states[id].Hash,
		}
	}

	return json.Marshal(entries)
}

// LoadSignedBaseline loads a verified baseline.
// Returns error if signature verification fails (possible tampering).
// This is the SECURE alternative to LoadBaseline for production use.
func (c *Cerberus) LoadSignedBaseline(signed *SignedBaseline, key []byte) error {
	valid, err := VerifyBaseline(signed, key)
	if err != nil {
		return fmt.Errorf("cerberus: verify baseline: %w", err)
	}
	if !valid {
		return fmt.Errorf("cerberus: baseline signature invalid (possible tampering)")
	}

	// Signature valid - load the states
	c.LoadBaseline(signed.States)
	return nil
}

// ExportSignedState exports current state with HMAC signature.
// Use this instead of ExportState for secure persistence.
func (c *Cerberus) ExportSignedState(key []byte) (*SignedBaseline, error) {
	states := c.ExportState()
	return SignBaseline(states, key)
}

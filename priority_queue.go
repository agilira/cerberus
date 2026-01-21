// priority_queue.go: Min-heap priority queue for efficient probe scheduling
//
// Copyright (c) 2025 AGILira - A. Giordano
// SPDX-License-Identifier: MPL-2.0
//
// SOLUTION for O(n) poll loop issue:
// Instead of iterating ALL probes every tick, we use a min-heap sorted by
// next poll time. Only pop probes where nextPoll <= now.
// Complexity: O(k log n) where k = probes actually due

package cerberus

import (
	"container/heap"
	"sync"
	"time"
)

// probeEntry represents a probe in the priority queue
type probeEntry struct {
	probeID  string    // Probe identifier
	nextPoll time.Time // When this probe should next be polled
	index    int       // Index in heap (managed by heap.Interface)
}

// probeHeap implements heap.Interface for probeEntry
// Min-heap: earliest nextPoll at root
type probeHeap []*probeEntry

func (h probeHeap) Len() int           { return len(h) }
func (h probeHeap) Less(i, j int) bool { return h[i].nextPoll.Before(h[j].nextPoll) }
func (h probeHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *probeHeap) Push(x any) {
	entry := x.(*probeEntry)
	entry.index = len(*h)
	*h = append(*h, entry)
}

func (h *probeHeap) Pop() any {
	old := *h
	n := len(old)
	entry := old[n-1]
	old[n-1] = nil // GC
	entry.index = -1
	*h = old[0 : n-1]
	return entry
}

// ProbeScheduler manages probe scheduling with a priority queue
// Thread-safe: uses mutex for all operations
type ProbeScheduler struct {
	mu      sync.Mutex
	heap    probeHeap
	entries map[string]*probeEntry // probeID -> entry for O(1) lookup
}

// NewProbeScheduler creates a new scheduler
func NewProbeScheduler() *ProbeScheduler {
	ps := &ProbeScheduler{
		heap:    make(probeHeap, 0),
		entries: make(map[string]*probeEntry),
	}
	heap.Init(&ps.heap)
	return ps
}

// Schedule adds or updates a probe's next poll time
// If probe already scheduled, updates its position in the queue
func (ps *ProbeScheduler) Schedule(probeID string, nextPoll time.Time) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if entry, exists := ps.entries[probeID]; exists {
		// Update existing entry
		entry.nextPoll = nextPoll
		heap.Fix(&ps.heap, entry.index)
	} else {
		// Add new entry
		entry := &probeEntry{
			probeID:  probeID,
			nextPoll: nextPoll,
		}
		heap.Push(&ps.heap, entry)
		ps.entries[probeID] = entry
	}
}

// ScheduleNow schedules a probe to be polled immediately
func (ps *ProbeScheduler) ScheduleNow(probeID string) {
	ps.Schedule(probeID, time.Now())
}

// Remove removes a probe from the scheduler
func (ps *ProbeScheduler) Remove(probeID string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if entry, exists := ps.entries[probeID]; exists {
		heap.Remove(&ps.heap, entry.index)
		delete(ps.entries, probeID)
	}
}

// PopDue returns all probes that are due (nextPoll <= now)
// Returns probe IDs in order of their scheduled time
// Caller is responsible for rescheduling them after polling
func (ps *ProbeScheduler) PopDue(now time.Time) []string {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	var due []string
	for ps.heap.Len() > 0 {
		// Peek at the earliest entry
		entry := ps.heap[0]
		if entry.nextPoll.After(now) {
			break // No more due probes
		}

		// Pop and collect
		heap.Pop(&ps.heap)
		delete(ps.entries, entry.probeID)
		due = append(due, entry.probeID)
	}
	return due
}

// NextPollTime returns when the next probe is due
// Returns zero time if no probes scheduled
func (ps *ProbeScheduler) NextPollTime() time.Time {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if ps.heap.Len() == 0 {
		return time.Time{}
	}
	return ps.heap[0].nextPoll
}

// Len returns the number of scheduled probes
func (ps *ProbeScheduler) Len() int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.heap.Len()
}

// Clear removes all entries from the scheduler
func (ps *ProbeScheduler) Clear() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.heap = make(probeHeap, 0)
	ps.entries = make(map[string]*probeEntry)
	heap.Init(&ps.heap)
}

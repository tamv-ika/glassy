// THROWAWAY: SP0 spike code. The real broker (SP2) is a gRPC service in front of Agones.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"
)

// ConnectInfo is what one player needs to reach its game server through the gateways
// (spec §5.3). The broker mints the transport sections; they stay opaque here.
type ConnectInfo struct {
	SessionID    string          `json:"session_id"`
	Native       json.RawMessage `json:"native,omitempty"`
	WebRTC       json.RawMessage `json:"webrtc,omitempty"`
	WebTransport json.RawMessage `json:"webtransport,omitempty"`
}

// Instance is an allocated game server as the broker reports it.
type Instance struct {
	ID          string
	Address     string
	Port        int
	PlayerCount int
	Status      string
	CreatedAt   time.Time
	Metadata    map[string]any
}

// Broker is the part of the glassy broker API that the fleet manager calls (spec §5.4).
type Broker interface {
	Allocate(ctx context.Context, fleet string, userIDs []string, metadata map[string]any) (Instance, map[string]ConnectInfo, error)
	Join(ctx context.Context, instanceID string, userIDs []string) (map[string]ConnectInfo, error)
	Get(ctx context.Context, id string) (Instance, error)
	List(ctx context.Context, query string, limit int, cursor string) ([]Instance, string, error)
	Delete(ctx context.Context, id string) error
}

var ErrNotFound = errors.New("instance not found")

// FakeBroker allocates instances in memory. It stands in for the broker until SP2.
type FakeBroker struct {
	// AllocateErr, when set, makes every Allocate fail with it.
	AllocateErr error
	// AllocateDelay simulates the time Agones takes to allocate.
	AllocateDelay time.Duration

	mu        sync.Mutex
	next      int
	instances map[string]*Instance
}

func NewFakeBroker() *FakeBroker {
	return &FakeBroker{instances: map[string]*Instance{}}
}

// SessionIDFor is the session ID the fake mints for a user, so tests can check the round trip.
func (f *FakeBroker) SessionIDFor(userID string) string {
	return "sess-" + userID
}

func (f *FakeBroker) Allocate(ctx context.Context, fleet string, userIDs []string, metadata map[string]any) (Instance, map[string]ConnectInfo, error) {
	if f.AllocateDelay > 0 {
		select {
		case <-time.After(f.AllocateDelay):
		case <-ctx.Done():
			return Instance{}, nil, ctx.Err()
		}
	}
	if f.AllocateErr != nil {
		return Instance{}, nil, f.AllocateErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	inst := &Instance{
		ID:          fmt.Sprintf("gs-%d", f.next),
		Address:     "203.0.113.10",
		Port:        443,
		PlayerCount: len(userIDs),
		Status:      "Allocated",
		CreatedAt:   time.Now().UTC(),
		Metadata:    maps.Clone(metadata),
	}
	f.instances[inst.ID] = inst
	return *inst, f.connectInfos(inst.ID, userIDs), nil
}

func (f *FakeBroker) Join(_ context.Context, instanceID string, userIDs []string) (map[string]ConnectInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inst, ok := f.instances[instanceID]
	if !ok {
		return nil, fmt.Errorf("join %s: %w", instanceID, ErrNotFound)
	}
	inst.PlayerCount += len(userIDs)
	return f.connectInfos(instanceID, userIDs), nil
}

func (f *FakeBroker) Get(_ context.Context, id string) (Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inst, ok := f.instances[id]
	if !ok {
		return Instance{}, fmt.Errorf("get %s: %w", id, ErrNotFound)
	}
	return *inst, nil
}

// List ignores the query and pagination: the fake never holds more than a handful.
func (f *FakeBroker) List(_ context.Context, _ string, limit int, _ string) ([]Instance, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := slices.Sorted(maps.Keys(f.instances))
	if limit > 0 && len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]Instance, 0, len(ids))
	for _, id := range ids {
		out = append(out, *f.instances[id])
	}
	return out, "", nil
}

func (f *FakeBroker) Delete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.instances[id]; !ok {
		return fmt.Errorf("delete %s: %w", id, ErrNotFound)
	}
	delete(f.instances, id)
	return nil
}

func (f *FakeBroker) connectInfos(instanceID string, userIDs []string) map[string]ConnectInfo {
	out := make(map[string]ConnectInfo, len(userIDs))
	for _, u := range userIDs {
		out[u] = ConnectInfo{
			SessionID:    f.SessionIDFor(u),
			Native:       json.RawMessage(`{"gateways":["203.0.113.10:7000"]}`),
			WebTransport: json.RawMessage(fmt.Sprintf(`{"url":"https://%s.wt.example/glassy"}`, instanceID)),
		}
	}
	return out
}

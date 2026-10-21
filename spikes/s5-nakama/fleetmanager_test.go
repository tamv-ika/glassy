package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heroiclabs/nakama-common/runtime"
)

var _ runtime.FleetManagerInitializer = (*GlassyFleetManager)(nil)

// testCallbacks mirrors Nakama's LocalFmCallbackHandler: an ID-keyed registry, invoked once.
type testCallbacks struct {
	mu   sync.Mutex
	next int
	fns  map[string]runtime.FmCreateCallbackFn
}

func newTestCallbacks() *testCallbacks {
	return &testCallbacks{fns: map[string]runtime.FmCreateCallbackFn{}}
}

func (h *testCallbacks) GenerateCallbackId() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	return fmt.Sprintf("cb-%d", h.next)
}

func (h *testCallbacks) SetCallback(id string, fn runtime.FmCreateCallbackFn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fns[id] = fn
}

func (h *testCallbacks) InvokeCallback(id string, status runtime.FmCreateStatus, info *runtime.InstanceInfo, sessions []*runtime.SessionInfo, metadata map[string]any, err error) {
	h.mu.Lock()
	fn := h.fns[id]
	delete(h.fns, id)
	h.mu.Unlock()
	if fn != nil {
		fn(status, info, sessions, metadata, err)
	}
}

type createResult struct {
	status   runtime.FmCreateStatus
	info     *runtime.InstanceInfo
	sessions []*runtime.SessionInfo
	metadata map[string]any
	err      error
}

func newManager(t *testing.T, fake *FakeBroker) *GlassyFleetManager {
	t.Helper()
	fm := New(fake, "default")
	if err := fm.Init(nil, newTestCallbacks()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return fm
}

// create calls Create and waits up to 1s for its callback.
func create(t *testing.T, ctx context.Context, fm *GlassyFleetManager, userIDs []string) createResult {
	t.Helper()
	done := make(chan createResult, 1)
	ret, err := fm.Create(ctx, len(userIDs), userIDs, nil, map[string]any{"mode": "duel"},
		func(status runtime.FmCreateStatus, info *runtime.InstanceInfo, sessions []*runtime.SessionInfo, metadata map[string]any, err error) {
			done <- createResult{status, info, sessions, metadata, err}
		})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if ret != nil {
		t.Fatalf("Create returned %v, want nil (Nakama never reads it)", ret)
	}
	select {
	case r := <-done:
		return r
	case <-time.After(time.Second):
		t.Fatal("callback not invoked within 1s")
		return createResult{}
	}
}

func TestCreateInvokesCallbackWithConnectInfoPerUser(t *testing.T) {
	fake := NewFakeBroker()
	fm := newManager(t, fake)

	r := create(t, context.Background(), fm, []string{"u1", "u2"})

	if r.status != runtime.CreateSuccess || r.err != nil {
		t.Fatalf("status %v err %v, want CreateSuccess", r.status, r.err)
	}
	if r.info.Id != "gs-1" || r.info.ConnectionInfo.IpAddress != "203.0.113.10" || r.info.ConnectionInfo.Port != 443 {
		t.Fatalf("instance info %+v / %+v", r.info, r.info.ConnectionInfo)
	}
	if r.metadata["mode"] != "duel" {
		t.Fatalf("metadata %v, want the Create metadata back", r.metadata)
	}
	if len(r.sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(r.sessions))
	}
	for i, want := range []string{"u1", "u2"} {
		s := r.sessions[i]
		if s.UserId != want {
			t.Fatalf("session %d user %q, want %q", i, s.UserId, want)
		}
		ci, err := DecodeConnectInfo(s.SessionId)
		if err != nil {
			t.Fatalf("decode session %d: %v", i, err)
		}
		if ci.SessionID != fake.SessionIDFor(s.UserId) {
			t.Fatalf("session %d ConnectInfo.SessionID %q, want %q", i, ci.SessionID, fake.SessionIDFor(s.UserId))
		}
	}
}

func TestCreateBrokerErrorReportsCreateError(t *testing.T) {
	fake := NewFakeBroker()
	fake.AllocateErr = errors.New("no ready game servers")
	fm := newManager(t, fake)

	r := create(t, context.Background(), fm, []string{"u1"})

	if r.status != runtime.CreateError || r.err == nil {
		t.Fatalf("status %v err %v, want CreateError with an error", r.status, r.err)
	}
	if r.info != nil || r.sessions != nil || r.metadata != nil {
		t.Fatalf("got info %v sessions %v metadata %v, want all nil", r.info, r.sessions, r.metadata)
	}
}

func TestCreateSurvivesCallerContextCancel(t *testing.T) {
	fake := NewFakeBroker()
	fake.AllocateDelay = 50 * time.Millisecond
	fm := newManager(t, fake)
	// Nakama cancels an RPC's context when the RPC returns, long before allocation finishes.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan runtime.FmCreateStatus, 1)
	_, err := fm.Create(ctx, 1, []string{"u1"}, nil, nil,
		func(status runtime.FmCreateStatus, _ *runtime.InstanceInfo, _ []*runtime.SessionInfo, _ map[string]any, _ error) {
			done <- status
		})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cancel()

	select {
	case status := <-done:
		if status != runtime.CreateSuccess {
			t.Fatalf("status %v after caller cancel, want CreateSuccess", status)
		}
	case <-time.After(time.Second):
		t.Fatal("callback not invoked within 1s")
	}
}

func TestCreateWithoutInitFails(t *testing.T) {
	fm := New(NewFakeBroker(), "default")
	_, err := fm.Create(context.Background(), 1, []string{"u1"}, nil, nil,
		func(runtime.FmCreateStatus, *runtime.InstanceInfo, []*runtime.SessionInfo, map[string]any, error) {})
	if err == nil {
		t.Fatal("Create before Init succeeded, want an error")
	}
}

func TestJoinReturnsSessionInfo(t *testing.T) {
	fake := NewFakeBroker()
	fm := newManager(t, fake)
	inst, _, err := fake.Allocate(context.Background(), "default", []string{"u1"}, nil)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	join, err := fm.Join(context.Background(), inst.ID, []string{"u3"}, nil)

	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if join.InstanceInfo.Id != inst.ID {
		t.Fatalf("join instance %q, want %q", join.InstanceInfo.Id, inst.ID)
	}
	if len(join.SessionInfo) != 1 || join.SessionInfo[0].UserId != "u3" {
		t.Fatalf("join sessions %+v, want one for u3", join.SessionInfo)
	}
	ci, err := DecodeConnectInfo(join.SessionInfo[0].SessionId)
	if err != nil || ci.SessionID != fake.SessionIDFor("u3") {
		t.Fatalf("ConnectInfo %+v err %v", ci, err)
	}
}

func TestJoinUnknownInstanceFails(t *testing.T) {
	fm := newManager(t, NewFakeBroker())
	if _, err := fm.Join(context.Background(), "gs-404", []string{"u1"}, nil); err == nil {
		t.Fatal("Join on an unknown instance succeeded")
	}
}

func TestGetMapsInstanceFields(t *testing.T) {
	fake := NewFakeBroker()
	fm := newManager(t, fake)
	inst, _, err := fake.Allocate(context.Background(), "default", []string{"u1", "u2"}, map[string]any{"mode": "duel"})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	info, err := fm.Get(context.Background(), inst.ID)

	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if info.Id != inst.ID || info.PlayerCount != 2 || info.Status != inst.Status ||
		!info.CreateTime.Equal(inst.CreatedAt) || info.Metadata["mode"] != "duel" ||
		info.ConnectionInfo.IpAddress != inst.Address || info.ConnectionInfo.Port != inst.Port {
		t.Fatalf("Get mapped %+v from %+v", info, inst)
	}
}

func TestConnectInfoEncodingIsURLSafe(t *testing.T) {
	// Runs of '?' and '>' make standard base64 emit '/' and '+' at any alignment.
	ci := ConnectInfo{
		SessionID:    "s-?????>>>>>",
		Native:       json.RawMessage(`{"routing_ticket":"?????>>>>>"}`),
		WebTransport: json.RawMessage(`{"url":"https://x.wt.test/?q=>>>>>"}`),
	}
	raw, err := json.Marshal(ci)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.ContainsAny(base64.StdEncoding.EncodeToString(raw), "+/") {
		t.Fatal("fixture does not exercise '+' or '/'")
	}

	enc, err := EncodeConnectInfo(ci)

	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if strings.ContainsAny(enc, "+/=") {
		t.Fatalf("encoded %q contains '+', '/' or '='", enc)
	}
	back, err := DecodeConnectInfo(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(back, ci) {
		t.Fatalf("round trip %+v, want %+v", back, ci)
	}
}

func TestDecodeConnectInfoRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "not base64!", base64.RawURLEncoding.EncodeToString([]byte("[1,2]"))} {
		if _, err := DecodeConnectInfo(s); err == nil {
			t.Errorf("DecodeConnectInfo(%q) succeeded, want an error", s)
		}
	}
}

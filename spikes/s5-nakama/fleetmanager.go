// THROWAWAY: SP0 spike code; the production plugin is glassy-nakama (SP2, spec §5.4).

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/heroiclabs/nakama-common/runtime"
)

// allocateTimeout bounds one allocation; past it the callback reports CreateTimeout.
const allocateTimeout = 30 * time.Second

// GlassyFleetManager adapts the glassy broker to Nakama's FleetManager. Each player's
// ConnectInfo travels in SessionInfo.SessionId, encoded with EncodeConnectInfo.
type GlassyFleetManager struct {
	broker Broker
	fleet  string

	nk        runtime.NakamaModule
	callbacks runtime.FmCallbackHandler
}

func New(b Broker, fleet string) *GlassyFleetManager {
	return &GlassyFleetManager{broker: b, fleet: fleet}
}

// Init is called by initializer.RegisterFleetManager.
func (m *GlassyFleetManager) Init(nk runtime.NakamaModule, callbacks runtime.FmCallbackHandler) error {
	m.nk = nk
	m.callbacks = callbacks
	return nil
}

func (m *GlassyFleetManager) Get(ctx context.Context, id string) (*runtime.InstanceInfo, error) {
	inst, err := m.broker.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return instanceInfo(inst), nil
}

func (m *GlassyFleetManager) List(ctx context.Context, query string, limit int, previousCursor string) ([]*runtime.InstanceInfo, string, error) {
	insts, next, err := m.broker.List(ctx, query, limit, previousCursor)
	if err != nil {
		return nil, "", err
	}
	out := make([]*runtime.InstanceInfo, 0, len(insts))
	for _, inst := range insts {
		out = append(out, instanceInfo(inst))
	}
	return out, next, nil
}

// Create allocates asynchronously and reports through Nakama's callback registry. It returns
// a nil map: Nakama itself never calls Create (game code does) and never reads the map.
// Latencies are ignored because SP0 allocates in a single region.
func (m *GlassyFleetManager) Create(ctx context.Context, maxPlayers int, userIds []string, latencies []runtime.FleetUserLatencies, metadata map[string]any, callback runtime.FmCreateCallbackFn) (map[string]string, error) {
	if m.callbacks == nil {
		return nil, errors.New("glassy fleet manager: Init was not called")
	}
	if callback == nil {
		return nil, errors.New("glassy fleet manager: Create needs a callback")
	}
	id := m.callbacks.GenerateCallbackId()
	m.callbacks.SetCallback(id, callback)
	request := maps.Clone(metadata)
	if request == nil {
		request = map[string]any{}
	}
	request["max_players"] = maxPlayers
	// The allocation outlives the RPC or hook that asked for it, whose context Nakama cancels.
	go m.allocate(context.WithoutCancel(ctx), id, userIds, request, metadata)
	return nil, nil
}

func (m *GlassyFleetManager) allocate(ctx context.Context, callbackID string, userIDs []string, request, metadata map[string]any) {
	ctx, cancel := context.WithTimeout(ctx, allocateTimeout)
	defer cancel()
	inst, infos, err := m.broker.Allocate(ctx, m.fleet, userIDs, request)
	var sessions []*runtime.SessionInfo
	if err == nil {
		sessions, err = sessionInfos(userIDs, infos)
	}
	if err != nil {
		status := runtime.CreateError
		if errors.Is(err, context.DeadlineExceeded) {
			status = runtime.CreateTimeout
		}
		m.callbacks.InvokeCallback(callbackID, status, nil, nil, nil, err)
		return
	}
	m.callbacks.InvokeCallback(callbackID, runtime.CreateSuccess, instanceInfo(inst), sessions, metadata, nil)
}

func (m *GlassyFleetManager) Join(ctx context.Context, id string, userIds []string, metadata map[string]string) (*runtime.JoinInfo, error) {
	infos, err := m.broker.Join(ctx, id, userIds)
	if err != nil {
		return nil, err
	}
	sessions, err := sessionInfos(userIds, infos)
	if err != nil {
		return nil, err
	}
	// Read after joining so the player count includes the new players.
	inst, err := m.broker.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &runtime.JoinInfo{InstanceInfo: instanceInfo(inst), SessionInfo: sessions}, nil
}

// Update is a no-op: player counts live in Agones and the broker reads them from there, so
// there is nothing for Nakama to push.
func (m *GlassyFleetManager) Update(ctx context.Context, id string, playerCount int, metadata map[string]any) error {
	return nil
}

func (m *GlassyFleetManager) Delete(ctx context.Context, id string) error {
	return m.broker.Delete(ctx, id)
}

// EncodeConnectInfo packs a ConnectInfo into SessionInfo.SessionId: unpadded base64url of its
// JSON, so it survives URLs, headers and notification payloads unescaped.
func EncodeConnectInfo(ci ConnectInfo) (string, error) {
	// json.Marshal would HTML-escape '<', '>' and '&' even inside the broker's opaque sections,
	// changing their bytes and growing each such character to six.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ci); err != nil {
		return "", fmt.Errorf("encode ConnectInfo: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes.TrimSuffix(buf.Bytes(), []byte("\n"))), nil
}

func DecodeConnectInfo(s string) (ConnectInfo, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return ConnectInfo{}, fmt.Errorf("decode ConnectInfo: %w", err)
	}
	var ci ConnectInfo
	if err := json.Unmarshal(raw, &ci); err != nil {
		return ConnectInfo{}, fmt.Errorf("decode ConnectInfo: %w", err)
	}
	return ci, nil
}

// sessionInfos returns one SessionInfo per user, in userIDs order; nil when there are no users,
// as the FmCreateCallbackFn contract asks.
func sessionInfos(userIDs []string, infos map[string]ConnectInfo) ([]*runtime.SessionInfo, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	out := make([]*runtime.SessionInfo, 0, len(userIDs))
	for _, u := range userIDs {
		ci, ok := infos[u]
		if !ok {
			return nil, fmt.Errorf("broker returned no ConnectInfo for user %q", u)
		}
		enc, err := EncodeConnectInfo(ci)
		if err != nil {
			return nil, err
		}
		out = append(out, &runtime.SessionInfo{UserId: u, SessionId: enc})
	}
	return out, nil
}

// instanceInfo maps a broker instance. ConnectionInfo is the game server's own address and is
// informational only: clients connect through the gateways named in their ConnectInfo.
func instanceInfo(inst Instance) *runtime.InstanceInfo {
	return &runtime.InstanceInfo{
		Id:             inst.ID,
		ConnectionInfo: &runtime.ConnectionInfo{IpAddress: inst.Address, Port: inst.Port},
		CreateTime:     inst.CreatedAt,
		PlayerCount:    inst.PlayerCount,
		Status:         inst.Status,
		Metadata:       inst.Metadata,
	}
}

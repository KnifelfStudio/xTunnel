package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

type controlMessage struct {
	Type           string      `json:"type"`
	TrackID        string      `json:"track_id,omitempty"`
	ServiceSession string      `json:"service_session,omitempty"`
	ConfigVersion  uint64      `json:"config_version,omitempty"`
	AgentID        string      `json:"agent_id,omitempty"`
	RequestID      string      `json:"request_id,omitempty"`
	ForwardID      string      `json:"forward_id,omitempty"`
	Transport      string      `json:"transport,omitempty"`
	Target         *Target     `json:"target,omitempty"`
	Candidates     []string    `json:"candidates,omitempty"`
	ActualIP       string      `json:"actual_ip,omitempty"`
	Ticket         string      `json:"ticket,omitempty"`
	ErrorCode      string      `json:"error_code,omitempty"`
	Rules          *RuleConfig `json:"rules,omitempty"`
	PairingCode    string      `json:"pairing_code,omitempty"`
	SourceEndpoint string      `json:"source_endpoint,omitempty"`
}

type controlPeer struct {
	conn    *websocket.Conn
	track   *track
	agent   *agent
	session string
	sendq   chan controlMessage
	done    chan struct{}
	once    sync.Once
}

func (p *controlPeer) close() { p.once.Do(func() { close(p.done); _ = p.conn.Close() }) }
func (p *controlPeer) send(m controlMessage) error {
	select {
	case <-p.done:
		return errors.New("control closed")
	default:
	}
	select {
	case p.sendq <- m:
		return nil
	default:
		p.close()
		return errors.New("control queue full")
	}
}
func (p *controlPeer) terminate(reason string) {
	if p.send(controlMessage{Type: "STOP", ErrorCode: reason}) != nil {
		p.close()
	}
}
func (p *controlPeer) writeLoop() {
	defer p.close()
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		var m controlMessage
		select {
		case <-p.done:
			return
		case m = <-p.sendq:
		case <-tick.C:
			m = controlMessage{Type: "PING"}
		}
		_ = p.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if p.conn.WriteJSON(m) != nil {
			return
		}
		if m.Type == "STOP" {
			return
		}
	}
}

var upgrader = websocket.Upgrader{ReadBufferSize: 4096, WriteBufferSize: 4096, HandshakeTimeout: 10 * time.Second, Subprotocols: []string{"xtunnel.v1"}}

func protocolRequested(r *http.Request) bool {
	for _, v := range websocket.Subprotocols(r) {
		if v == "xtunnel.v1" {
			return true
		}
	}
	return false
}
func (s *Server) control(w http.ResponseWriter, r *http.Request) {
	if !protocolRequested(r) {
		writeError(w, 400, "PROTOCOL_ERROR")
		return
	}
	token := bearer(r)
	s.mu.Lock()
	var t *track
	var a *agent
	if candidate := s.tracks[r.Header.Get("X-XTunnel-Track")]; candidate != nil && token == candidate.token && r.Header.Get("X-XTunnel-Role") == "server" {
		t = candidate
	}
	if r.Header.Get("X-XTunnel-Role") == "agent" {
		a = s.agents[token]
		if a != nil {
			t = a.track
		}
	}
	if t == nil {
		s.mu.Unlock()
		writeError(w, 401, "UNAUTHORIZED")
		return
	}
	if !t.active || !bound(r, t) || (a != nil && (a.id != r.Header.Get("X-XTunnel-Agent") || a.session != t.session || a.version != t.version || t.peer == nil)) {
		s.mu.Unlock()
		writeError(w, 409, "SESSION_INVALID")
		return
	}
	if (a == nil && t.peer != nil) || (a != nil && a.peer != nil) {
		s.mu.Unlock()
		writeError(w, 409, "CONTROL_ALREADY_CONNECTED")
		return
	}
	session, version := t.session, t.version
	s.mu.Unlock()
	conn, e := upgrader.Upgrade(timedHijacker{w}, r, nil)
	if e != nil {
		return
	}
	p := &controlPeer{conn: conn, track: t, agent: a, session: session, sendq: make(chan controlMessage, 32), done: make(chan struct{})}
	s.mu.Lock()
	if s.closed || !t.active || t.session != session || t.version != version || (a == nil && t.peer != nil) || (a != nil && (s.agents[token] != a || a.peer != nil || t.peer == nil)) {
		s.mu.Unlock()
		p.close()
		return
	}
	if a == nil {
		t.peer = p
	} else {
		a.peer = p
	}
	v := view(t)
	s.workers.Add(2)
	s.mu.Unlock()
	defer s.workers.Done()
	defer s.detachControl(p)
	hello := controlMessage{Type: "HELLO", TrackID: t.id, ServiceSession: session, ConfigVersion: version, Rules: &v.Rules}
	if a != nil {
		hello.AgentID = a.id
	} else {
		hello.PairingCode = v.PairingCode
	}
	_ = p.send(hello)
	go func() { defer s.workers.Done(); p.writeLoop() }()
	conn.SetReadLimit(64 << 10)
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error { return conn.SetReadDeadline(time.Now().Add(60 * time.Second)) })
	for {
		kind, b, e := conn.ReadMessage()
		if e != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		if kind != websocket.TextMessage || !utf8.Valid(b) {
			return
		}
		var m controlMessage
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
			return
		}
		switch m.Type {
		case "PING":
			if p.send(controlMessage{Type: "PONG"}) != nil {
				return
			}
		case "PONG":
		case "RESOLVED", "TARGET_READY", "TARGET_FAILED":
			if a != nil || !s.serverResult(p, m) {
				return
			}
		case "CANCEL":
			if a == nil || !s.controlCancel(p, m) {
				return
			}
		default:
			return
		}
	}
}
func (s *Server) detachControl(p *controlPeer) {
	p.close()
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.agent == nil {
		if p.track.peer == p {
			p.track.peer = nil
			s.revokeAgentsLocked(p.track, "TRACK_OFFLINE")
		}
	} else if p.agent.peer == p {
		p.agent.peer = nil
		delete(s.agents, p.agent.token)
		for _, f := range s.forwards {
			if f.agent == p.agent {
				s.finishLocked(f, "CONTROL_DISCONNECTED")
			}
		}
	}
}
func validRequestID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if c < 33 || c > 126 {
			return false
		}
	}
	return !strings.ContainsAny(id, "\r\n")
}
func (s *Server) controlCancel(p *controlPeer, m controlMessage) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.forwards[m.ForwardID]
	if f == nil || f.agent != p.agent || m.ServiceSession != f.session || m.ConfigVersion != f.version {
		return false
	}
	s.finishLocked(f, "CANCELLED")
	return true
}

package relay

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/gorilla/websocket"
)

type ForwardView struct {
	ForwardID   string `json:"forward_id"`
	RequestID   string `json:"request_id"`
	Status      string `json:"status"`
	ActualIP    string `json:"actual_ip,omitempty"`
	Target      Target `json:"target"`
	Transport   string `json:"transport"`
	AgentTicket string `json:"agent_ticket,omitempty"`
	ErrorCode   string `json:"error_code,omitempty"`
}
type forward struct {
	id, requestID, session, transport, status, errorCode string
	version                                              uint64
	track                                                *track
	agent                                                *agent
	target                                               Target
	source                                               netip.AddrPort
	selectedIP                                           netip.Addr
	inspection                                           Inspection
	prefix, dnsQuery                                     []byte
	rules                                                *compiledRules
	agentTicket                                          string
	agentConn, serverConn                                *websocket.Conn
	targetReady, terminal                                bool
	ready, done                                          chan struct{}
	deadline, connectDeadline, finished                  time.Time
}
type ticket struct {
	forward *forward
	role    string
	expires time.Time
}

func forwardView(f *forward) ForwardView {
	v := ForwardView{ForwardID: f.id, RequestID: f.requestID, Status: f.status, Target: f.target, Transport: f.transport, ErrorCode: f.errorCode}
	if f.selectedIP.IsValid() {
		v.ActualIP = f.selectedIP.String()
	}
	if !f.terminal {
		v.AgentTicket = f.agentTicket
	}
	return v
}
func (s *Server) currentForwardLocked(f *forward) bool {
	return !s.closed && !f.terminal && f.track.active && f.track.peer != nil && f.track.session == f.session && f.track.version == f.version && s.agents[f.agent.token] == f.agent && f.agent.peer != nil
}
func (s *Server) notifyForwardLocked(f *forward) {
	if f.agent.peer != nil {
		_ = f.agent.peer.send(controlMessage{Type: "FORWARD_RESULT", ForwardID: f.id, RequestID: f.requestID, ServiceSession: f.session, ConfigVersion: f.version, ActualIP: forwardView(f).ActualIP, ErrorCode: f.errorCode, Transport: f.transport, Target: &f.target})
	}
}
func (s *Server) finishLocked(f *forward, code string) {
	if f.terminal {
		return
	}
	f.terminal = true
	f.status = "FAILED"
	if code == "CLOSED" {
		f.status = "CLOSED"
	}
	f.errorCode = code
	f.finished = time.Now()
	close(f.done)
	for token, t := range s.tickets {
		if t.forward == f {
			delete(s.tickets, token)
		}
	}
	if f.agentConn != nil {
		_ = f.agentConn.Close()
	}
	if f.serverConn != nil {
		_ = f.serverConn.Close()
	}
	s.notifyForwardLocked(f)
	if f.track.peer != nil && f.track.session == f.session {
		_ = f.track.peer.send(controlMessage{Type: "CLOSE_FORWARD", ForwardID: f.id, ServiceSession: f.session, ConfigVersion: f.version, ErrorCode: code})
	}
}
func (s *Server) forwardForAgentLocked(w http.ResponseWriter, r *http.Request) (*forward, *agent) {
	a := s.agentLocked(w, r)
	if a == nil {
		return nil, nil
	}
	f := s.forwards[r.PathValue("forward")]
	if f == nil || f.agent != a {
		writeError(w, 404, "FORWARD_NOT_FOUND")
		return nil, a
	}
	return f, a
}
func (s *Server) reserveForwardLocked(w http.ResponseWriter, r *http.Request, reqID string) (*forward, *agent) {
	a := s.agentLocked(w, r)
	if a == nil {
		return nil, nil
	}
	if a.peer == nil {
		writeError(w, 409, "CONTROL_OFFLINE")
		return nil, a
	}
	n := 0
	for _, f := range s.forwards {
		if f.agent == a {
			n++
			if !f.terminal && f.requestID == reqID {
				writeError(w, 409, "DUPLICATE_REQUEST")
				return nil, a
			}
		}
	}
	if n >= 128 || len(s.forwards) >= 8192 {
		writeError(w, 503, "RESOURCE_LIMIT")
		return nil, a
	}
	id, e := secret()
	if e != nil {
		writeError(w, 500, "INTERNAL_ERROR")
		return nil, a
	}
	f := &forward{id: id, requestID: reqID, session: a.session, version: a.version, track: a.track, agent: a, status: "RESOLVING", rules: a.track.rules, ready: make(chan struct{}), done: make(chan struct{}), deadline: time.Now().Add(5 * time.Second)}
	s.forwards[id] = f
	return f, a
}

type forwardRequest struct {
	RequestID      string `json:"request_id"`
	Transport      string `json:"transport"`
	Target         Target `json:"target"`
	FirstPacket    []byte `json:"first_packet,omitempty"`
	SourceEndpoint string `json:"source_endpoint,omitempty"`
}

func (s *Server) createForward(w http.ResponseWriter, r *http.Request) {
	var req forwardRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !validRequestID(req.RequestID) || (req.Transport != "tcp" && req.Transport != "udp") || len(req.FirstPacket) > maxFirstPacket {
		writeError(w, 400, "PROTOCOL_ERROR")
		return
	}
	target, e := normalizeTarget(req.Target)
	if e != nil {
		writeError(w, 400, "PROTOCOL_ERROR")
		return
	}
	ins := Inspection{Kind: "tcp", Host: target.Host, Port: target.Port}
	var source netip.AddrPort
	if req.Transport == "tcp" {
		ins, e = inspectPrefix(target, req.FirstPacket)
		if e != nil {
			writeError(w, 400, "PROTOCOL_ERROR")
			return
		}
		if ins.Kind == "connect" {
			// The agent terminates a downstream CONNECT and tunnels its payload.
			writeError(w, 400, "PROTOCOL_ERROR")
			return
		}
		if (ins.Kind == "http1" || ins.Kind == "h2") && len(ins.Header) != len(req.FirstPacket) {
			writeError(w, 400, "PROTOCOL_ERROR")
			return
		}
		target = Target{Host: ins.Host, Port: ins.Port}
	} else {
		source, e = netip.ParseAddrPort(req.SourceEndpoint)
		if e != nil || !source.Addr().Is4() || source.Port() == 0 || len(req.FirstPacket) != 0 {
			writeError(w, 400, "PROTOCOL_ERROR")
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, _ := s.reserveForwardLocked(w, r, req.RequestID)
	if f == nil {
		return
	}
	f.transport = req.Transport
	f.target = target
	f.inspection = ins
	f.prefix = append([]byte(nil), req.FirstPacket...)
	f.source = source
	if ip, e := netip.ParseAddr(target.Host); e == nil {
		s.chooseCandidateLocked(f, []string{ip.String()})
	} else {
		_ = f.track.peer.send(controlMessage{Type: "RESOLVE", ForwardID: f.id, RequestID: f.requestID, ServiceSession: f.session, ConfigVersion: f.version, Target: &f.target})
	}
	writeJSON(w, 202, forwardView(f))
}
func (s *Server) chooseCandidateLocked(f *forward, candidates []string) {
	if len(candidates) == 0 || len(candidates) > 32 {
		s.finishLocked(f, "RESOLUTION_FAILED")
		return
	}
	ips := make([]netip.Addr, 0, len(candidates))
	for _, c := range candidates {
		ip, e := netip.ParseAddr(c)
		if e != nil || !ip.Is4() {
			s.finishLocked(f, "PROTOCOL_ERROR")
			return
		}
		ips = append(ips, ip)
	}
	isHTTP := f.inspection.Kind == "http1" || f.inspection.Kind == "h2"
	for _, ip := range ips {
		if f.rules.allows(ip, f.inspection.Host, f.inspection.URL, isHTTP) {
			f.selectedIP = ip
			break
		}
	}
	if !f.selectedIP.IsValid() {
		s.finishLocked(f, "RULE_REJECTED")
		return
	}
	f.status = "CONFIRM_REQUIRED"
	f.deadline = time.Now().Add(30 * time.Second)
	if f.agent.peer != nil {
		_ = f.agent.peer.send(controlMessage{Type: "CONFIRM_REQUIRED", ForwardID: f.id, RequestID: f.requestID, ServiceSession: f.session, ConfigVersion: f.version, Target: &f.target, ActualIP: f.selectedIP.String(), Transport: f.transport})
	}
}
func (s *Server) getForward(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, _ := s.forwardForAgentLocked(w, r); f != nil {
		writeJSON(w, 200, forwardView(f))
	}
}

type confirmRequest struct {
	ActualIP string `json:"actual_ip"`
}

func (s *Server) confirmForward(w http.ResponseWriter, r *http.Request) {
	var req confirmRequest
	if !readJSON(w, r, &req) {
		return
	}
	agentTicket, e1 := secret()
	serverTicket, e2 := secret()
	if e1 != nil || e2 != nil {
		writeError(w, 500, "INTERNAL_ERROR")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, _ := s.forwardForAgentLocked(w, r)
	if f == nil {
		return
	}
	if !s.currentForwardLocked(f) || f.status != "CONFIRM_REQUIRED" || req.ActualIP != f.selectedIP.String() {
		writeError(w, 409, "FORWARD_STATE_INVALID")
		return
	}
	s.issueTicketsLocked(f, agentTicket, serverTicket)
	f.targetReady = false
	f.connectDeadline = time.Now().Add(10 * time.Second)
	source := ""
	if f.transport == "udp" {
		source = f.source.String()
	}
	_ = f.track.peer.send(controlMessage{Type: "CONNECT", ForwardID: f.id, RequestID: f.requestID, ServiceSession: f.session, ConfigVersion: f.version, AgentID: f.agent.id, Transport: f.transport, Target: &f.target, ActualIP: f.selectedIP.String(), SourceEndpoint: source, Ticket: serverTicket})
	writeJSON(w, 200, forwardView(f))
}
func (s *Server) issueTicketsLocked(f *forward, a, b string) {
	f.status = "CONNECTING"
	f.agentTicket = a
	f.deadline = time.Now().Add(30 * time.Second)
	expires := time.Now().Add(30 * time.Second)
	s.tickets[a] = &ticket{forward: f, role: "agent", expires: expires}
	s.tickets[b] = &ticket{forward: f, role: "server", expires: expires}
}
func (s *Server) cancelForward(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, _ := s.forwardForAgentLocked(w, r); f != nil {
		s.finishLocked(f, "CANCELLED")
		writeJSON(w, 200, forwardView(f))
	}
}
func (s *Server) serverResult(p *controlPeer, m controlMessage) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.forwards[m.ForwardID]
	// Late messages from canceled or prior versions are ignored, never reactivated.
	if f == nil {
		return true
	}
	if f.track != p.track {
		return false
	}
	if f.terminal || f.session != p.session || m.ServiceSession != f.session || m.ConfigVersion != f.version {
		return true
	}
	if !s.currentForwardLocked(f) || f.track.peer != p {
		return true
	}
	switch m.Type {
	case "RESOLVED":
		if f.status != "RESOLVING" {
			s.finishLocked(f, "PROTOCOL_ERROR")
			return true
		}
		if m.ErrorCode != "" {
			if m.ErrorCode != "RESOLUTION_FAILED" && m.ErrorCode != "TIMEOUT" {
				s.finishLocked(f, "PROTOCOL_ERROR")
				return true
			}
			s.finishLocked(f, m.ErrorCode)
		} else {
			s.chooseCandidateLocked(f, m.Candidates)
		}
	case "TARGET_READY":
		if f.transport == "dns" || f.status != "CONNECTING" || m.ActualIP != f.selectedIP.String() {
			s.finishLocked(f, "PROTOCOL_ERROR")
			return true
		}
		if !time.Now().Before(f.connectDeadline) {
			s.finishLocked(f, "TIMEOUT")
			return true
		}
		f.targetReady = true
		s.maybeReadyLocked(f)
	case "TARGET_FAILED":
		if m.ErrorCode != "CONNECT_FAILED" && m.ErrorCode != "TIMEOUT" && m.ErrorCode != "RESOLUTION_FAILED" {
			s.finishLocked(f, "PROTOCOL_ERROR")
			return true
		}
		s.finishLocked(f, m.ErrorCode)
	default:
		return false
	}
	return true
}
func (s *Server) maybeReadyLocked(f *forward) {
	if !s.currentForwardLocked(f) || f.status != "CONNECTING" || !f.targetReady || f.agentConn == nil || f.serverConn == nil {
		return
	}
	f.status = "READY"
	close(f.ready)
	msg := controlMessage{Type: "READY", ForwardID: f.id, RequestID: f.requestID, ServiceSession: f.session, ConfigVersion: f.version, ActualIP: forwardView(f).ActualIP, Transport: f.transport, Target: &f.target}
	_ = f.agent.peer.send(msg)
	_ = f.track.peer.send(msg)
}

type dnsRequest struct {
	RequestID string `json:"request_id"`
	Query     []byte `json:"query"`
}

func (s *Server) createDNS(w http.ResponseWriter, r *http.Request) {
	var req dnsRequest
	if !readJSON(w, r, &req) {
		return
	}
	q, e := validateDNSQuery(req.Query)
	if e != nil || !validRequestID(req.RequestID) {
		writeError(w, 400, "PROTOCOL_ERROR")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.agentLocked(w, r) == nil {
		return
	}
	if q.Type == 28 {
		answer, e := emptyAAAAAnswer(req.Query)
		if e != nil {
			writeError(w, 400, "PROTOCOL_ERROR")
			return
		}
		writeJSON(w, 200, map[string]any{"status": "ANSWER", "answer": answer})
		return
	}
	at, e1 := secret()
	st, e2 := secret()
	if e1 != nil || e2 != nil {
		writeError(w, 500, "INTERNAL_ERROR")
		return
	}
	f, _ := s.reserveForwardLocked(w, r, req.RequestID)
	if f == nil {
		return
	}
	f.transport = "dns"
	f.target = Target{Host: q.Name}
	f.dnsQuery = append([]byte(nil), req.Query...)
	s.issueTicketsLocked(f, at, st)
	f.targetReady = true
	f.deadline = time.Now().Add(5 * time.Second)
	_ = f.track.peer.send(controlMessage{Type: "DNS_OPEN", ForwardID: f.id, RequestID: f.requestID, ServiceSession: f.session, ConfigVersion: f.version, AgentID: f.agent.id, Transport: "dns", Ticket: st})
	writeJSON(w, 202, forwardView(f))
}

package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error_code": code})
}
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	status := readJSONStatus(w, r, v)
	if status != 0 {
		writeError(w, status, "PROTOCOL_ERROR")
		return false
	}
	return true
}
func readJSONStatus(w http.ResponseWriter, r *http.Request, v any) int {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return 415
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	b, e := io.ReadAll(r.Body)
	if e != nil || !utf8.Valid(b) {
		return 400
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return 400
	}
	if d.Decode(new(any)) != io.EOF {
		return 400
	}
	return 0
}
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") || len(h) > 256 {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}
func bound(r *http.Request, t *track) bool {
	return r.Header.Get("X-XTunnel-Track") == t.id && r.Header.Get("X-XTunnel-Session") == t.session && r.Header.Get("X-XTunnel-Version") == strconv.FormatUint(t.version, 10)
}
func (s *Server) managementLocked(w http.ResponseWriter, r *http.Request) *track {
	if s.closed {
		writeError(w, 503, "SERVER_STOPPED")
		return nil
	}
	t := s.tracks[r.PathValue("track")]
	if t == nil || bearer(r) != t.token {
		writeError(w, 401, "UNAUTHORIZED")
		return nil
	}
	if r.Method != http.MethodGet && !bound(r, t) {
		writeError(w, 409, "SESSION_INVALID")
		return nil
	}
	return t
}
func (s *Server) agentLocked(w http.ResponseWriter, r *http.Request) *agent {
	if s.closed {
		writeError(w, 503, "SERVER_STOPPED")
		return nil
	}
	a := s.agents[bearer(r)]
	if a == nil {
		writeError(w, 401, "UNAUTHORIZED")
		return nil
	}
	if !bound(r, a.track) || r.Header.Get("X-XTunnel-Agent") != a.id || a.session != a.track.session || a.version != a.track.version || !a.track.active || a.track.peer == nil {
		writeError(w, 409, "SESSION_INVALID")
		return nil
	}
	return a
}

type configRequest struct {
	Rules RuleConfig `json:"rules"`
}

// encoding/json accepts null as a zero string; that would turn a null regex
// into an empty expression matching every URL. Reject null list elements.
func (r *RuleConfig) UnmarshalJSON(b []byte) error {
	var payload struct {
		CIDRs    []*string `json:"ipv4_cidrs"`
		Domains  []*string `json:"domains"`
		URLRegex []*string `json:"http_url_regex"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&payload); err != nil {
		return err
	}
	var result RuleConfig
	sources := [][]*string{payload.CIDRs, payload.Domains, payload.URLRegex}
	destinations := []*[]string{&result.CIDRs, &result.Domains, &result.URLRegex}
	for i, source := range sources {
		values := make([]string, len(source))
		for j, value := range source {
			if value == nil {
				return badProtocol("rule entries must be strings")
			}
			values[j] = *value
		}
		*destinations[i] = values
	}
	*r = result
	return nil
}

func (r *configRequest) UnmarshalJSON(b []byte) error {
	var payload struct {
		Rules *RuleConfig `json:"rules"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&payload); err != nil {
		return err
	}
	if payload.Rules == nil {
		return badProtocol("explicit rules object required")
	}
	r.Rules = *payload.Rules
	return nil
}

func (s *Server) createTrack(w http.ResponseWriter, r *http.Request) {
	var req configRequest
	if !readJSON(w, r, &req) {
		return
	}
	rules, e := compileRules(req.Rules)
	if e != nil {
		writeError(w, 400, "INVALID_RULES")
		return
	}
	id, e1 := secret()
	token, e2 := secret()
	session, e3 := secret()
	if e1 != nil || e2 != nil || e3 != nil {
		writeError(w, 500, "INTERNAL_ERROR")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		writeError(w, 503, "SERVER_STOPPED")
		return
	}
	if len(s.tracks) >= 4096 {
		writeError(w, 503, "RESOURCE_LIMIT")
		return
	}
	code, e := s.allocateCodeLocked(nil)
	if e != nil {
		writeError(w, 503, e.Error())
		return
	}
	t := &track{id: id, token: token, session: session, version: 1, code: code, config: req.Rules, rules: rules, active: true, codes: map[string]bool{code: true}}
	s.tracks[id] = t
	s.codes[code] = t
	v := view(t)
	v.ManagementToken = token
	writeJSON(w, 201, v)
}
func (s *Server) getTrack(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.managementLocked(w, r); t != nil {
		writeJSON(w, 200, view(t))
	}
}
func (s *Server) updateRules(w http.ResponseWriter, r *http.Request) {
	var req configRequest
	if !readJSON(w, r, &req) {
		return
	}
	rules, e := compileRules(req.Rules)
	if e != nil {
		writeError(w, 400, "INVALID_RULES")
		return
	}
	s.mu.Lock()
	t := s.managementLocked(w, r)
	if t == nil {
		s.mu.Unlock()
		return
	}
	if !t.active {
		s.mu.Unlock()
		writeError(w, 409, "SESSION_INVALID")
		return
	}
	code, e := s.allocateCodeLocked(nil)
	if e != nil {
		s.mu.Unlock()
		writeError(w, 503, e.Error())
		return
	}
	t.config = req.Rules
	t.rules = rules
	t.version++
	t.code = code
	t.codes[code] = true
	s.codes[code] = t
	s.revokeAgentsLocked(t, "CONFIG_UPDATED")
	p := t.peer
	v := view(t)
	s.mu.Unlock()
	if p != nil {
		_ = p.send(controlMessage{Type: "TRACK_UPDATED", TrackID: v.TrackID, ServiceSession: v.ServiceSession, ConfigVersion: v.ConfigVersion, Rules: &v.Rules, PairingCode: code})
	}
	writeJSON(w, 200, v)
}
func (s *Server) restartTrack(w http.ResponseWriter, r *http.Request) {
	var req configRequest
	if !readJSON(w, r, &req) {
		return
	}
	rules, e := compileRules(req.Rules)
	if e != nil {
		writeError(w, 400, "INVALID_RULES")
		return
	}
	session, e := secret()
	if e != nil {
		writeError(w, 500, "INTERNAL_ERROR")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.managementLocked(w, r)
	if t == nil {
		return
	}
	s.revokeSessionLocked(t, "SESSION_RESTARTED")
	code, e := s.allocateCodeLocked(t.revokedCodes)
	if e != nil {
		writeError(w, 503, e.Error())
		return
	}
	t.session = session
	t.version = 1
	t.config = req.Rules
	t.rules = rules
	t.active = true
	t.code = code
	t.codes[code] = true
	s.codes[code] = t
	writeJSON(w, 200, view(t))
}
func (s *Server) stopTrack(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.managementLocked(w, r); t != nil {
		s.revokeSessionLocked(t, "TRACK_STOPPED")
		writeJSON(w, 200, view(t))
	}
}

type pairRequest struct {
	PairingCode     string `json:"pairing_code"`
	ExpectedTrackID string `json:"expected_track_id,omitempty"`
}
type PairView struct {
	TrackID        string     `json:"track_id"`
	ServiceSession string     `json:"service_session"`
	ConfigVersion  uint64     `json:"config_version"`
	AgentID        string     `json:"agent_id"`
	AgentToken     string     `json:"agent_token"`
	Rules          RuleConfig `json:"rules"`
}

func validCode(c string) bool {
	if len(c) != 4 {
		return false
	}
	for _, ch := range c {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
func (s *Server) pair(w http.ResponseWriter, r *http.Request) {
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		ip = r.RemoteAddr
	}
	s.mu.Lock()
	l := s.failures[ip]
	if l != nil && time.Now().Before(l.blockedUntil) {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "60")
		writeError(w, 429, "PAIR_RATE_LIMITED")
		return
	}
	s.mu.Unlock()
	var req pairRequest
	if status := readJSONStatus(w, r, &req); status != 0 {
		s.mu.Lock()
		limited := s.recordPairFailureLocked(ip)
		s.mu.Unlock()
		if limited {
			w.Header().Set("Retry-After", "60")
			writeError(w, 429, "PAIR_RATE_LIMITED")
		} else {
			writeError(w, status, "PROTOCOL_ERROR")
		}
		return
	}
	id, e1 := secret()
	token, e2 := secret()
	if e1 != nil || e2 != nil {
		writeError(w, 500, "INTERNAL_ERROR")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if l = s.failures[ip]; l != nil && time.Now().Before(l.blockedUntil) {
		w.Header().Set("Retry-After", "60")
		writeError(w, 429, "PAIR_RATE_LIMITED")
		return
	}
	t := s.codes[req.PairingCode]
	if !validCode(req.PairingCode) || t == nil || !t.active || t.peer == nil || (req.ExpectedTrackID != "" && req.ExpectedTrackID != t.id) {
		if s.recordPairFailureLocked(ip) {
			w.Header().Set("Retry-After", "60")
			writeError(w, 429, "PAIR_RATE_LIMITED")
		} else {
			writeError(w, 404, "PAIR_UNAVAILABLE")
		}
		return
	}
	n := 0
	for _, a := range s.agents {
		if a.track == t {
			n++
		}
	}
	if n >= 128 || len(s.agents) >= 8192 {
		writeError(w, 503, "RESOURCE_LIMIT")
		return
	}
	a := &agent{id: id, token: token, session: t.session, version: t.version, track: t, created: time.Now()}
	s.agents[token] = a
	writeJSON(w, 201, PairView{TrackID: t.id, ServiceSession: t.session, ConfigVersion: t.version, AgentID: id, AgentToken: token, Rules: t.config})
}
func (s *Server) recordPairFailureLocked(ip string) bool {
	now := time.Now()
	l := s.failures[ip]
	if l == nil {
		if len(s.failures) >= 8192 {
			return true
		}
		l = &failureLimit{start: now}
		s.failures[ip] = l
	}
	if now.Sub(l.start) >= time.Minute {
		l.start = now
		l.count = 0
	}
	l.count++
	if l.count >= 10 {
		l.blockedUntil = now.Add(time.Minute)
		return true
	}
	return false
}

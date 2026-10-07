package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type TrackView struct {
	TrackID         string     `json:"track_id"`
	ManagementToken string     `json:"management_token,omitempty"`
	ServiceSession  string     `json:"service_session"`
	ConfigVersion   uint64     `json:"config_version"`
	PairingCode     string     `json:"pairing_code"`
	Rules           RuleConfig `json:"rules"`
	Online          bool       `json:"online"`
}
type track struct {
	id, token, session, code string
	version                  uint64
	config                   RuleConfig
	rules                    *compiledRules
	active                   bool
	codes                    map[string]bool
	revokedCodes             map[string]bool
	peer                     *controlPeer
}
type agent struct {
	id, token, session string
	version            uint64
	track              *track
	peer               *controlPeer
	created            time.Time
}
type failureLimit struct {
	start, blockedUntil time.Time
	count               int
}

// Server owns all session state. This process never dials a business target.
type Server struct {
	// ponytail: one lock and a 10,000-code pool; shard after measured contention.
	mu       sync.Mutex
	tracks   map[string]*track
	codes    map[string]*track
	agents   map[string]*agent
	forwards map[string]*forward
	tickets  map[string]*ticket
	failures map[string]*failureLimit
	closed   bool
	done     chan struct{}
	workers  sync.WaitGroup
}

func New() *Server {
	s := &Server{tracks: make(map[string]*track), codes: make(map[string]*track), agents: make(map[string]*agent), forwards: make(map[string]*forward), tickets: make(map[string]*ticket), failures: make(map[string]*failureLimit), done: make(chan struct{})}
	s.workers.Add(1)
	go s.maintain()
	return s
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("POST /v1/tracks", s.createTrack)
	mux.HandleFunc("GET /v1/tracks/{track}", s.getTrack)
	mux.HandleFunc("PUT /v1/tracks/{track}/rules", s.updateRules)
	mux.HandleFunc("POST /v1/tracks/{track}/restart", s.restartTrack)
	mux.HandleFunc("DELETE /v1/tracks/{track}/session", s.stopTrack)
	mux.HandleFunc("POST /v1/pair", s.pair)
	mux.HandleFunc("GET /v1/control", s.control)
	mux.HandleFunc("POST /v1/forwards", s.createForward)
	mux.HandleFunc("GET /v1/forwards/{forward}", s.getForward)
	mux.HandleFunc("POST /v1/forwards/{forward}/confirm", s.confirmForward)
	mux.HandleFunc("DELETE /v1/forwards/{forward}", s.cancelForward)
	mux.HandleFunc("POST /v1/dns", s.createDNS)
	mux.HandleFunc("GET /v1/data", s.data)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.TLS == nil {
			writeError(w, 426, "TLS_REQUIRED")
			return
		}
		if r.URL.RawQuery != "" {
			writeError(w, 400, "PROTOCOL_ERROR")
			return
		}
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			writeError(w, 503, "SERVER_STOPPED")
			return
		}
		if r.URL.Path == "/v1/control" || r.URL.Path == "/v1/data" {
			mux.ServeHTTP(w, r)
			return
		}
		// JSON replies are small and buffered so socket backpressure never holds mu.
		reply := &jsonReply{header: w.Header().Clone()}
		mux.ServeHTTP(reply, r)
		for name, values := range reply.header {
			w.Header()[name] = values
		}
		status := reply.status
		if status == 0 {
			status = 200
		}
		w.WriteHeader(status)
		_, _ = w.Write(reply.body.Bytes())
	})
}

type jsonReply struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *jsonReply) Header() http.Header { return w.header }
func (w *jsonReply) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *jsonReply) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.body.Write(p)
}
func secret() (string, error) {
	var b [32]byte
	if _, e := io.ReadFull(rand.Reader, b[:]); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// allocateCodeLocked does not change ownership until the operation commits.
func (s *Server) allocateCodeLocked(excluded map[string]bool) (string, error) {
	n := 0
	for i := 0; i < 10000; i++ {
		c := fmt.Sprintf("%04d", i)
		if s.codes[c] == nil && !excluded[c] {
			n++
		}
	}
	if n == 0 {
		return "", errors.New("PAIRING_CODE_EXHAUSTED")
	}
	k, e := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if e != nil {
		return "", errors.New("INTERNAL_ERROR")
	}
	idx := int(k.Int64())
	for i := 0; i < 10000; i++ {
		c := fmt.Sprintf("%04d", i)
		if s.codes[c] == nil && !excluded[c] {
			if idx == 0 {
				return c, nil
			}
			idx--
		}
	}
	return "", errors.New("PAIRING_CODE_EXHAUSTED")
}
func view(t *track) TrackView {
	return TrackView{TrackID: t.id, ServiceSession: t.session, ConfigVersion: t.version, PairingCode: t.code, Rules: t.config, Online: t.active && t.peer != nil}
}
func (s *Server) revokeAgentsLocked(t *track, reason string) {
	for token, a := range s.agents {
		if a.track == t {
			delete(s.agents, token)
			if a.peer != nil {
				a.peer.terminate(reason)
			}
		}
	}
	for _, f := range s.forwards {
		if f.track == t {
			s.finishLocked(f, reason)
		}
	}
}
func (s *Server) revokeSessionLocked(t *track, reason string) {
	t.active = false
	if len(t.codes) > 0 {
		t.revokedCodes = t.codes
	}
	for c := range t.codes {
		delete(s.codes, c)
	}
	t.codes = make(map[string]bool)
	t.code = ""
	p := t.peer
	t.peer = nil
	s.revokeAgentsLocked(t, reason)
	if p != nil {
		p.terminate(reason)
	}
}
func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.done)
	for _, t := range s.tracks {
		s.revokeSessionLocked(t, "SERVER_STOPPED")
	}
	s.mu.Unlock()
	s.workers.Wait()
}
func (s *Server) maintain() {
	defer s.workers.Done()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-tick.C:
			s.mu.Lock()
			for token, t := range s.tickets {
				if !now.Before(t.expires) {
					delete(s.tickets, token)
					s.finishLocked(t.forward, "TIMEOUT")
				}
			}
			for id, f := range s.forwards {
				if f.terminal {
					if now.Sub(f.finished) > 30*time.Second {
						delete(s.forwards, id)
					}
					continue
				}
				if (f.status != "READY" || f.transport == "dns") && !f.deadline.IsZero() && !now.Before(f.deadline) {
					s.finishLocked(f, "TIMEOUT")
				}
				if !f.targetReady && !f.connectDeadline.IsZero() && !now.Before(f.connectDeadline) {
					s.finishLocked(f, "TIMEOUT")
				}
			}
			for token, a := range s.agents {
				if a.peer == nil && now.Sub(a.created) > 60*time.Second {
					delete(s.agents, token)
				}
			}
			for ip, l := range s.failures {
				if now.Sub(l.start) > 2*time.Minute && !now.Before(l.blockedUntil) {
					delete(s.failures, ip)
				}
			}
			s.mu.Unlock()
		}
	}
}

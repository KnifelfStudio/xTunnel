package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

func (s *Server) data(w http.ResponseWriter, r *http.Request) {
	if !protocolRequested(r) {
		writeError(w, 400, "PROTOCOL_ERROR")
		return
	}
	role := r.Header.Get("X-XTunnel-Role")
	token := r.Header.Get("X-XTunnel-Ticket")
	s.mu.Lock()
	t := s.tickets[token]
	if t == nil || !time.Now().Before(t.expires) {
		s.mu.Unlock()
		writeError(w, 401, "TICKET_INVALID")
		return
	}
	f := t.forward
	identity := role == "agent" && bearer(r) == f.agent.token || role == "server" && bearer(r) == f.track.token
	if role != t.role || !identity || !bound(r, f.track) || r.Header.Get("X-XTunnel-Agent") != f.agent.id || r.Header.Get("X-XTunnel-Forward") != f.id || !s.currentForwardLocked(f) || (role == "agent" && f.agentConn != nil) || (role == "server" && f.serverConn != nil) {
		s.mu.Unlock()
		writeError(w, 403, "TICKET_BINDING_INVALID")
		return
	}
	delete(s.tickets, token)
	s.mu.Unlock()
	conn, e := upgrader.Upgrade(timedHijacker{w}, r, nil)
	if e != nil {
		s.mu.Lock()
		s.finishLocked(f, "PROTOCOL_ERROR")
		s.mu.Unlock()
		return
	}
	conn.SetReadLimit(maxDataMessage)
	s.mu.Lock()
	if !s.currentForwardLocked(f) || (role == "agent" && f.agentConn != nil) || (role == "server" && f.serverConn != nil) {
		s.mu.Unlock()
		_ = conn.Close()
		return
	}
	if role == "agent" {
		f.agentConn = conn
	} else {
		f.serverConn = conn
	}
	s.workers.Add(2)
	s.maybeReadyLocked(f)
	s.mu.Unlock()
	go s.dataHeartbeat(conn, f)
	defer s.workers.Done()
	select {
	case <-f.done:
		return
	case <-f.ready:
	}
	if role == "server" {
		<-f.done
		return
	}
	code := s.runForward(f)
	s.mu.Lock()
	s.finishLocked(f, code)
	s.mu.Unlock()
}

type wsReader struct {
	conn    *websocket.Conn
	current io.Reader
	fin     bool
}

func (r *wsReader) SetReadDeadline(t time.Time) error { return r.conn.SetReadDeadline(t) }
func (r *wsReader) Read(p []byte) (int, error) {
	if r.fin {
		return 0, io.EOF
	}
	for {
		if r.current != nil {
			n, e := r.current.Read(p)
			if e == io.EOF {
				r.current = nil
				if n > 0 {
					return n, nil
				}
			} else {
				return n, e
			}
		}
		kind, reader, e := r.conn.NextReader()
		if e != nil {
			return 0, e
		}
		if kind == websocket.TextMessage {
			b, e := io.ReadAll(io.LimitReader(reader, 129))
			if e != nil {
				return 0, e
			}
			var m struct {
				Type string `json:"type"`
			}
			d := json.NewDecoder(bytes.NewReader(b))
			d.DisallowUnknownFields()
			if len(b) > 128 || d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || m.Type != "FIN" {
				return 0, badProtocol("unexpected data text")
			}
			r.fin = true
			if timed, ok := r.conn.NetConn().(*messageConn); ok {
				timed.readFinished.Store(true)
			}
			return 0, io.EOF
		}
		if kind != websocket.BinaryMessage {
			return 0, badProtocol("non-binary data")
		}
		r.current = reader
	}
}

type wsWriter struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (w *wsWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for len(p) > 0 {
		size := len(p)
		if size > maxDataMessage {
			size = maxDataMessage
		}
		_ = w.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if e := w.conn.WriteMessage(websocket.BinaryMessage, p[:size]); e != nil {
			return n, e
		}
		n += size
		p = p[size:]
	}
	return n, nil
}
func (w *wsWriter) fin() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return w.conn.WriteJSON(map[string]string{"type": "FIN"})
}
func (s *Server) runForward(f *forward) string {
	switch f.transport {
	case "dns":
		return s.runDNS(f)
	case "udp":
		return s.runUDP(f)
	case "tcp":
		return s.runTCP(f)
	default:
		return "PROTOCOL_ERROR"
	}
}
func (s *Server) runTCP(f *forward) string {
	a := &wsReader{conn: f.agentConn}
	b := &wsReader{conn: f.serverConn}
	aw := &wsWriter{conn: f.agentConn}
	bw := &wsWriter{conn: f.serverConn}
	exchange := newStreamSession()
	defer exchange.close()
	results := make(chan error, 2)
	go func() {
		source := io.Reader(a)
		if len(f.prefix) > 0 {
			_ = a.SetReadDeadline(time.Now().Add(10 * time.Second))
			got := make([]byte, len(f.prefix))
			_, e := io.ReadFull(a, got)
			_ = a.SetReadDeadline(time.Time{})
			if e != nil || !bytes.Equal(got, f.prefix) {
				results <- badProtocol("precheck prefix mismatch")
				return
			}
			source = &prefixedReader{Reader: io.MultiReader(bytes.NewReader(got), a), deadline: a}
		}
		e := guardTCP(bw, source, f.target, f.selectedIP, f.rules, f.inspection, exchange)
		if e == nil {
			e = bw.fin()
		}
		results <- e
	}()
	go func() {
		e := relayResponses(aw, b, f.inspection, exchange)
		if e == nil {
			e = aw.fin()
		}
		results <- e
	}()
	first := <-results
	if first != nil {
		exchange.close()
		_ = f.agentConn.Close()
		_ = f.serverConn.Close()
		<-results
		return classifyDataError(first)
	}
	second := <-results
	return classifyDataError(second)
}

type prefixedReader struct {
	io.Reader
	deadline *wsReader
}

func (r *prefixedReader) SetReadDeadline(t time.Time) error { return r.deadline.SetReadDeadline(t) }
func classifyDataError(e error) string {
	if e == nil || errors.Is(e, io.EOF) {
		return "CLOSED"
	}
	var protocol *protocolError
	if errors.As(e, &protocol) {
		return "PROTOCOL_ERROR"
	}
	var timeout interface{ Timeout() bool }
	if errors.As(e, &timeout) && timeout.Timeout() {
		return "TIMEOUT"
	}
	// A channel that already carried business cannot authorize replay of that channel.
	if isRuleRejection(e) {
		return "RULE_REJECTED_AFTER_READY"
	}
	return "CHANNEL_FAILED"
}
func (s *Server) runDNS(f *forward) string {
	_ = f.serverConn.SetWriteDeadline(f.deadline)
	if e := f.serverConn.WriteMessage(websocket.BinaryMessage, f.dnsQuery); e != nil {
		return "CHANNEL_FAILED"
	}
	_ = f.serverConn.SetReadDeadline(f.deadline)
	kind, response, e := readDataMessage(f.serverConn)
	if e != nil {
		return classifyDataError(e)
	}
	if kind != websocket.BinaryMessage || validateDNSResponse(f.dnsQuery, response) != nil {
		return "PROTOCOL_ERROR"
	}
	_ = f.agentConn.SetWriteDeadline(f.deadline)
	if f.agentConn.WriteMessage(websocket.BinaryMessage, response) != nil {
		return "CHANNEL_FAILED"
	}
	return "CLOSED"
}

// UDP v1: version byte, source IPv4/port, destination IPv4/port, then datagram.
func udpFrame(source netip.AddrPort, destination netip.AddrPort, payload []byte) []byte {
	a := source.Addr().As4()
	b := destination.Addr().As4()
	out := make([]byte, 13+len(payload))
	out[0] = 1
	copy(out[1:5], a[:])
	out[5] = byte(source.Port() >> 8)
	out[6] = byte(source.Port())
	copy(out[7:11], b[:])
	out[11] = byte(destination.Port() >> 8)
	out[12] = byte(destination.Port())
	copy(out[13:], payload)
	return out
}
func checkUDPFrame(frame []byte, source, destination netip.AddrPort) error {
	if len(frame) < 13 || len(frame) > 13+65507 || frame[0] != 1 {
		return badProtocol("invalid UDP datagram")
	}
	want := udpFrame(source, destination, nil)
	if !bytes.Equal(frame[:13], want) {
		return badProtocol("UDP endpoint mismatch")
	}
	return nil
}
func (s *Server) runUDP(f *forward) string {
	dst := netip.AddrPortFrom(f.selectedIP, uint16(f.target.Port))
	done := make(chan error, 2)
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	watchDone := make(chan struct{})
	watchStopped := make(chan struct{})
	var idle atomic.Bool
	go func() {
		defer close(watchStopped)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-watchDone:
				return
			case now := <-tick.C:
				if now.Sub(time.Unix(0, lastActivity.Load())) >= 60*time.Second {
					idle.Store(true)
					_ = f.agentConn.Close()
					_ = f.serverConn.Close()
					return
				}
			}
		}
	}()
	pump := func(src, dstConn *websocket.Conn) {
		for {
			kind, frame, e := readDataMessage(src)
			if e == nil && (kind != websocket.BinaryMessage || checkUDPFrame(frame, f.source, dst) != nil) {
				e = badProtocol("invalid UDP frame")
			}
			if e != nil {
				done <- e
				return
			}
			lastActivity.Store(time.Now().UnixNano())
			_ = dstConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if e = dstConn.WriteMessage(websocket.BinaryMessage, frame); e != nil {
				done <- e
				return
			}
		}
	}
	go pump(f.agentConn, f.serverConn)
	go pump(f.serverConn, f.agentConn)
	e := <-done
	_ = f.agentConn.Close()
	_ = f.serverConn.Close()
	<-done
	close(watchDone)
	<-watchStopped
	if idle.Load() {
		return "TIMEOUT"
	}
	return classifyDataError(e)
}

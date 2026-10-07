package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/dns/dnsmessage"
)

type testClient struct {
	t      *testing.T
	server *httptest.Server
	track  TrackView
	pair   PairView
}

func newTestClient(t *testing.T, s *Server) *testClient {
	t.Helper()
	ts := httptest.NewTLSServer(s.Handler())
	t.Cleanup(ts.Close)
	return &testClient{t: t, server: ts}
}
func (c *testClient) headers(role string) http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-XTunnel-Track", c.track.TrackID)
	h.Set("X-XTunnel-Session", c.track.ServiceSession)
	h.Set("X-XTunnel-Version", strconv.FormatUint(c.track.ConfigVersion, 10))
	h.Set("X-XTunnel-Role", role)
	if role == "server" {
		h.Set("Authorization", "Bearer "+c.track.ManagementToken)
	} else if role == "agent" {
		h.Set("Authorization", "Bearer "+c.pair.AgentToken)
		h.Set("X-XTunnel-Agent", c.pair.AgentID)
	}
	return h
}
func (c *testClient) request(method, path, role string, body any, want int, out any) {
	c.t.Helper()
	b, e := json.Marshal(body)
	if e != nil {
		c.t.Fatal(e)
	}
	r, e := http.NewRequest(method, c.server.URL+path, bytes.NewReader(b))
	if e != nil {
		c.t.Fatal(e)
	}
	r.Header = c.headers(role)
	res, e := c.server.Client().Do(r)
	if e != nil {
		c.t.Fatal(e)
	}
	defer res.Body.Close()
	if res.StatusCode != want {
		var failed struct {
			Code string `json:"error_code"`
		}
		_ = json.NewDecoder(res.Body).Decode(&failed)
		c.t.Fatalf("%s: status %d want %d: %s", method, res.StatusCode, want, failed.Code)
	}
	if out != nil && json.NewDecoder(res.Body).Decode(out) != nil {
		c.t.Fatal("decode response")
	}
}
func (c *testClient) create(rules RuleConfig) {
	c.request("POST", "/v1/tracks", "", configRequest{Rules: rules}, 201, &c.track)
}
func (c *testClient) control(role string) *websocket.Conn {
	c.t.Helper()
	d := websocket.Dialer{TLSClientConfig: c.server.Client().Transport.(*http.Transport).TLSClientConfig, Subprotocols: []string{"xtunnel.v1"}}
	conn, res, e := d.Dial("wss"+strings.TrimPrefix(c.server.URL, "https")+"/v1/control", c.headers(role))
	if e != nil {
		if res != nil {
			c.t.Fatalf("control dial %d: %v", res.StatusCode, e)
		}
		c.t.Fatal(e)
	}
	c.t.Cleanup(func() { _ = conn.Close() })
	readControl(c.t, conn, "HELLO")
	return conn
}
func readControl(t *testing.T, conn *websocket.Conn, kind string) controlMessage {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		var m controlMessage
		if e := conn.ReadJSON(&m); e != nil {
			t.Fatal(e)
		}
		if m.Type == "PING" {
			_ = conn.WriteJSON(controlMessage{Type: "PONG"})
			continue
		}
		if m.Type == kind {
			return m
		}
	}
}
func (c *testClient) pairAgent(code, expected string, want int) {
	c.request("POST", "/v1/pair", "", pairRequest{PairingCode: code, ExpectedTrackID: expected}, want, &c.pair)
}
func (c *testClient) data(role string, f ForwardView, ticket string, want int) *websocket.Conn {
	c.t.Helper()
	h := c.headers(role)
	h.Set("X-XTunnel-Ticket", ticket)
	h.Set("X-XTunnel-Forward", f.ForwardID)
	h.Set("X-XTunnel-Agent", c.pair.AgentID)
	d := websocket.Dialer{TLSClientConfig: c.server.Client().Transport.(*http.Transport).TLSClientConfig, Subprotocols: []string{"xtunnel.v1"}}
	conn, res, e := d.Dial("wss"+strings.TrimPrefix(c.server.URL, "https")+"/v1/data", h)
	if want != 101 {
		if e == nil {
			conn.Close()
			c.t.Fatal("unexpected ticket success")
		}
		if res == nil || res.StatusCode != want {
			c.t.Fatalf("ticket status want%d: %v", want, e)
		}
		res.Body.Close()
		return nil
	}
	if e != nil {
		c.t.Fatalf("data dial: %v", e)
	}
	c.t.Cleanup(func() { conn.Close() })
	return conn
}
func (c *testClient) openForward(sc, ac *websocket.Conn, transport string, target Target, prefix []byte, source string) (ForwardView, *websocket.Conn, *websocket.Conn) {
	c.t.Helper()
	var f ForwardView
	c.request("POST", "/v1/forwards", "agent", forwardRequest{RequestID: "request-" + strconv.FormatInt(time.Now().UnixNano(), 10), Transport: transport, Target: target, FirstPacket: prefix, SourceEndpoint: source}, 202, &f)
	if _, e := netip.ParseAddr(f.Target.Host); e != nil {
		resolve := readControl(c.t, sc, "RESOLVE")
		_ = sc.WriteJSON(controlMessage{Type: "RESOLVED", ForwardID: resolve.ForwardID, ServiceSession: c.track.ServiceSession, ConfigVersion: c.track.ConfigVersion, Candidates: []string{"10.1.2.3"}})
	}
	offer := readControl(c.t, ac, "CONFIRM_REQUIRED")
	c.request("POST", "/v1/forwards/"+f.ForwardID+"/confirm", "agent", confirmRequest{ActualIP: offer.ActualIP}, 200, &f)
	connect := readControl(c.t, sc, "CONNECT")
	a := c.data("agent", f, f.AgentTicket, 101)
	b := c.data("server", f, connect.Ticket, 101)
	_ = sc.WriteJSON(controlMessage{Type: "TARGET_READY", ForwardID: f.ForwardID, ServiceSession: c.track.ServiceSession, ConfigVersion: c.track.ConfigVersion, ActualIP: f.ActualIP})
	readControl(c.t, ac, "READY")
	readControl(c.t, sc, "READY")
	return f, a, b
}

func TestSessionsUpdateRestartAndPairCodeOwnership(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	c := newTestClient(t, s)
	c.create(RuleConfig{})
	old := c.track.PairingCode
	c.pairAgent(old, "", 404)
	sc := c.control("server")
	c.pairAgent(old, "", 201)
	c.control("agent")
	c.request("PUT", "/v1/tracks/"+c.track.TrackID+"/rules", "server", configRequest{Rules: RuleConfig{Domains: []string{"example.com"}}}, 200, &c.track)
	readControl(t, sc, "TRACK_UPDATED")
	if c.track.PairingCode == old || c.track.ConfigVersion != 2 {
		t.Fatal("update did not rotate code/version")
	}
	c.pairAgent(old, c.track.TrackID, 201)
	if len(c.pair.Rules.Domains) != 1 {
		t.Fatal("old code has old rules")
	}
	c.request("POST", "/v1/tracks/"+c.track.TrackID+"/restart", "server", configRequest{Rules: RuleConfig{}}, 200, &c.track)
	c.pairAgent(old, "", 404)
	if c.track.PairingCode == old || c.track.Online {
		t.Fatal("restart reused old code or remained online")
	}
	c.control("server")
	c.pairAgent(c.track.PairingCode, c.track.TrackID, 201)
	c.pairAgent(c.track.PairingCode, "different-track", 404)
}
func TestTCPAndUDPRelayAndOneUseTickets(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	c := newTestClient(t, s)
	c.create(RuleConfig{CIDRs: []string{"10.0.0.0/8"}})
	sc := c.control("server")
	c.pairAgent(c.track.PairingCode, "", 201)
	ac := c.control("agent")
	f, a, b := c.openForward(sc, ac, "tcp", Target{Host: "10.1.2.3", Port: 1234}, []byte{0, 1, 2}, "")
	c.data("agent", f, f.AgentTicket, 401)
	if e := a.WriteMessage(websocket.BinaryMessage, []byte{0, 1, 2, 3, 4}); e != nil {
		t.Fatal(e)
	}
	_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
	p := make([]byte, 5)
	_, e := io.ReadFull(&wsReader{conn: b}, p)
	if e != nil || !bytes.Equal(p, []byte{0, 1, 2, 3, 4}) {
		t.Fatalf("TCP bytes %v %v", p, e)
	}
	_ = b.WriteMessage(websocket.BinaryMessage, []byte("reply"))
	_ = a.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, p, e = a.ReadMessage()
	if e != nil || string(p) != "reply" {
		t.Fatalf("TCP reply %v %v", p, e)
	}
	c.request("DELETE", "/v1/forwards/"+f.ForwardID, "agent", nil, 200, nil)
	_, a, b = c.openForward(sc, ac, "udp", Target{Host: "10.1.2.3", Port: 53}, nil, "192.0.2.1:12345")
	frame := udpFrame(netip.MustParseAddrPort("192.0.2.1:12345"), netip.MustParseAddrPort("10.1.2.3:53"), []byte{4, 5, 6})
	_ = a.WriteMessage(websocket.BinaryMessage, frame)
	_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, p, e = b.ReadMessage()
	if e != nil || !bytes.Equal(p, frame) {
		t.Fatalf("UDP boundary %v", e)
	}
	frame[12]++
	_ = a.WriteMessage(websocket.BinaryMessage, frame)
	result := readControl(t, ac, "FORWARD_RESULT")
	if result.ErrorCode != "PROTOCOL_ERROR" {
		t.Fatalf("UDP mutation %s", result.ErrorCode)
	}
}
func TestRuleRejectionDoesNotIssueTicketsOrReachServer(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	c := newTestClient(t, s)
	c.create(RuleConfig{URLRegex: []string{"^http://api.example.com/allowed$"}})
	sc := c.control("server")
	c.pairAgent(c.track.PairingCode, "", 201)
	ac := c.control("agent")
	var f ForwardView
	c.request("POST", "/v1/forwards", "agent", forwardRequest{RequestID: "rejected", Transport: "tcp", Target: Target{Host: "api.example.com", Port: 80}, FirstPacket: []byte("GET /denied HTTP/1.1\r\nHost: api.example.com\r\n\r\n")}, 202, &f)
	resolve := readControl(t, sc, "RESOLVE")
	_ = sc.WriteJSON(controlMessage{Type: "RESOLVED", ForwardID: resolve.ForwardID, ServiceSession: c.track.ServiceSession, ConfigVersion: c.track.ConfigVersion, Candidates: []string{"10.1.2.3"}})
	result := readControl(t, ac, "FORWARD_RESULT")
	if result.ErrorCode != "RULE_REJECTED" {
		t.Fatalf("not rule rejection %s", result.ErrorCode)
	}
	c.request("GET", "/v1/forwards/"+f.ForwardID, "agent", nil, 200, &f)
	if f.AgentTicket != "" || f.Status != "FAILED" {
		t.Fatal("rejection granted data")
	}
	s.mu.Lock()
	count := len(s.tickets)
	s.mu.Unlock()
	if count != 0 {
		t.Fatal("tickets created for rejected request")
	}
}

func TestDataPrefixFailureKeepsTrackOnline(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	c := newTestClient(t, s)
	c.create(RuleConfig{})
	sc := c.control("server")
	c.pairAgent(c.track.PairingCode, "", 201)
	ac := c.control("agent")
	_, a, b := c.openForward(sc, ac, "tcp", Target{Host: "10.1.2.3", Port: 1234}, []byte{0, 1, 2}, "")
	_ = a.WriteMessage(websocket.BinaryMessage, []byte{0, 3, 4})
	m := readControl(t, ac, "FORWARD_RESULT")
	if m.ErrorCode != "PROTOCOL_ERROR" {
		t.Fatalf("prefix mismatch %s", m.ErrorCode)
	}
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, p, e := b.ReadMessage(); e == nil {
		t.Fatalf("mismatched prefix reached server: %v", p)
	}
	_, a, b = c.openForward(sc, ac, "tcp", Target{Host: "10.1.2.3", Port: 1234}, []byte{0}, "")
	_ = a.WriteMessage(websocket.BinaryMessage, []byte{0, 5})
	p := make([]byte, 2)
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, e := io.ReadFull(&wsReader{conn: b}, p); e != nil || !bytes.Equal(p, []byte{0, 5}) {
		t.Fatalf("track did not survive data failure: %v", e)
	}
	_ = a.WriteMessage(websocket.TextMessage, []byte(`{"type":"FIN","extra":1}`))
	m = readControl(t, ac, "FORWARD_RESULT")
	if m.ErrorCode != "PROTOCOL_ERROR" {
		t.Fatalf("invalid FIN accepted: %s", m.ErrorCode)
	}
}
func TestCodePoolFailureIsAtomicAndRestartStaysStopped(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	c := newTestClient(t, s)
	c.create(RuleConfig{})
	c.control("server")
	old := c.track
	s.mu.Lock()
	owner := &track{}
	for i := 0; i < 10000; i++ {
		code := fmt.Sprintf("%04d", i)
		if s.codes[code] == nil {
			s.codes[code] = owner
		}
	}
	s.mu.Unlock()
	c.request("PUT", "/v1/tracks/"+old.TrackID+"/rules", "server", configRequest{Rules: RuleConfig{Domains: []string{"example.com"}}}, 503, nil)
	c.request("GET", "/v1/tracks/"+old.TrackID, "server", nil, 200, &c.track)
	if c.track.ConfigVersion != old.ConfigVersion || c.track.PairingCode != old.PairingCode || !c.track.Online {
		t.Fatal("failed update partially committed")
	}
	c.request("POST", "/v1/tracks/"+old.TrackID+"/restart", "server", configRequest{}, 503, nil)
	c.request("GET", "/v1/tracks/"+old.TrackID, "server", nil, 200, &c.track)
	if c.track.Online || c.track.PairingCode != "" {
		t.Fatal("exhausted restart restored old session")
	}
	c.request("POST", "/v1/tracks/"+old.TrackID+"/restart", "server", configRequest{}, 503, nil)
}
func TestPairFailureLimitAndLeadingZeroCode(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	c := newTestClient(t, s)
	c.create(RuleConfig{})
	c.control("server")
	s.mu.Lock()
	track := s.tracks[c.track.TrackID]
	delete(s.codes, track.code)
	track.codes = map[string]bool{"0007": true}
	track.code = "0007"
	s.codes["0007"] = track
	s.mu.Unlock()
	c.track.PairingCode = "0007"
	c.pairAgent("0007", "", 201)
	for i := 0; i < 9; i++ {
		c.request("POST", "/v1/pair", "", pairRequest{PairingCode: "bad"}, 404, nil)
	}
	c.request("POST", "/v1/pair", "", pairRequest{PairingCode: "bad"}, 429, nil)
	c.request("POST", "/v1/pair", "", pairRequest{PairingCode: "0007"}, 429, nil)
}
func TestDNSAuxiliaryChannelUsesServerAndPreservesCNAMEAndTTL(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	c := newTestClient(t, s)
	c.create(RuleConfig{CIDRs: []string{"192.0.2.0/24"}})
	sc := c.control("server")
	c.pairAgent(c.track.PairingCode, "", 201)
	ac := c.control("agent")
	query := dnsQueryFixture(t, dnsmessage.TypeA)
	var f ForwardView
	c.request("POST", "/v1/dns", "agent", dnsRequest{RequestID: "private-dns", Query: query}, 202, &f)
	open := readControl(t, sc, "DNS_OPEN")
	a := c.data("agent", f, f.AgentTicket, 101)
	b := c.data("server", f, open.Ticket, 101)
	readControl(t, ac, "READY")
	readControl(t, sc, "READY")
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	kind, got, e := b.ReadMessage()
	if e != nil || kind != websocket.BinaryMessage || !bytes.Equal(got, query) {
		t.Fatalf("server DNS query %v", e)
	}
	var msg dnsmessage.Message
	if e := msg.Unpack(query); e != nil {
		t.Fatal(e)
	}
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: msg.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 45}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("backend.example.")}}, {Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("backend.example."), Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{10, 1, 2, 3}}}}
	answer := packDNSFixture(t, msg)
	_ = b.WriteMessage(websocket.BinaryMessage, answer)
	_ = a.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, got, e = a.ReadMessage()
	if e != nil || !bytes.Equal(got, answer) {
		t.Fatalf("agent DNS response changed %v", e)
	}
	result := readControl(t, ac, "FORWARD_RESULT")
	if result.ErrorCode != "CLOSED" {
		t.Fatalf("DNS result %s", result.ErrorCode)
	}
	var empty struct {
		Status string `json:"status"`
		Answer []byte `json:"answer"`
	}
	c.request("POST", "/v1/dns", "agent", dnsRequest{RequestID: "aaaa", Query: dnsQueryFixture(t, dnsmessage.TypeAAAA)}, 200, &empty)
	if empty.Status != "ANSWER" || len(empty.Answer) == 0 {
		t.Fatal("AAAA answer missing")
	}
}

func TestTCPHalfCloseKeepsAgentWriteDirectionOpen(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	c := newTestClient(t, s)
	c.create(RuleConfig{})
	sc := c.control("server")
	c.pairAgent(c.track.PairingCode, "", 201)
	ac := c.control("agent")
	_, a, b := c.openForward(sc, ac, "tcp", Target{Host: "10.1.2.3", Port: 1234}, []byte{0}, "")
	_ = a.WriteMessage(websocket.BinaryMessage, []byte{0})
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := &wsReader{conn: b}
	head := make([]byte, 1)
	if _, e := io.ReadFull(reader, head); e != nil {
		t.Fatal(e)
	}
	_ = b.WriteMessage(websocket.BinaryMessage, []byte("banner"))
	_ = b.WriteJSON(map[string]string{"type": "FIN"})
	_ = a.SetReadDeadline(time.Now().Add(2 * time.Second))
	ar := &wsReader{conn: a}
	reply := make([]byte, 6)
	if _, e := io.ReadFull(ar, reply); e != nil || string(reply) != "banner" {
		t.Fatalf("banner %v", e)
	}
	if _, e := ar.Read(make([]byte, 1)); e != io.EOF {
		t.Fatalf("server half-close: %v", e)
	}
	if e := a.WriteMessage(websocket.BinaryMessage, []byte{1, 2, 3}); e != nil {
		t.Fatal(e)
	}
	_ = a.WriteJSON(map[string]string{"type": "FIN"})
	p := make([]byte, 3)
	if _, e := io.ReadFull(reader, p); e != nil || !bytes.Equal(p, []byte{1, 2, 3}) {
		t.Fatalf("server FIN closed reverse direction: %v", e)
	}
}

func TestBadTargetResultOnlyClosesItsForward(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	c := newTestClient(t, s)
	c.create(RuleConfig{})
	sc := c.control("server")
	c.pairAgent(c.track.PairingCode, "", 201)
	ac := c.control("agent")
	var f ForwardView
	c.request("POST", "/v1/forwards", "agent", forwardRequest{RequestID: "bad-result", Transport: "tcp", Target: Target{Host: "10.1.2.3", Port: 1234}}, 202, &f)
	offer := readControl(t, ac, "CONFIRM_REQUIRED")
	c.request("POST", "/v1/forwards/"+f.ForwardID+"/confirm", "agent", confirmRequest{ActualIP: offer.ActualIP}, 200, &f)
	readControl(t, sc, "CONNECT")
	_ = sc.WriteJSON(controlMessage{Type: "TARGET_READY", ForwardID: f.ForwardID, ServiceSession: c.track.ServiceSession, ConfigVersion: c.track.ConfigVersion, ActualIP: "10.9.9.9"})
	if result := readControl(t, ac, "FORWARD_RESULT"); result.ErrorCode != "PROTOCOL_ERROR" {
		t.Fatalf("bad target result: %s", result.ErrorCode)
	}
	_, a, b := c.openForward(sc, ac, "tcp", Target{Host: "10.1.2.3", Port: 1234}, []byte{0}, "")
	_ = a.WriteMessage(websocket.BinaryMessage, []byte{0, 7})
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 2)
	if _, e := io.ReadFull(&wsReader{conn: b}, got); e != nil || !bytes.Equal(got, []byte{0, 7}) {
		t.Fatalf("target result took track offline: %v", e)
	}
}

func TestDataTicketBindingsAndLocalConnectBoundary(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	c := newTestClient(t, s)
	c.create(RuleConfig{})
	sc := c.control("server")
	c.pairAgent(c.track.PairingCode, "", 201)
	ac := c.control("agent")
	c.request("PUT", "/v1/tracks/"+c.track.TrackID+"/rules", "agent", configRequest{}, 401, nil)
	c.request("POST", "/v1/forwards", "agent", forwardRequest{RequestID: "literal-connect", Transport: "tcp", Target: Target{Host: "10.1.2.3", Port: 443}, FirstPacket: []byte("CONNECT 10.1.2.3:443 HTTP/1.1\r\nHost: 10.1.2.3:443\r\n\r\n")}, 400, nil)
	var f ForwardView
	c.request("POST", "/v1/forwards", "agent", forwardRequest{RequestID: "bound-ticket", Transport: "tcp", Target: Target{Host: "10.1.2.3", Port: 1234}, FirstPacket: []byte{0}}, 202, &f)
	offer := readControl(t, ac, "CONFIRM_REQUIRED")
	c.request("POST", "/v1/forwards/"+f.ForwardID+"/confirm", "agent", confirmRequest{ActualIP: offer.ActualIP}, 200, &f)
	connect := readControl(t, sc, "CONNECT")
	c.data("server", f, f.AgentTicket, 403)
	c.track.ConfigVersion++
	c.data("agent", f, f.AgentTicket, 403)
	c.track.ConfigVersion--
	a := c.data("agent", f, f.AgentTicket, 101)
	b := c.data("server", f, connect.Ticket, 101)
	_ = sc.WriteJSON(controlMessage{Type: "TARGET_READY", ForwardID: f.ForwardID, ServiceSession: c.track.ServiceSession, ConfigVersion: c.track.ConfigVersion, ActualIP: f.ActualIP})
	readControl(t, ac, "READY")
	_ = a.WriteMessage(websocket.BinaryMessage, []byte{0, 8})
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 2)
	if _, e := io.ReadFull(&wsReader{conn: b}, got); e != nil || !bytes.Equal(got, []byte{0, 8}) {
		t.Fatalf("invalid binding consumed valid ticket: %v", e)
	}
}

package relay

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGuardHTTPRejectsLaterRequestBeforeForwardingItsBytes(t *testing.T) {
	rules, err := compileRules(RuleConfig{URLRegex: []string{`^http://example.com/ok$`}})
	if err != nil {
		t.Fatal(err)
	}
	first := "POST /ok HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc"
	second := "POST /denied HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\n\r\nsecret"
	var dst bytes.Buffer
	err = guardTCP(&dst, strings.NewReader(first+second), Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "tcp", Host: "example.com", Port: 80}, nil)
	var rejected *ruleRejection
	if !errors.As(err, &rejected) {
		t.Fatalf("expected rule rejection, got %v", err)
	}
	if dst.String() != first {
		t.Fatalf("forwarded rejected request: %q", dst.String())
	}
}

type announcingWriter struct {
	bytes.Buffer
	once  sync.Once
	wrote chan struct{}
}

func (w *announcingWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	w.once.Do(func() { close(w.wrote) })
	return n, err
}

func TestResponsesTrackHEADAndALaterWebSocketUpgrade(t *testing.T) {
	rules, _ := compileRules(RuleConfig{})
	head := "HEAD /head HTTP/1.1\r\nHost: example.com\r\n\r\n"
	upgrade := "GET /ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
	replies := "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x00"
	session := newStreamSession()
	defer session.close()
	serverRead, serverWrite := io.Pipe()
	defer serverRead.Close()
	defer serverWrite.Close()
	requests := &announcingWriter{wrote: make(chan struct{})}
	var responses bytes.Buffer
	guardResult := make(chan error, 1)
	responseResult := make(chan error, 1)
	go func() {
		guardResult <- guardTCP(requests, strings.NewReader(head+upgrade+"\x81\x00"), Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "http1", Host: "example.com", Port: 80}, session)
	}()
	go func() { responseResult <- relayResponses(&responses, serverRead, Inspection{Kind: "http1"}, session) }()
	<-requests.wrote
	go func() { io.WriteString(serverWrite, replies); serverWrite.Close() }()
	if err := <-responseResult; err != nil {
		session.close()
		t.Fatal(err)
	}
	if err := <-guardResult; err != nil {
		t.Fatal(err)
	}
	if requests.String() != head+upgrade+"\x81\x00" || responses.String() != replies {
		t.Fatalf("requests=%q responses=%q", requests.String(), responses.String())
	}
}

func TestGuardRejectsInvalidChunkExtensionsAndTrailers(t *testing.T) {
	rules, _ := compileRules(RuleConfig{})
	head := "POST /body HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
	for _, body := range []string{"3;\r\nabc\r\n0\r\n\r\n", "0\r\nHost: bad.example\r\n\r\n"} {
		var dst bytes.Buffer
		err := guardTCP(&dst, strings.NewReader(head+body), Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "http1", Host: "example.com", Port: 80}, nil)
		var malformed *protocolError
		if !errors.As(err, &malformed) || dst.String() != head {
			t.Fatalf("err=%v bytes=%q", err, dst.String())
		}
	}
}

func TestGuardOrdinaryASCIIProtocolRemainsTCP(t *testing.T) {
	rules, _ := compileRules(RuleConfig{URLRegex: []string{`^http://example.com/allowed$`}})
	var dst bytes.Buffer
	raw := "EHLO example.com\r\nMAIL FROM:<sender@example.com>\r\n"
	if err := guardTCP(&dst, strings.NewReader(raw), Target{"example.com", 25}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "tcp", Host: "example.com", Port: 25}, nil); err != nil || dst.String() != raw {
		t.Fatalf("err=%v raw=%q", err, dst.String())
	}
}

func TestResponsesFinishAfterTheLastRequest(t *testing.T) {
	rules, _ := compileRules(RuleConfig{})
	session := newStreamSession()
	defer session.close()
	request := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	reply := "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"
	var requests, responses bytes.Buffer
	if err := guardTCP(&requests, strings.NewReader(request), Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "http1", Host: "example.com", Port: 80}, session); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- relayResponses(&responses, strings.NewReader(reply), Inspection{Kind: "http1"}, session)
	}()
	select {
	case err := <-result:
		if err != nil || responses.String() != reply {
			t.Fatalf("err=%v response=%q", err, responses.String())
		}
	case <-time.After(time.Second):
		session.close()
		<-result
		t.Fatal("response guard did not finish after final response")
	}
}

func TestGuardTLSChecksActualFragmentedClientHello(t *testing.T) {
	rules, _ := compileRules(RuleConfig{Domains: []string{"example.com"}})
	wire := clientHelloRecords("api.example.com", true)
	var dst bytes.Buffer
	if err := guardTCP(&dst, bytes.NewReader(append(wire, []byte("opaque TLS bytes")...)), Target{"api.example.com", 443}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "tls", Host: "api.example.com", Port: 443}, nil); err != nil || !bytes.Equal(dst.Bytes(), append(wire, []byte("opaque TLS bytes")...)) {
		t.Fatalf("err=%v bytes=%x", err, dst.Bytes())
	}
	dst.Reset()
	if err := guardTCP(&dst, bytes.NewReader(wire), Target{"other.example", 443}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "tls", Host: "other.example", Port: 443}, nil); err == nil || dst.Len() != 0 {
		t.Fatalf("mismatched SNI forwarded: err=%v bytes=%x", err, dst.Bytes())
	}
}

type deadlineRecordingReader struct {
	io.Reader
	deadlines []time.Time
}

func (r *deadlineRecordingReader) SetReadDeadline(value time.Time) error {
	r.deadlines = append(r.deadlines, value)
	return nil
}

func TestGuardHeaderDeadlineIsClearedBeforeOpaqueTLSData(t *testing.T) {
	rules, _ := compileRules(RuleConfig{})
	src := &deadlineRecordingReader{Reader: bytes.NewReader(clientHelloRecords("example.com", true))}
	var dst bytes.Buffer
	if err := guardTCP(&dst, src, Target{"example.com", 443}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "tls", Host: "example.com", Port: 443}, nil); err != nil {
		t.Fatal(err)
	}
	if len(src.deadlines) != 2 || src.deadlines[0].IsZero() || !src.deadlines[1].IsZero() {
		t.Fatalf("deadlines=%v", src.deadlines)
	}
}

func TestGuardHTTPKeepsChunkedBodyBoundaries(t *testing.T) {
	rules, err := compileRules(RuleConfig{URLRegex: []string{`^http://example.com/ok$`}})
	if err != nil {
		t.Fatal(err)
	}
	first := "POST /ok HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTrailer: X-Check\r\n\r\n3;ext=yes\r\nabc\r\n0\r\nX-Check: yes\r\n\r\n"
	second := "GET /denied HTTP/1.1\r\nHost: example.com\r\n\r\n"
	var dst bytes.Buffer
	err = guardTCP(&dst, strings.NewReader(first+second), Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "http1", Host: "example.com", Port: 80}, nil)
	var rejected *ruleRejection
	if !errors.As(err, &rejected) || dst.String() != first {
		t.Fatalf("err=%v forwarded=%q", err, dst.String())
	}
}

func TestGuardRejectsProtocolAmbiguityBeforeAnyBytes(t *testing.T) {
	rules, err := compileRules(RuleConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"POST /ok HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
		"GET /ok HTTP/1.1\r\nHost: unrelated.example\r\n\r\n",
		"GET /ok HTTP/1.1\r\nHost: example.com\r\nX-Large: " + strings.Repeat("x", maxHeaderBytes) + "\r\n\r\n",
		"GET /ok HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
	} {
		var dst bytes.Buffer
		err := guardTCP(&dst, strings.NewReader(raw), Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "tcp", Host: "example.com", Port: 80}, nil)
		var malformed *protocolError
		if !errors.As(err, &malformed) || dst.Len() != 0 {
			t.Fatalf("err=%v forwarded=%d", err, dst.Len())
		}
	}
}

func TestGuardUninspectedHTTPIsNotRawTCP(t *testing.T) {
	rules, err := compileRules(RuleConfig{URLRegex: []string{`^http://example.com/ok$`}})
	if err != nil {
		t.Fatal(err)
	}
	var dst bytes.Buffer
	err = guardTCP(&dst, strings.NewReader("GET /denied HTTP/1.1\r\nHost: example.com\r\n\r\n"), Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "tcp", Host: "example.com", Port: 80}, nil)
	var rejected *ruleRejection
	if !errors.As(err, &rejected) || dst.Len() != 0 {
		t.Fatalf("err=%v forwarded=%q", err, dst.String())
	}
}

func TestGuardLeadingWhitespaceCannotHideDeniedHTTP(t *testing.T) {
	rules, _ := compileRules(RuleConfig{URLRegex: []string{`^http://example.com/allowed$`}})
	for _, prefix := range []string{"\r\n", "\n", " ", "\t"} {
		var dst bytes.Buffer
		err := guardTCP(&dst, strings.NewReader(prefix+"GET /denied HTTP/1.1\r\nHost: example.com\r\n\r\n"), Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "tcp", Host: "example.com", Port: 80}, nil)
		if err == nil || dst.Len() != 0 {
			t.Fatalf("prefix=%q err=%v forwarded=%q", prefix, err, dst.String())
		}
	}
}

func TestGuardHTTP1RejectsLiteralCONNECTBeforeItsHeaders(t *testing.T) {
	rules, _ := compileRules(RuleConfig{})
	connect := "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n"
	for _, allowed := range []string{"", "GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\n"} {
		var dst bytes.Buffer
		err := guardTCP(&dst, strings.NewReader(allowed+connect+"secret"), Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "tcp", Host: "example.com", Port: 80}, nil)
		var malformed *protocolError
		if !errors.As(err, &malformed) || dst.String() != allowed {
			t.Fatalf("err=%v bytes=%q", err, dst.String())
		}
	}
}

func TestGuardWebSocketRequiresSuccessfulUpgrade(t *testing.T) {
	rules, err := compileRules(RuleConfig{})
	if err != nil {
		t.Fatal(err)
	}
	head := "GET /ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
	session := newStreamSession()
	session.upgrades <- "websocket"
	var dst bytes.Buffer
	if err := guardTCP(&dst, strings.NewReader(head+"\x81\x00"), Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "http1", Host: "example.com", Port: 80}, session); err != nil || dst.String() != head+"\x81\x00" {
		t.Fatalf("err=%v bytes=%q", err, dst.String())
	}
	session = newStreamSession()
	session.upgrades <- ""
	dst.Reset()
	if err := guardTCP(&dst, strings.NewReader(head+"\x81\x00"), Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "http1", Host: "example.com", Port: 80}, session); err == nil || dst.String() != head {
		t.Fatalf("failed upgrade forwarded opaque data: err=%v bytes=%q", err, dst.String())
	}
}

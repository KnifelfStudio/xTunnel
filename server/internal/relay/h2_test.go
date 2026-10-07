package relay

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestGuardH2RejectsLiteralCONNECTBeforeItsHeaders(t *testing.T) {
	for _, later := range []bool{false, true} {
		rules, _ := compileRules(RuleConfig{})
		var src, block bytes.Buffer
		src.WriteString(http2.ClientPreface)
		f := http2.NewFramer(&src, nil)
		f.WriteSettings()
		e := hpack.NewEncoder(&block)
		id := uint32(1)
		if later {
			for _, field := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/ok"}} {
				e.WriteField(field)
			}
			f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true})
			id = 3
		}
		allowed := append([]byte(nil), src.Bytes()...)
		block.Reset()
		e.WriteField(hpack.HeaderField{Name: ":method", Value: "CONNECT"})
		e.WriteField(hpack.HeaderField{Name: ":authority", Value: "example.com:80"})
		f.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block.Bytes(), EndHeaders: true})
		f.WriteData(id, true, []byte("secret"))
		var dst bytes.Buffer
		err := guardTCP(&dst, &src, Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "tcp", Host: "example.com", Port: 80}, nil)
		var malformed *protocolError
		if !errors.As(err, &malformed) || !bytes.Equal(dst.Bytes(), allowed) {
			t.Fatalf("later=%v err=%v bytes=%x", later, err, dst.Bytes())
		}
	}
}

func TestGuardH2TrailersCannotInjectHeaders(t *testing.T) {
	rules, _ := compileRules(RuleConfig{})
	var src, block bytes.Buffer
	src.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&src, nil)
	fr.WriteSettings()
	e := hpack.NewEncoder(&block)
	for _, f := range []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/body"}} {
		e.WriteField(f)
	}
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true})
	fr.WriteData(1, false, []byte("body"))
	allowed := append([]byte(nil), src.Bytes()...)
	block.Reset()
	e.WriteField(hpack.HeaderField{Name: "x-trailer", Value: "value\r\ninjected: yes"})
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true})
	var dst bytes.Buffer
	err := guardTCP(&dst, &src, Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "h2", Host: "example.com", Port: 80}, nil)
	var malformed *protocolError
	if !errors.As(err, &malformed) || !bytes.Equal(dst.Bytes(), allowed) {
		t.Fatalf("err=%v bytes=%x", err, dst.Bytes())
	}
}

func TestH2CUpgradeKeepsPerRequestRules(t *testing.T) {
	rules, _ := compileRules(RuleConfig{URLRegex: []string{`^http://example.com/upgrade$`}})
	head := "GET /upgrade HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n"
	var request, block bytes.Buffer
	request.WriteString(head)
	request.WriteString(http2.ClientPreface)
	f := http2.NewFramer(&request, nil)
	f.WriteSettings()
	allowed := append([]byte(nil), request.Bytes()...)
	e := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/denied"}} {
		e.WriteField(field)
	}
	f.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true})
	var reply bytes.Buffer
	reply.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n")
	http2.NewFramer(&reply, nil).WriteSettings()
	session := newStreamSession()
	defer session.close()
	serverRead, serverWrite := io.Pipe()
	defer serverRead.Close()
	defer serverWrite.Close()
	requests := &announcingWriter{wrote: make(chan struct{})}
	var responses bytes.Buffer
	guardResult, responseResult := make(chan error, 1), make(chan error, 1)
	go func() {
		guardResult <- guardTCP(requests, &request, Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "http1", Host: "example.com", Port: 80}, session)
	}()
	go func() { responseResult <- relayResponses(&responses, serverRead, Inspection{Kind: "http1"}, session) }()
	<-requests.wrote
	go func() { serverWrite.Write(reply.Bytes()); serverWrite.Close() }()
	if err := <-responseResult; err != nil {
		session.close()
		t.Fatal(err)
	}
	err := <-guardResult
	var rejected *ruleRejection
	if !errors.As(err, &rejected) || !bytes.Equal(requests.Bytes(), allowed) || !bytes.Equal(responses.Bytes(), reply.Bytes()) {
		t.Fatalf("err=%v requests=%x", err, requests.Bytes())
	}
}

func TestKnownH2ServerSettingsCannotSelectOpaqueResponses(t *testing.T) {
	var wire, block bytes.Buffer
	f := http2.NewFramer(&wire, nil)
	f.WriteSettings()
	allowed := append([]byte(nil), wire.Bytes()...)
	e := hpack.NewEncoder(&block)
	e.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	e.WriteField(hpack.HeaderField{Name: "X-Bad", Value: "header"})
	f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true})
	session := newStreamSession()
	defer session.close()
	var dst bytes.Buffer
	err := relayResponses(&dst, &wire, Inspection{Kind: "h2"}, session)
	var malformed *protocolError
	if !errors.As(err, &malformed) || !bytes.Equal(dst.Bytes(), allowed) {
		t.Fatalf("err=%v response=%x", err, dst.Bytes())
	}
}

func TestGuardH2CanCancelARequestAfterItsBodyEnds(t *testing.T) {
	rules, _ := compileRules(RuleConfig{})
	var src, block bytes.Buffer
	src.WriteString(http2.ClientPreface)
	f := http2.NewFramer(&src, nil)
	f.WriteSettings()
	e := hpack.NewEncoder(&block)
	for _, id := range []uint32{1, 3} {
		block.Reset()
		for _, field := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/ok"}} {
			e.WriteField(field)
		}
		f.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true})
		if id == 1 {
			f.WriteRSTStream(id, http2.ErrCodeCancel)
		}
	}
	expected := append([]byte(nil), src.Bytes()...)
	var dst bytes.Buffer
	if err := guardTCP(&dst, &src, Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "h2", Host: "example.com", Port: 80}, nil); err != nil || !bytes.Equal(dst.Bytes(), expected) {
		t.Fatalf("err=%v bytes=%x", err, dst.Bytes())
	}
}

func TestGuardH2ChecksEachStreamBeforeForwardingHeaders(t *testing.T) {
	rules, err := compileRules(RuleConfig{URLRegex: []string{`^http://example.com/ok$`}})
	if err != nil {
		t.Fatal(err)
	}
	var src bytes.Buffer
	src.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&src, nil)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	write := func(id uint32, path string) {
		block.Reset()
		for _, f := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: path}} {
			if err := enc.WriteField(f); err != nil {
				t.Fatal(err)
			}
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
			t.Fatal(err)
		}
	}
	write(1, "/ok")
	allowed := append([]byte(nil), src.Bytes()...)
	write(3, "/denied")
	var dst bytes.Buffer
	err = guardTCP(&dst, &src, Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "h2", Host: "example.com", Port: 80}, nil)
	var rejected *ruleRejection
	if !errors.As(err, &rejected) || !bytes.Equal(dst.Bytes(), allowed) {
		t.Fatalf("err=%v forwarded=%x allowed=%x", err, dst.Bytes(), allowed)
	}
}

func TestGuardH2RejectsUnapprovedDataAndSplitOversizedHeaders(t *testing.T) {
	rules, err := compileRules(RuleConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"data_without_headers", "oversized_headers"} {
		t.Run(mode, func(t *testing.T) {
			var src bytes.Buffer
			src.WriteString(http2.ClientPreface)
			fr := http2.NewFramer(&src, nil)
			fr.WriteSettings()
			allowed := append([]byte(nil), src.Bytes()...)
			if mode == "data_without_headers" {
				fr.WriteData(1, true, []byte("secret"))
			} else {
				var block bytes.Buffer
				enc := hpack.NewEncoder(&block)
				for _, f := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/ok"}, {Name: "x-large", Value: strings.Repeat("x", maxHeaderBytes)}} {
					enc.WriteField(f)
				}
				b := block.Bytes()
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: b[:len(b)/2], EndHeaders: false})
				fr.WriteContinuation(1, true, b[len(b)/2:])
			}
			var dst bytes.Buffer
			err := guardTCP(&dst, &src, Target{"example.com", 80}, netip.MustParseAddr("10.1.2.3"), rules, Inspection{Kind: "h2", Host: "example.com", Port: 80}, nil)
			var malformed *protocolError
			if !errors.As(err, &malformed) || !bytes.Equal(dst.Bytes(), allowed) {
				t.Fatalf("err=%v forwarded=%x", err, dst.Bytes())
			}
		})
	}
}

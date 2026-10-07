package relay

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestHTTPInspectionUsesActualHeader(t *testing.T) {
	for _, tt := range []struct {
		name                  string
		target                Target
		wire, kind, host, url string
	}{
		{"encoded full URL", Target{"10.0.0.1", 8080}, "GET /a%2Fb?b=2&a=1 HTTP/1.1\r\nHost: API.Example.Com.:8080\r\n\r\n", "http1", "api.example.com", "http://api.example.com:8080/a%2Fb?b=2&a=1"},
		{"absolute target", Target{"example.com", 80}, "GET http://EXAMPLE.com./?x=%2F HTTP/1.1\r\nHost: example.com\r\n\r\n", "http1", "example.com", "http://example.com/?x=%2F"},
		{"options star", Target{"example.com", 80}, "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n", "http1", "example.com", ""},
		{"connect", Target{"example.com", 443}, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", "connect", "example.com", ""},
		{"upgrade", Target{"example.com", 80}, "GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n", "http1", "example.com", "http://example.com/chat"},
		{"custom HTTP method", Target{"example.com", 80}, "PURGE /cache HTTP/1.1\r\nHost: example.com\r\n\r\n", "http1", "example.com", "http://example.com/cache"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := inspectPrefix(tt.target, []byte(tt.wire))
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind != tt.kind || got.Host != tt.host || got.URL != tt.url || !bytes.Equal(got.Header, []byte(tt.wire)) {
				t.Fatalf("inspection = %+v", got)
			}
		})
	}
}

func TestMalformedRecognizablePrefixCannotBecomeTCP(t *testing.T) {
	for _, wire := range []string{
		"GET / HTTP/1.1\r\nHost: example.com\r\n", "GET / HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: other.com\r\n\r\n", "GET / HTTP/1.1\r\nHost: example.com:81\r\n\r\n",
		"GET http://other.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
		"GET /a#fragment HTTP/1.1\r\nHost: example.com\r\n\r\n", "GET / HTTP/1.1\nHost: example.com\n\n",
		"GET / HTTP/1.1\r\nHost: example.com\r\n bad: value\r\n\r\n", "GET / HTTP/1.1\r\nHost: example.com:bad\r\n\r\n",
		"PRI * HTTP/2.0\r\n\r\nSM\r\n", "GET", "\x16\x03\x01\x00\x10\x01",
		"CUSTOM /unfinished\r\n", "CUSTOM thing HTTP/1.invalid\r\n", "EHLO example.com", "PURGE ",
	} {
		if _, err := inspectPrefix(Target{"example.com", 80}, []byte(wire)); err == nil {
			t.Errorf("accepted malformed prefix %q", wire)
		}
	}
}

func TestAmbiguousLeadingWhitespaceCannotBecomeOpaqueTCP(t *testing.T) {
	request := "GET /denied HTTP/1.1\r\nHost: example.com\r\n\r\n"
	for _, leading := range []string{"\r", "\n", "\r\n", "\r\n\r\n", " ", "\t"} {
		for _, wire := range []string{leading, leading + request} {
			got, err := inspectPrefix(Target{"example.com", 80}, []byte(wire))
			if _, ok := err.(*protocolError); !ok {
				t.Errorf("ambiguous protocol start %q = kind %q, error %v; want protocol error", leading, got.Kind, err)
			}
		}
	}
}

func TestH2CUpgradeSettingsAreValidatedBeforeForwarding(t *testing.T) {
	base := "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c\r\n"
	for _, extra := range []string{
		"Connection: upgrade\r\nHTTP2-Settings: \r\n",
		"Connection: upgrade, http2-settings\r\n",
		"Connection: upgrade, http2-settings\r\nHTTP2-Settings: !invalid!\r\n",
		"Connection: upgrade, http2-settings\r\nHTTP2-Settings: AA\r\n",
		"Connection: upgrade, http2-settings\r\nHTTP2-Settings: AAIAAAAC\r\n",
	} {
		if _, err := inspectPrefix(Target{"example.com", 80}, []byte(base+extra+"\r\n")); err == nil {
			t.Errorf("accepted invalid h2c settings %q", extra)
		}
	}
	if got, err := inspectPrefix(Target{"example.com", 80}, []byte(base+"Connection: upgrade, http2-settings\r\nHTTP2-Settings: AAIAAAAA\r\n\r\n")); err != nil || got.Upgrade != "h2c" {
		t.Fatalf("valid h2c=%+v,%v", got, err)
	}
}

func TestRawTCPAndServerFirst(t *testing.T) {
	for _, wire := range [][]byte{nil, {0, 1, 2, 3}, []byte("\x00 /payload HTTP/1.1\r\n"), []byte("SSH-2.0-peer\r\n"), []byte("EHLO example.com\r\n")} {
		got, err := inspectPrefix(Target{"10.0.0.1", 22}, wire)
		if err != nil || got.Kind != "tcp" {
			t.Fatalf("raw TCP = %+v, %v", got, err)
		}
	}
}

func clientHelloRecords(host string, fragment bool) []byte {
	n := []byte(host)
	sni := make([]byte, 5+len(n))
	binary.BigEndian.PutUint16(sni, uint16(len(n)+3))
	sni[2] = 0
	binary.BigEndian.PutUint16(sni[3:], uint16(len(n)))
	copy(sni[5:], n)
	ext := make([]byte, 4+len(sni))
	binary.BigEndian.PutUint16(ext[2:], uint16(len(sni)))
	copy(ext[4:], sni)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0, 0x2f, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := func(payload []byte) []byte {
		out := []byte{22, 3, 1, byte(len(payload) >> 8), byte(len(payload))}
		return append(out, payload...)
	}
	if fragment {
		return append(record(handshake[:11]), record(handshake[11:])...)
	}
	return record(handshake)
}

func TestTLSClientHelloSNIAndFragments(t *testing.T) {
	for _, fragment := range []bool{false, true} {
		wire := clientHelloRecords("API.Example.com", fragment)
		got, err := inspectPrefix(Target{"10.0.0.1", 443}, wire)
		if err != nil || got.Kind != "tls" || got.Host != "api.example.com" || !bytes.Equal(got.Header, wire) {
			t.Fatalf("TLS inspection=%+v, %v", got, err)
		}
		if _, err := inspectPrefix(Target{"other.com", 443}, wire); err == nil {
			t.Fatal("accepted SNI target mismatch")
		}
		if _, err := inspectPrefix(Target{"10.0.0.1", 443}, wire[:len(wire)-1]); err == nil {
			t.Fatal("accepted truncated ClientHello")
		}
	}
}

func TestTLSRejectsInvalidWireSNI(t *testing.T) {
	for _, host := range []string{" example.com", "example.com ", "bücher.example"} {
		if _, err := inspectPrefix(Target{"10.0.0.1", 443}, clientHelloRecords(host, false)); err == nil {
			t.Errorf("accepted invalid wire SNI %q", host)
		}
	}
	// Keep the SNI extension but remove all its server-name entries.
	wire := clientHelloRecords("", false)
	wire = wire[:len(wire)-3]
	binary.BigEndian.PutUint16(wire[3:], uint16(len(wire)-5))
	wire[8] = byte(len(wire) - 9)
	binary.BigEndian.PutUint16(wire[50:], 6)
	binary.BigEndian.PutUint16(wire[54:], 2)
	binary.BigEndian.PutUint16(wire[56:], 0)
	if _, err := inspectPrefix(Target{"10.0.0.1", 443}, wire); err == nil {
		t.Fatal("accepted empty SNI list")
	}
}

func TestPrefixLimitsAndHeaderBodyBoundary(t *testing.T) {
	wire := []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody")
	got, err := inspectPrefix(Target{"example.com", 80}, wire)
	if err != nil || bytes.Contains(got.Header, []byte("body")) {
		t.Fatalf("body became header: %+v, %v", got, err)
	}
	oversized := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nX-Fill: " + strings.Repeat("a", maxHeaderBytes) + "\r\n\r\n")
	if _, err := inspectPrefix(Target{"example.com", 80}, oversized); err == nil {
		t.Fatal("accepted oversized HTTP header")
	}
	if _, err := inspectPrefix(Target{"example.com", 80}, bytes.Repeat([]byte{0}, maxFirstPacket+1)); err == nil {
		t.Fatal("accepted oversized first packet")
	}
}

func FuzzInspectPrefix(f *testing.F) {
	for _, wire := range [][]byte{nil, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), clientHelloRecords("example.com", true), h2Prefix([]hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/"}})} {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire []byte) { _, _ = inspectPrefix(Target{"10.0.0.1", 80}, wire) })
}

func h2Prefix(fields []hpack.HeaderField) []byte {
	var block, frames bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			panic(err)
		}
	}
	frames.WriteString(http2.ClientPreface)
	f := http2.NewFramer(&frames, nil)
	if err := f.WriteSettings(); err != nil {
		panic(err)
	}
	if err := f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
		panic(err)
	}
	return frames.Bytes()
}

func TestH2InspectionChecksPseudoHeaders(t *testing.T) {
	fields := []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "example.com:8080"}, {Name: ":path", Value: "/a%2Fb?b=2&a=1"}}
	wire := h2Prefix(fields)
	got, err := inspectPrefix(Target{"10.0.0.1", 8080}, wire)
	if err != nil || got.Kind != "h2" || got.URL != "http://example.com:8080/a%2Fb?b=2&a=1" || !bytes.Equal(got.Header, wire) {
		t.Fatalf("h2=%+v, %v", got, err)
	}
	for _, bad := range [][]hpack.HeaderField{
		append(append([]hpack.HeaderField{}, fields...), hpack.HeaderField{Name: ":path", Value: "/denied"}),
		append(append([]hpack.HeaderField{}, fields...), hpack.HeaderField{Name: "host", Value: "other.com"}),
		append(append([]hpack.HeaderField{}, fields...), hpack.HeaderField{Name: "host", Value: ""}),
		append(append([]hpack.HeaderField{}, fields...), hpack.HeaderField{Name: "x-name", Value: " value "}),
		{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "example.com:8080"}},
	} {
		if _, err := inspectPrefix(Target{"10.0.0.1", 8080}, h2Prefix(bad)); err == nil {
			t.Fatal("accepted invalid h2 pseudo headers")
		}
	}
}

func TestH2PrefixRejectsSelfDependentPriority(t *testing.T) {
	var block, wire bytes.Buffer
	e := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/"}} {
		if err := e.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	wire.WriteString(http2.ClientPreface)
	f := http2.NewFramer(&wire, nil)
	if err := f.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true, Priority: http2.PriorityParam{StreamDep: 1, Weight: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectPrefix(Target{"example.com", 80}, wire.Bytes()); err == nil {
		t.Fatal("accepted self-dependent HEADERS")
	}
}

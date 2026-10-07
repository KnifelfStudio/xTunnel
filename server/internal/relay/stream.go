package relay

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// A rule rejection applies to the withheld request, never to earlier bytes.
// The channel owner must prohibit local replay once any business bytes were sent.
type ruleRejection struct{}

func (*ruleRejection) Error() string { return "request rejected by track rules" }

func isRuleRejection(err error) bool { var rejected *ruleRejection; return errors.As(err, &rejected) }

type requestMetadata struct{ method, upgrade string }

// A single concrete session connects the two byte-stream guards. The bounded
// request queue applies backpressure to HTTP pipelining instead of retaining it.
type streamSession struct {
	kind          chan string
	requests      chan requestMetadata
	upgrades      chan string
	done          chan struct{}
	once          sync.Once
	requestsEnded sync.Once
	agentDeadline func(time.Time) error
}

func newStreamSession() *streamSession {
	return &streamSession{kind: make(chan string, 1), requests: make(chan requestMetadata, 128), upgrades: make(chan string, 1), done: make(chan struct{})}
}

func (s *streamSession) close() { s.once.Do(func() { close(s.done) }) }

func (s *streamSession) endRequests() { s.requestsEnded.Do(func() { close(s.requests) }) }

func (s *streamSession) sendRequest(meta requestMetadata) error {
	select {
	case s.requests <- meta:
		return nil
	case <-s.done:
		return io.ErrClosedPipe
	}
}

func (s *streamSession) sendUpgrade(value string) error {
	select {
	case s.upgrades <- value:
		return nil
	case <-s.done:
		return io.ErrClosedPipe
	}
}

// guardTCP validates bytes from the actual channel independently of precheck.
// The WSS reader owns read deadlines and cancellation; all buffering is bounded.
func guardTCP(dst io.Writer, src io.Reader, target Target, selectedIP netip.Addr, rules *compiledRules, initial Inspection, session *streamSession) error {
	if session == nil {
		session = newStreamSession()
		defer session.close()
	}
	defer session.endRequests()
	br := bufio.NewReaderSize(src, maxHeaderBytes)
	if reader, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
		session.agentDeadline = reader.SetReadDeadline
	}
	if err := session.setAgentDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	kind, err := sniffStream(br)
	if err != nil {
		return err
	}
	select {
	case session.kind <- kind:
	case <-session.done:
		return io.ErrClosedPipe
	}
	if kind == "" {
		return nil
	}
	if initial.Kind != "" && initial.Kind != "tcp" && initial.Kind != kind {
		return badProtocol("data protocol differs from precheck")
	}
	switch kind {
	case "http1":
		return guardHTTP1(dst, br, target, selectedIP, rules, session)
	case "h2":
		return guardH2(dst, br, target, selectedIP, rules, false, session)
	case "tls":
		hello, err := readClientHello(br)
		if err != nil {
			return err
		}
		actual, err := inspectTLS(target, hello)
		if err != nil {
			return err
		}
		if err := sameEndpoint(target, actual); err != nil {
			return err
		}
		if !rules.allows(selectedIP, actual.Host, "", false) {
			return &ruleRejection{}
		}
		if err := session.setAgentDeadline(time.Time{}); err != nil {
			return err
		}
		if err := writeBytes(dst, hello); err != nil {
			return err
		}
	default:
		if !rules.allows(selectedIP, target.Host, "", false) {
			return &ruleRejection{}
		}
		if err := session.setAgentDeadline(time.Time{}); err != nil {
			return err
		}
	}
	_, err = io.CopyBuffer(dst, br, make([]byte, 32<<10))
	return err
}

func sniffStream(br *bufio.Reader) (string, error) {
	first, err := br.Peek(1)
	if err == io.EOF {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if err := validateProtocolStart(first); err != nil {
		return "", err
	}
	if first[0] == 22 {
		return "tls", nil
	}
	if !tokenByte(first[0]) {
		return "tcp", nil
	}
	for {
		prefix, _ := br.Peek(br.Buffered())
		if end := bytes.IndexByte(prefix, '\n'); end >= 0 {
			line := prefix[:end+1]
			if bytes.HasPrefix(line, []byte("PRI * HTTP/2.")) {
				magic, err := br.Peek(len(http2.ClientPreface))
				if err != nil || string(magic) != http2.ClientPreface {
					return "", badProtocol("invalid HTTP/2 preface")
				}
				return "h2", nil
			}
			if looksHTTP(line) {
				return "http1", nil
			}
			return "tcp", nil
		}
		for _, c := range prefix {
			if c != ' ' && c != '\r' && c != '\t' && !tokenByte(c) {
				if looksHTTP(prefix) {
					return "http1", nil
				}
				return "tcp", nil
			}
		}
		if br.Buffered() >= maxHeaderBytes {
			return "", badProtocol("first line exceeds limit")
		}
		_, err = br.Peek(br.Buffered() + 1)
		if err != nil {
			prefix, _ = br.Peek(br.Buffered())
			if err == io.EOF {
				if looksHTTP(prefix) || bytes.HasPrefix([]byte(http2.ClientPreface), prefix) {
					return "", badProtocol("incomplete request prefix")
				}
				return "tcp", nil
			}
			return "", err
		}
	}
}

func sameEndpoint(target Target, actual Inspection) error {
	if actual.Host != target.Host || actual.Port != target.Port {
		return badProtocol("request endpoint differs from channel authorization")
	}
	return nil
}

func readHeader(br *bufio.Reader) ([]byte, error) {
	var header []byte
	for {
		line, err := readBoundedLine(br, maxHeaderBytes-len(header))
		if err != nil {
			if err == io.EOF && len(header) == 0 && len(line) == 0 {
				return nil, io.EOF
			}
			return nil, badProtocol("incomplete or oversized HTTP header")
		}
		header = append(header, line...)
		if bytes.Equal(line, []byte("\r\n")) {
			return header, nil
		}
	}
}

func readBoundedLine(br *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		piece, err := br.ReadSlice('\n')
		if len(line)+len(piece) > limit {
			return nil, badProtocol("line exceeds limit")
		}
		line = append(line, piece...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return line, err
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return nil, badProtocol("HTTP requires CRLF")
		}
		return line, nil
	}
}

func guardHTTP1(dst io.Writer, br *bufio.Reader, target Target, ip netip.Addr, rules *compiledRules, session *streamSession) error {
	first := true
	for {
		if !first {
			if err := session.setAgentDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return err
			}
		}
		first = false
		header, err := readHeader(br)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		actual, err := inspectHTTPHeader(target, header)
		if err != nil {
			return err
		}
		if err := sameEndpoint(target, actual); err != nil {
			return err
		}
		if err := session.setAgentDeadline(time.Time{}); err != nil {
			return err
		}
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
		if err != nil {
			return badProtocol("invalid HTTP request")
		}
		if req.Method == "CONNECT" {
			return badProtocol("CONNECT must be terminated by the agent")
		}
		if !rules.allows(ip, actual.Host, actual.URL, true) {
			return &ruleRejection{}
		}
		want := actual.Upgrade
		if err := session.sendRequest(requestMetadata{req.Method, want}); err != nil {
			return err
		}
		if err := writeBytes(dst, header); err != nil {
			return err
		}
		if len(req.TransferEncoding) != 0 {
			if err := copyChunked(dst, br); err != nil {
				return err
			}
		} else if req.ContentLength > 0 {
			if err := copyBodyBytes(dst, br, req.ContentLength); err != nil {
				return err
			}
		}
		if want == "" {
			continue
		}
		timer := time.NewTimer(10 * time.Second)
		var got string
		var ok bool
		select {
		case got, ok = <-session.upgrades:
		case <-session.done:
			timer.Stop()
			return io.ErrClosedPipe
		case <-timer.C:
			timer.Stop()
			return badProtocol("upgrade response timed out")
		}
		timer.Stop()
		if !ok {
			return badProtocol("upgrade response unavailable")
		}
		if got == "" {
			continue
		}
		if got != want {
			return badProtocol("upgrade response differs from request")
		}
		if got == "h2c" {
			return guardH2(dst, br, target, ip, rules, true, session)
		}
		if got != "websocket" {
			return badProtocol("unsupported protocol upgrade")
		}
		_, err = io.CopyBuffer(dst, br, make([]byte, 32<<10))
		return err
	}
}

func copyChunked(dst io.Writer, br *bufio.Reader) error {
	for {
		line, err := readBoundedLine(br, maxHeaderBytes)
		if err != nil {
			return badProtocol("invalid HTTP chunk header")
		}
		text := string(line[:len(line)-2])
		number, extensions, hasExtensions := strings.Cut(text, ";")
		if number == "" || len(number) > 16 {
			return badProtocol("invalid HTTP chunk size")
		}
		for _, c := range number {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return badProtocol("invalid HTTP chunk size")
			}
		}
		n, err := strconv.ParseUint(number, 16, 63)
		if err != nil || hasExtensions && !validChunkExtensions(extensions) {
			return badProtocol("invalid HTTP chunk size or extension")
		}
		if n == 0 {
			trailer, err := readHeader(br)
			if err != nil {
				return badProtocol("invalid HTTP trailers")
			}
			if err := validateTrailers(trailer); err != nil {
				return err
			}
			if err := writeBytes(dst, line); err != nil {
				return err
			}
			return writeBytes(dst, trailer)
		}
		if err := writeBytes(dst, line); err != nil {
			return err
		}
		if err := copyBodyBytes(dst, br, int64(n)); err != nil {
			return err
		}
		var end [2]byte
		if _, err := io.ReadFull(br, end[:]); err != nil || end != [2]byte{'\r', '\n'} {
			return badProtocol("invalid HTTP chunk boundary")
		}
		if err := writeBytes(dst, end[:]); err != nil {
			return err
		}
	}
}

func validChunkExtensions(s string) bool {
	for s != "" {
		s = strings.TrimLeft(s, " \t")
		n := 0
		for n < len(s) && tokenByte(s[n]) {
			n++
		}
		if n == 0 {
			return false
		}
		s = strings.TrimLeft(s[n:], " \t")
		if strings.HasPrefix(s, "=") {
			s = strings.TrimLeft(s[1:], " \t")
			if strings.HasPrefix(s, "\"") {
				n = 1
				for n < len(s) && s[n] != '"' {
					if s[n] == '\\' {
						n++
					}
					if n >= len(s) || s[n] < 32 && s[n] != '\t' || s[n] == 127 {
						return false
					}
					n++
				}
				if n >= len(s) {
					return false
				}
				s = s[n+1:]
			} else {
				n = 0
				for n < len(s) && tokenByte(s[n]) {
					n++
				}
				if n == 0 {
					return false
				}
				s = s[n:]
			}
		}
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return true
		}
		if s[0] != ';' {
			return false
		}
		s = s[1:]
		if s == "" {
			return false
		}
	}
	return false
}

func validateTrailers(trailer []byte) error {
	for _, line := range strings.Split(string(trailer), "\r\n") {
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			return badProtocol("invalid HTTP trailer")
		}
		for i := range name {
			if !tokenByte(name[i]) {
				return badProtocol("invalid HTTP trailer name")
			}
		}
		for i := range value {
			if value[i] < 32 && value[i] != '\t' || value[i] == 127 {
				return badProtocol("invalid HTTP trailer value")
			}
		}
		switch strings.ToLower(name) {
		case "content-length", "transfer-encoding", "host", "connection", "upgrade", "trailer":
			return badProtocol("forbidden HTTP trailer")
		}
	}
	return nil
}

func readClientHello(br *bufio.Reader) ([]byte, error) {
	var wire, handshake []byte
	for {
		var head [5]byte
		if _, err := io.ReadFull(br, head[:]); err != nil {
			return nil, badProtocol("incomplete TLS record")
		}
		n := int(binary.BigEndian.Uint16(head[3:]))
		if head[0] != 22 || head[1] != 3 || n == 0 || n > (16<<10)+2048 || len(wire)+5+n > maxFirstPacket {
			return nil, badProtocol("invalid TLS record")
		}
		wire = append(wire, head[:]...)
		start := len(wire)
		wire = append(wire, make([]byte, n)...)
		if _, err := io.ReadFull(br, wire[start:]); err != nil {
			return nil, badProtocol("incomplete TLS record")
		}
		handshake = append(handshake, wire[start:]...)
		if len(handshake) < 4 {
			continue
		}
		length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if handshake[0] != 1 || length+4 > maxFirstPacket {
			return nil, badProtocol("invalid TLS ClientHello")
		}
		if len(handshake) >= length+4 {
			return wire, nil
		}
	}
}

func writeBytes(dst io.Writer, data []byte) error {
	n, err := dst.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func (s *streamSession) setAgentDeadline(deadline time.Time) error {
	if s.agentDeadline != nil {
		return s.agentDeadline(deadline)
	}
	return nil
}

// relayResponses observes actual target responses before releasing opaque
// upgraded traffic. Request metadata is queued before each forwarded header.
func relayResponses(dst io.Writer, src io.Reader, initial Inspection, session *streamSession) error {
	br := bufio.NewReaderSize(src, maxHeaderBytes)
	deadline := func(t time.Time) error {
		if reader, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
			return reader.SetReadDeadline(t)
		}
		return nil
	}
	kind := ""
	switch initial.Kind {
	case "h2":
		kind = "h2"
	case "http1":
		kind = "http1"
	case "tls":
		kind = "tcp"
	}
	if kind == "" {
		peek := make(chan error, 1)
		go func() { _, err := br.Peek(1); peek <- err }()
		select {
		case kind = <-session.kind:
			if err := <-peek; err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
		case err := <-peek:
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			select {
			case kind = <-session.kind:
			default:
				kind = "tcp"
			}
		case <-session.done:
			return io.ErrClosedPipe
		}
	}

	if kind == "h2" {
		return relayH2Responses(dst, br, deadline)
	}
	if kind != "http1" {
		_, err := io.CopyBuffer(dst, br, make([]byte, 32<<10))
		return err
	}
	for {
		var meta requestMetadata
		select {
		case next, ok := <-session.requests:
			if !ok {
				return nil
			}
			meta = next
		case <-session.done:
			return io.ErrClosedPipe
		}
		for {
			if err := deadline(time.Now().Add(10 * time.Second)); err != nil {
				return err
			}
			head, err := readHeader(br)
			if err != nil {
				return badProtocol("incomplete HTTP response header")
			}
			response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(head)), &http.Request{Method: meta.method})
			if err != nil {
				return badProtocol("invalid HTTP response")
			}
			if err := validateHTTPFraming(response.Header); err != nil {
				return err
			}
			if err := deadline(time.Time{}); err != nil {
				return err
			}
			if response.StatusCode == 101 {
				protocol := strings.ToLower(response.Header.Get("Upgrade"))
				if meta.upgrade == "" || protocol != meta.upgrade || !headerHasToken(response.Header.Get("Connection"), "upgrade") || protocol != "websocket" && protocol != "h2c" {
					return badProtocol("invalid upgrade response")
				}
				if err := writeBytes(dst, head); err != nil {
					return err
				}
				if err := session.sendUpgrade(protocol); err != nil {
					return err
				}
				if protocol == "h2c" {
					return relayH2Responses(dst, br, deadline)
				}
				_, err := io.CopyBuffer(dst, br, make([]byte, 32<<10))
				return err
			}
			if err := writeBytes(dst, head); err != nil {
				return err
			}
			if response.StatusCode < 200 {
				continue
			}
			if meta.upgrade != "" {
				if err := session.sendUpgrade(""); err != nil {
					return err
				}
			}
			if meta.method == "HEAD" || response.StatusCode == 204 || response.StatusCode == 304 {
				break
			}
			if len(response.TransferEncoding) != 0 {
				if err := copyChunked(dst, br); err != nil {
					return err
				}
			} else if response.ContentLength > 0 {
				if err := copyBodyBytes(dst, br, response.ContentLength); err != nil {
					return err
				}
			} else if response.ContentLength < 0 {
				_, err := io.CopyBuffer(dst, br, make([]byte, 32<<10))
				return err
			}
			break
		}
	}
}

func copyBodyBytes(dst io.Writer, src io.Reader, length int64) error {
	_, err := io.CopyN(dst, src, length)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return badProtocol("incomplete HTTP body")
	}
	return err
}

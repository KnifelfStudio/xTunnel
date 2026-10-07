package relay

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func inspectPrefix(target Target, prefix []byte) (Inspection, error) {
	target, err := normalizeTarget(target)
	if err != nil {
		return Inspection{}, err
	}
	if len(prefix) > maxFirstPacket {
		return Inspection{}, badProtocol("first packet is too large")
	}
	if err := validateProtocolStart(prefix); err != nil {
		return Inspection{}, err
	}
	if len(prefix) != 0 && (bytes.HasPrefix(prefix, []byte(http2.ClientPreface)) || bytes.HasPrefix([]byte(http2.ClientPreface), prefix) || bytes.HasPrefix(prefix, []byte("PRI * HTTP/2.0"))) {
		return inspectH2Prefix(target, prefix)
	}
	if len(prefix) != 0 && prefix[0] == 22 {
		return inspectTLS(target, prefix)
	}
	if looksHTTP(prefix) {
		return inspectHTTPHeader(target, prefix)
	}
	return Inspection{Kind: "tcp", Host: target.Host, Port: target.Port, Header: bytes.Clone(prefix)}, nil
}

// Tolerant HTTP servers may skip leading whitespace. It must never select
// opaque TCP rules before the actual request is inspected.
func validateProtocolStart(prefix []byte) error {
	if len(prefix) == 0 {
		return nil
	}
	switch prefix[0] {
	case '\r', '\n', ' ', '\t':
		return badProtocol("ambiguous leading protocol whitespace")
	}
	return nil
}

func looksHTTP(prefix []byte) bool {
	if len(prefix) == 0 {
		return false
	}
	line := prefix
	complete := false
	if end := bytes.IndexByte(prefix, '\n'); end >= 0 {
		line = bytes.TrimSuffix(prefix[:end], []byte{'\r'})
		complete = true
	}
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"} {
		if !complete && bytes.HasPrefix([]byte(method), line) {
			return true
		}
		if bytes.HasPrefix(line, []byte(method)) && (len(line) == len(method) || !tokenByte(line[len(method)])) {
			return true
		}
	}
	fields := bytes.Fields(line)
	if len(fields) == 0 || !validToken(string(fields[0])) {
		return false
	}
	if !complete && bytes.IndexAny(line, " \t") >= 0 {
		return true
	}
	for _, field := range fields {
		if strings.HasPrefix(strings.ToUpper(string(field)), "HTTP/") {
			return true
		}
	}
	if len(fields) > 1 {
		target := string(fields[1])
		if strings.HasPrefix(target, "/") || target == "*" || strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
			return true
		}
	}
	return false
}

func tokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))
}

func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if !tokenByte(s[i]) {
			return false
		}
	}
	return true
}

// This parser requires a complete, bounded header; incomplete recognizable
// protocols are errors rather than permission to use opaque TCP rules.
func inspectHTTPHeader(target Target, prefix []byte) (Inspection, error) {
	target, err := normalizeTarget(target)
	if err != nil {
		return Inspection{}, err
	}
	end := bytes.Index(prefix, []byte("\r\n\r\n"))
	if end < 0 {
		return Inspection{}, badProtocol("incomplete HTTP header")
	}
	end += 4
	if end > maxHeaderBytes {
		return Inspection{}, badProtocol("HTTP header is too large")
	}
	header := prefix[:end]
	lines := strings.Split(string(header[:end-4]), "\r\n")
	parts := strings.Split(lines[0], " ")
	if len(parts) != 3 || !validToken(parts[0]) || parts[2] != "HTTP/1.1" && parts[2] != "HTTP/1.0" {
		return Inspection{}, badProtocol("invalid HTTP request line")
	}
	for _, c := range []byte(parts[1]) {
		if c <= ' ' || c >= 127 {
			return Inspection{}, badProtocol("invalid HTTP request target")
		}
	}
	h := make(http.Header)
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !validToken(name) {
			return Inspection{}, badProtocol("invalid HTTP header field")
		}
		for _, c := range []byte(value) {
			if c < 32 && c != '\t' || c == 127 {
				return Inspection{}, badProtocol("invalid HTTP header value")
			}
		}
		h.Add(name, strings.Trim(value, " \t"))
	}
	if len(h.Values("Host")) != 1 {
		return Inspection{}, badProtocol("exactly one HTTP Host is required")
	}
	if err := validateHTTPFraming(h); err != nil {
		return Inspection{}, err
	}
	if _, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header))); err != nil {
		return Inspection{}, badProtocol("invalid HTTP request")
	}
	host, port, err := parseAuthority(h.Get("Host"), 80)
	if err != nil {
		return Inspection{}, err
	}
	inspection := Inspection{Kind: "http1", Host: host, Port: port, Header: bytes.Clone(header)}
	method, requestTarget := parts[0], parts[1]
	if method == "CONNECT" {
		connectHost, connectPort, err := parseAuthority(requestTarget, 0)
		if err != nil || connectHost != host || connectPort != port {
			return Inspection{}, badProtocol("CONNECT authority and Host disagree")
		}
		inspection.Kind = "connect"
	} else if requestTarget == "*" {
		if method != "OPTIONS" {
			return Inspection{}, badProtocol("asterisk target requires OPTIONS")
		}
	} else {
		inspection.URL, err = normalizedHTTPURL("http", host, port, requestTarget)
		if err != nil {
			return Inspection{}, err
		}
	}
	if err := checkActualTarget(target, host, port); err != nil {
		return Inspection{}, err
	}
	if upgrade := h.Get("Upgrade"); upgrade != "" {
		connection := strings.Join(h.Values("Connection"), ",")
		if len(h.Values("Upgrade")) != 1 || !validToken(upgrade) || !headerHasToken(connection, "upgrade") {
			return Inspection{}, badProtocol("invalid HTTP upgrade")
		}
		inspection.Upgrade = strings.ToLower(upgrade)
		if inspection.Upgrade == "h2c" {
			settings := h.Values("Http2-Settings")
			if !headerHasToken(connection, "http2-settings") || len(settings) != 1 {
				return Inspection{}, badProtocol("h2c requires HTTP2-Settings")
			}
			if err := validateH2SettingsHeader(settings[0]); err != nil {
				return Inspection{}, err
			}
		}
	}
	return inspection, nil
}

func validateH2SettingsHeader(value string) error {
	settings, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(settings)%6 != 0 {
		return badProtocol("invalid HTTP2-Settings")
	}
	for len(settings) != 0 {
		setting := http2.Setting{ID: http2.SettingID(binary.BigEndian.Uint16(settings)), Val: binary.BigEndian.Uint32(settings[2:])}
		if err := setting.Valid(); err != nil {
			return badProtocol("invalid HTTP2-Settings")
		}
		settings = settings[6:]
	}
	return nil
}

func validateHTTPFraming(h http.Header) error {
	lengths := h.Values("Content-Length")
	transfer := h.Values("Transfer-Encoding")
	if len(lengths) != 0 && len(transfer) != 0 {
		return badProtocol("Content-Length and Transfer-Encoding conflict")
	}
	var length string
	for _, value := range lengths {
		if value == "" {
			return badProtocol("invalid Content-Length")
		}
		for _, c := range []byte(value) {
			if c < '0' || c > '9' {
				return badProtocol("invalid Content-Length")
			}
		}
		if _, err := strconv.ParseUint(value, 10, 63); err != nil {
			return badProtocol("invalid Content-Length")
		}
		if length != "" && value != length {
			return badProtocol("conflicting Content-Length")
		}
		length = value
	}
	if len(transfer) != 0 && (len(transfer) != 1 || !strings.EqualFold(transfer[0], "chunked")) {
		return badProtocol("unsupported Transfer-Encoding")
	}
	return nil
}

func headerHasToken(value, want string) bool {
	for _, token := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(token), want) {
			return true
		}
	}
	return false
}

func parseAuthority(authority string, defaultPort int) (string, int, error) {
	if authority == "" || strings.ContainsAny(authority, " \t\r\n/@?#[]\\") {
		return "", 0, badProtocol("invalid authority")
	}
	host, port := authority, defaultPort
	if strings.Contains(authority, ":") {
		var value string
		host, value, _ = strings.Cut(authority, ":")
		if value == "" {
			return "", 0, badProtocol("invalid authority port")
		}
		for _, c := range []byte(value) {
			if c < '0' || c > '9' {
				return "", 0, badProtocol("invalid authority port")
			}
		}
		var err error
		port, err = strconv.Atoi(value)
		if err != nil {
			return "", 0, badProtocol("invalid authority port")
		}
	}
	target, err := normalizeTarget(Target{Host: host, Port: port})
	return target.Host, target.Port, err
}

func checkActualTarget(target Target, host string, port int) error {
	if target.Port != port {
		return badProtocol("request port does not match target")
	}
	if _, err := netip.ParseAddr(target.Host); err != nil && target.Host != host {
		return badProtocol("request host does not match target")
	}
	if actual, err := netip.ParseAddr(host); err == nil && target.Host != actual.String() {
		return badProtocol("request IP does not match target")
	}
	return nil
}

func normalizedHTTPURL(scheme, host string, port int, requestTarget string) (string, error) {
	if strings.Contains(requestTarget, "#") {
		return "", badProtocol("HTTP fragments are invalid")
	}
	path := requestTarget
	if !strings.HasPrefix(path, "/") {
		u, err := url.ParseRequestURI(requestTarget)
		if err != nil || u.Scheme != scheme || u.User != nil || u.Opaque != "" || u.Host == "" {
			return "", badProtocol("invalid absolute HTTP target")
		}
		defaultPort := 80
		if scheme == "https" {
			defaultPort = 443
		}
		absoluteHost, absolutePort, err := parseAuthority(u.Host, defaultPort)
		if err != nil || absoluteHost != host || absolutePort != port {
			return "", badProtocol("absolute authority and Host disagree")
		}
		path = u.EscapedPath()
		if path == "" {
			path = "/"
		}
		if u.RawQuery != "" || u.ForceQuery {
			path += "?" + u.RawQuery
		}
	} else if _, err := url.ParseRequestURI(path); err != nil {
		return "", badProtocol("invalid HTTP path")
	}
	authority := host
	if scheme == "http" && port != 80 || scheme == "https" && port != 443 {
		authority += ":" + strconv.Itoa(port)
	}
	return scheme + "://" + authority + path, nil
}

func inspectTLS(target Target, prefix []byte) (Inspection, error) {
	target, err := normalizeTarget(target)
	if err != nil {
		return Inspection{}, err
	}
	if len(prefix) > maxFirstPacket {
		return Inspection{}, badProtocol("TLS first packet is too large")
	}
	var handshake []byte
	consumed := 0
	for {
		if len(prefix)-consumed < 5 {
			return Inspection{}, badProtocol("incomplete TLS record")
		}
		header := prefix[consumed : consumed+5]
		length := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || header[1] != 3 || header[2] > 4 || length == 0 || length > 18432 {
			return Inspection{}, badProtocol("invalid TLS handshake record")
		}
		if len(prefix)-consumed-5 < length {
			return Inspection{}, badProtocol("incomplete TLS record")
		}
		handshake = append(handshake, prefix[consumed+5:consumed+5+length]...)
		consumed += 5 + length
		if len(handshake) < 4 {
			continue
		}
		length = int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if handshake[0] != 1 || length+4 > maxFirstPacket {
			return Inspection{}, badProtocol("invalid TLS ClientHello")
		}
		if len(handshake) < length+4 {
			continue
		}
		host, err := clientHelloSNI(handshake[4 : 4+length])
		if err != nil {
			return Inspection{}, err
		}
		if host == "" {
			host = target.Host
		}
		if err := checkActualTarget(target, host, target.Port); err != nil {
			return Inspection{}, err
		}
		return Inspection{Kind: "tls", Host: host, Port: target.Port, Header: bytes.Clone(prefix[:consumed])}, nil
	}
}

func clientHelloSNI(hello []byte) (string, error) {
	if len(hello) < 35 || hello[0] != 3 || hello[1] > 4 {
		return "", badProtocol("invalid TLS ClientHello")
	}
	pos := 34
	sessionLength := int(hello[pos])
	pos++
	if sessionLength > 32 || len(hello)-pos < sessionLength+2 {
		return "", badProtocol("invalid TLS session")
	}
	pos += sessionLength
	cipherLength := int(binary.BigEndian.Uint16(hello[pos:]))
	pos += 2
	if cipherLength < 2 || cipherLength%2 != 0 || len(hello)-pos < cipherLength+1 {
		return "", badProtocol("invalid TLS cipher suites")
	}
	pos += cipherLength
	compressionLength := int(hello[pos])
	pos++
	if compressionLength == 0 || len(hello)-pos < compressionLength {
		return "", badProtocol("invalid TLS compression")
	}
	pos += compressionLength
	if pos == len(hello) {
		return "", nil
	}
	if len(hello)-pos < 2 {
		return "", badProtocol("invalid TLS extensions")
	}
	extensionLength := int(binary.BigEndian.Uint16(hello[pos:]))
	pos += 2
	if extensionLength != len(hello)-pos {
		return "", badProtocol("invalid TLS extensions length")
	}
	seen := make(map[uint16]bool)
	var host string
	for pos < len(hello) {
		if len(hello)-pos < 4 {
			return "", badProtocol("invalid TLS extension")
		}
		kind := binary.BigEndian.Uint16(hello[pos:])
		length := int(binary.BigEndian.Uint16(hello[pos+2:]))
		pos += 4
		if seen[kind] || len(hello)-pos < length {
			return "", badProtocol("invalid TLS extension")
		}
		seen[kind] = true
		if kind == 0 {
			value := hello[pos : pos+length]
			if len(value) <= 2 || int(binary.BigEndian.Uint16(value)) != len(value)-2 {
				return "", badProtocol("invalid TLS SNI list")
			}
			for offset := 2; offset < len(value); {
				if len(value)-offset < 3 {
					return "", badProtocol("invalid TLS SNI")
				}
				typeID := value[offset]
				nameLength := int(binary.BigEndian.Uint16(value[offset+1:]))
				offset += 3
				if nameLength == 0 || len(value)-offset < nameLength {
					return "", badProtocol("invalid TLS SNI")
				}
				if typeID == 0 {
					if host != "" {
						return "", badProtocol("duplicate TLS SNI")
					}
					for _, c := range value[offset : offset+nameLength] {
						if c <= ' ' || c >= 127 {
							return "", badProtocol("invalid TLS SNI host")
						}
					}
					var err error
					host, err = normalizeDomain(string(value[offset : offset+nameLength]))
					if err != nil {
						return "", badProtocol("invalid TLS SNI host")
					}
				}
				offset += nameLength
			}
		}
		pos += length
	}
	return host, nil
}

func inspectH2Prefix(target Target, prefix []byte) (Inspection, error) {
	if !bytes.HasPrefix(prefix, []byte(http2.ClientPreface)) {
		return Inspection{}, badProtocol("incomplete or invalid HTTP/2 preface")
	}
	r := bytes.NewReader(prefix[len(http2.ClientPreface):])
	framer := http2.NewFramer(io.Discard, r)
	framer.SetMaxReadFrameSize(maxFirstPacket)
	first := true
	var block []byte
	var stream uint32
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return Inspection{}, badProtocol("invalid or incomplete HTTP/2 frame")
		}
		if first {
			settings, ok := frame.(*http2.SettingsFrame)
			if !ok || settings.IsAck() {
				return Inspection{}, badProtocol("HTTP/2 must start with SETTINGS")
			}
			if err := settings.ForeachSetting(func(s http2.Setting) error { return s.Valid() }); err != nil {
				return Inspection{}, badProtocol("invalid HTTP/2 settings")
			}
			first = false
			continue
		}
		if stream != 0 {
			continuation, ok := frame.(*http2.ContinuationFrame)
			if !ok || continuation.StreamID != stream {
				return Inspection{}, badProtocol("invalid HTTP/2 continuation")
			}
			block = append(block, continuation.HeaderBlockFragment()...)
			if len(block) > maxHeaderBytes {
				return Inspection{}, badProtocol("HTTP/2 header is too large")
			}
			if !continuation.HeadersEnded() {
				continue
			}
		} else {
			switch f := frame.(type) {
			case *http2.HeadersFrame:
				if f.StreamID%2 == 0 {
					return Inspection{}, badProtocol("invalid HTTP/2 request stream")
				}
				if f.HasPriority() && f.Priority.StreamDep == f.StreamID {
					return Inspection{}, badProtocol("HTTP/2 stream depends on itself")
				}
				stream = f.StreamID
				block = append(block, f.HeaderBlockFragment()...)
				if len(block) > maxHeaderBytes {
					return Inspection{}, badProtocol("HTTP/2 header is too large")
				}
				if !f.HeadersEnded() {
					continue
				}
			case *http2.SettingsFrame, *http2.PingFrame, *http2.WindowUpdateFrame, *http2.PriorityFrame:
				continue
			default:
				return Inspection{}, badProtocol("HTTP/2 request HEADERS required")
			}
		}
		decoder := hpack.NewDecoder(4096, nil)
		decoder.SetMaxStringLength(maxHeaderBytes)
		fields, err := decoder.DecodeFull(block)
		if err != nil {
			return Inspection{}, badProtocol("invalid HTTP/2 HPACK")
		}
		inspection, err := inspectH2Headers(target, fields)
		if err != nil {
			return Inspection{}, err
		}
		inspection.Header = bytes.Clone(prefix[:len(prefix)-r.Len()])
		return inspection, nil
	}
}

// Used with the stream's persistent HPACK decoder as well as its first request.
func inspectH2Headers(target Target, fields []hpack.HeaderField) (Inspection, error) {
	target, err := normalizeTarget(target)
	if err != nil {
		return Inspection{}, err
	}
	pseudo := make(map[string]string)
	h := make(http.Header)
	regular := false
	size := 0
	for _, field := range fields {
		size += len(field.Name) + len(field.Value) + 32
		if size > maxHeaderBytes {
			return Inspection{}, badProtocol("HTTP/2 decoded header is too large")
		}
		if strings.ToLower(field.Name) != field.Name {
			return Inspection{}, badProtocol("HTTP/2 header name must be lowercase")
		}
		if strings.Trim(field.Value, " \t") != field.Value {
			return Inspection{}, badProtocol("HTTP/2 header value has whitespace at its boundary")
		}
		for _, c := range []byte(field.Value) {
			if c < 32 && c != '\t' || c == 127 {
				return Inspection{}, badProtocol("invalid HTTP/2 header value")
			}
		}
		if strings.HasPrefix(field.Name, ":") {
			if regular || pseudo[field.Name] != "" || field.Value == "" {
				return Inspection{}, badProtocol("invalid HTTP/2 pseudo headers")
			}
			switch field.Name {
			case ":method", ":scheme", ":authority", ":path":
			default:
				return Inspection{}, badProtocol("unsupported HTTP/2 pseudo header")
			}
			pseudo[field.Name] = field.Value
		} else {
			regular = true
			if !validToken(field.Name) {
				return Inspection{}, badProtocol("invalid HTTP/2 header name")
			}
			switch field.Name {
			case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
				return Inspection{}, badProtocol("connection header is invalid in HTTP/2")
			}
			if field.Name == "te" && field.Value != "trailers" {
				return Inspection{}, badProtocol("invalid HTTP/2 TE")
			}
			h.Add(field.Name, field.Value)
		}
	}
	method := pseudo[":method"]
	if !validToken(method) {
		return Inspection{}, badProtocol("invalid HTTP/2 method")
	}
	scheme := pseudo[":scheme"]
	defaultPort := 80
	if scheme == "https" {
		defaultPort = 443
	}
	if method != "CONNECT" && scheme != "http" && scheme != "https" {
		return Inspection{}, badProtocol("invalid HTTP/2 scheme")
	}
	if method == "CONNECT" {
		defaultPort = 0
		if scheme != "" || pseudo[":path"] != "" {
			return Inspection{}, badProtocol("invalid HTTP/2 CONNECT")
		}
	}
	host, port, err := parseAuthority(pseudo[":authority"], defaultPort)
	if err != nil {
		return Inspection{}, err
	}
	if len(h.Values("Host")) > 1 {
		return Inspection{}, badProtocol("duplicate HTTP/2 Host")
	}
	if values := h.Values("Host"); len(values) == 1 {
		value := values[0]
		headerHost, headerPort, err := parseAuthority(value, defaultPort)
		if err != nil || headerHost != host || headerPort != port {
			return Inspection{}, badProtocol("HTTP/2 authority and Host disagree")
		}
	}
	if err := checkActualTarget(target, host, port); err != nil {
		return Inspection{}, err
	}
	if err := validateHTTPFraming(h); err != nil {
		return Inspection{}, err
	}
	inspection := Inspection{Kind: "h2", Host: host, Port: port}
	path := pseudo[":path"]
	if method == "CONNECT" {
		inspection.Kind = "connect"
		return inspection, nil
	}
	if path == "*" {
		if method != "OPTIONS" {
			return Inspection{}, badProtocol("asterisk target requires OPTIONS")
		}
		return inspection, nil
	}
	if path == "" || !strings.HasPrefix(path, "/") {
		return Inspection{}, badProtocol("invalid HTTP/2 path")
	}
	for _, c := range []byte(path) {
		if c <= ' ' || c >= 127 {
			return Inspection{}, badProtocol("invalid HTTP/2 path")
		}
	}
	inspection.URL, err = normalizedHTTPURL(scheme, host, port, path)
	return inspection, err
}

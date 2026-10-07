package relay

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type recordedReader struct {
	r      io.Reader
	wire   bytes.Buffer
	prefix []byte
}

func (r *recordedReader) Read(p []byte) (int, error) {
	var n int
	var err error
	if len(r.prefix) != 0 {
		n = copy(p, r.prefix)
		r.prefix = r.prefix[n:]
	} else {
		n, err = r.r.Read(p)
	}
	r.wire.Write(p[:n])
	return n, err
}

type h2HeaderReader struct {
	recorder  *recordedReader
	framer    *http2.Framer
	decoder   *hpack.Decoder
	deadline  func(time.Time) error
	inHeaders bool
}

func newH2Reader(src io.Reader) *h2HeaderReader {
	r := &recordedReader{r: src}
	f := http2.NewFramer(io.Discard, r)
	f.SetMaxReadFrameSize(maxDataMessage - 9)
	d := hpack.NewDecoder(4096, nil)
	d.SetMaxStringLength(maxHeaderBytes)
	d.SetAllowedMaxDynamicTableSize(4096)
	return &h2HeaderReader{recorder: r, framer: f, decoder: d}
}

func (r *h2HeaderReader) next() (http2.Frame, []byte, error) {
	if r.deadline != nil && !r.inHeaders {
		if err := r.deadline(time.Now().Add(10 * time.Second)); err != nil {
			return nil, nil, err
		}
	}
	var head [9]byte
	n, err := io.ReadFull(r.recorder.r, head[:])
	if err == io.EOF && n == 0 {
		return nil, nil, io.EOF
	}
	if err != nil {
		return nil, nil, badProtocol("incomplete HTTP/2 frame header")
	}
	if head[3] == byte(http2.FrameHeaders) || head[3] == byte(http2.FrameContinuation) {
		r.inHeaders = true
	} else if !r.inHeaders && r.deadline != nil {
		if err := r.deadline(time.Time{}); err != nil {
			return nil, nil, err
		}
	}
	r.recorder.wire.Reset()
	r.recorder.prefix = head[:]
	frame, err := r.framer.ReadFrame()
	if err == io.EOF && r.recorder.wire.Len() == 0 {
		return nil, nil, io.EOF
	}
	if err != nil {
		return nil, nil, badProtocol("invalid or oversized HTTP/2 frame")
	}
	return frame, bytes.Clone(r.recorder.wire.Bytes()), nil
}

func (r *h2HeaderReader) headers(first *http2.HeadersFrame, wire []byte) ([]hpack.HeaderField, []byte, error) {
	encoded := bytes.Clone(first.HeaderBlockFragment())
	ended := first.HeadersEnded()
	for !ended {
		frame, part, err := r.next()
		if err != nil {
			return nil, nil, badProtocol("incomplete HTTP/2 header block")
		}
		cont, ok := frame.(*http2.ContinuationFrame)
		if !ok || cont.StreamID != first.StreamID {
			return nil, nil, badProtocol("invalid HTTP/2 continuation")
		}
		encoded = append(encoded, cont.HeaderBlockFragment()...)
		wire = append(wire, part...)
		if len(encoded) > maxHeaderBytes || len(wire) > maxFirstPacket {
			return nil, nil, badProtocol("HTTP/2 header block exceeds limit")
		}
		ended = cont.HeadersEnded()
	}
	if len(encoded) > maxHeaderBytes || len(wire) > maxFirstPacket {
		return nil, nil, badProtocol("HTTP/2 header block exceeds limit")
	}
	var fields []hpack.HeaderField
	size := 0
	r.decoder.SetEmitEnabled(true)
	r.decoder.SetEmitFunc(func(f hpack.HeaderField) {
		size += len(f.Name) + len(f.Value) + 32
		if size <= maxHeaderBytes {
			fields = append(fields, f)
		} else {
			r.decoder.SetEmitEnabled(false)
		}
	})
	if _, err := r.decoder.Write(encoded); err != nil {
		return nil, nil, badProtocol("invalid HTTP/2 HPACK")
	}
	if err := r.decoder.Close(); err != nil || size > maxHeaderBytes {
		return nil, nil, badProtocol("invalid or oversized HTTP/2 decoded headers")
	}
	r.inHeaders = false
	if r.deadline != nil {
		if err := r.deadline(time.Time{}); err != nil {
			return nil, nil, err
		}
	}
	return fields, wire, nil
}

type h2Stream struct {
	length, received int64
}

func guardH2(dst io.Writer, br *bufio.Reader, target Target, ip netip.Addr, rules *compiledRules, upgraded bool, session *streamSession) error {
	magic := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != http2.ClientPreface {
		return badProtocol("invalid HTTP/2 preface")
	}
	if err := writeBytes(dst, magic); err != nil {
		return err
	}
	r := newH2Reader(br)
	r.deadline = session.setAgentDeadline
	streams := make(map[uint32]*h2Stream)
	var largest uint32
	if upgraded {
		largest = 1
	}
	first := true
	for {
		frame, wire, err := r.next()
		if err == io.EOF {
			if len(streams) != 0 {
				return badProtocol("incomplete HTTP/2 stream")
			}
			return nil
		}
		if err != nil {
			return err
		}
		if first {
			settings, ok := frame.(*http2.SettingsFrame)
			if !ok || settings.IsAck() {
				return badProtocol("HTTP/2 must start with SETTINGS")
			}
			first = false
		}
		switch f := frame.(type) {
		case *http2.HeadersFrame:
			if f.StreamID%2 == 0 {
				return badProtocol("invalid HTTP/2 request stream")
			}
			if f.HasPriority() && f.Priority.StreamDep == f.StreamID {
				return badProtocol("HTTP/2 stream depends on itself")
			}
			fields, all, err := r.headers(f, wire)
			if err != nil {
				return err
			}
			wire = all
			stream := streams[f.StreamID]
			if stream != nil {
				if !f.StreamEnded() {
					return badProtocol("invalid HTTP/2 trailers")
				}
				if err := validateH2Trailers(fields); err != nil {
					return err
				}
				if stream.length >= 0 && stream.received != stream.length {
					return badProtocol("HTTP/2 content length mismatch")
				}
				delete(streams, f.StreamID)
			} else {
				if f.StreamID <= largest {
					return badProtocol("HTTP/2 request stream reused")
				}
				// ponytail: 128 simultaneous client streams; raise with measured capacity.
				if len(streams) >= 128 {
					return badProtocol("too many HTTP/2 streams")
				}
				actual, err := inspectH2Headers(target, fields)
				if err != nil {
					return err
				}
				if err := sameEndpoint(target, actual); err != nil {
					return err
				}
				if actual.Kind == "connect" {
					return badProtocol("CONNECT must be terminated by the agent")
				}
				if !rules.allows(ip, actual.Host, actual.URL, true) {
					return &ruleRejection{}
				}
				length, err := h2ContentLength(fields)
				if err != nil {
					return err
				}
				stream = &h2Stream{length: length}
				largest = f.StreamID
				if f.StreamEnded() {
					if length > 0 {
						return badProtocol("HTTP/2 content length mismatch")
					}
				} else {
					streams[f.StreamID] = stream
				}

			}
		case *http2.DataFrame:
			stream := streams[f.StreamID]
			if stream == nil {
				return badProtocol("HTTP/2 DATA has no approved stream")
			}
			stream.received += int64(len(f.Data()))
			if stream.received < 0 || stream.length >= 0 && stream.received > stream.length {
				return badProtocol("HTTP/2 content length exceeded")
			}
			if f.StreamEnded() {
				if stream.length >= 0 && stream.received != stream.length {
					return badProtocol("HTTP/2 content length mismatch")
				}
				delete(streams, f.StreamID)
			}
		case *http2.SettingsFrame:
			if err := f.ForeachSetting(func(s http2.Setting) error { return s.Valid() }); err != nil {
				return badProtocol("invalid HTTP/2 settings")
			}
		case *http2.RSTStreamFrame:
			// END_STREAM closes only the request direction; its response can
			// still be cancelled. Lower skipped client IDs are implicitly closed.
			if f.StreamID%2 == 0 || f.StreamID > largest {
				return badProtocol("HTTP/2 reset has no initiated stream")
			}
			delete(streams, f.StreamID)
		case *http2.PriorityFrame:
			if f.StreamDep == f.StreamID {
				return badProtocol("HTTP/2 stream depends on itself")
			}
		case *http2.ContinuationFrame, *http2.PushPromiseFrame:
			return badProtocol("unexpected HTTP/2 frame")
		}
		if err := writeBytes(dst, wire); err != nil {
			return err
		}
	}
}

func h2ContentLength(fields []hpack.HeaderField) (int64, error) {
	length := int64(-1)
	for _, f := range fields {
		if f.Name != "content-length" {
			continue
		}
		n, err := strconv.ParseInt(f.Value, 10, 64)
		if err != nil || n < 0 || length >= 0 && length != n {
			return 0, badProtocol("invalid HTTP/2 content length")
		}
		length = n
	}
	return length, nil
}

func validateH2Trailers(fields []hpack.HeaderField) error {
	var raw bytes.Buffer
	for _, f := range fields {
		if strings.HasPrefix(f.Name, ":") || f.Name != strings.ToLower(f.Name) {
			return badProtocol("invalid HTTP/2 trailer")
		}
		for i := range f.Value {
			if f.Value[i] < 32 && f.Value[i] != '\t' || f.Value[i] == 127 {
				return badProtocol("invalid HTTP/2 trailer value")
			}
		}
		fmt.Fprintf(&raw, "%s: %s\r\n", f.Name, f.Value)
	}
	return validateTrailers(raw.Bytes())
}

func relayH2Responses(dst io.Writer, src io.Reader, deadline func(time.Time) error) error {
	r := newH2Reader(src)
	r.deadline = deadline
	first := true
	for {
		frame, wire, err := r.next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if first {
			f, ok := frame.(*http2.SettingsFrame)
			if !ok || f.IsAck() {
				return badProtocol("HTTP/2 response must start with SETTINGS")
			}
			first = false
		}
		if f, ok := frame.(*http2.HeadersFrame); ok {
			fields, all, err := r.headers(f, wire)
			if err != nil {
				return err
			}
			wire = all
			status := 0
			regular := false
			for _, field := range fields {
				if field.Name != strings.ToLower(field.Name) || strings.Trim(field.Value, " \t") != field.Value {
					return badProtocol("invalid HTTP/2 response header")
				}
				for i := range field.Value {
					if field.Value[i] < 32 && field.Value[i] != '\t' || field.Value[i] == 127 {
						return badProtocol("invalid HTTP/2 response value")
					}
				}
				if field.Name == ":status" {
					if regular || status != 0 || len(field.Value) != 3 {
						return badProtocol("invalid HTTP/2 response status")
					}
					status, err = strconv.Atoi(field.Value)
					if err != nil || status < 100 || status > 599 {
						return badProtocol("invalid HTTP/2 response status")
					}
				} else {
					regular = true
					if !validToken(field.Name) {
						return badProtocol("invalid HTTP/2 response pseudo header")
					}
					switch field.Name {
					case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
						return badProtocol("invalid HTTP/2 response connection header")
					}
					if field.Name == "te" && field.Value != "trailers" {
						return badProtocol("invalid HTTP/2 response TE")
					}
				}
			}
			if _, err := h2ContentLength(fields); err != nil {
				return err
			}
		} else if _, ok := frame.(*http2.ContinuationFrame); ok {
			return badProtocol("unexpected HTTP/2 response continuation")
		}
		if err := writeBytes(dst, wire); err != nil {
			return err
		}
	}
}

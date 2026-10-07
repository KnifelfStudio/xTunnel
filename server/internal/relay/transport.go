package relay

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Track frame boundaries only for deadlines; Gorilla still validates/decodes
// every frame. Inspecting bytes here covers partial headers and read-ahead of
// the next frame without imposing a timeout on a genuinely idle TCP channel.
type messageConn struct {
	net.Conn
	mu                                                sync.Mutex
	outerDeadline, messageDeadline, transportDeadline time.Time
	readFinished                                      atomic.Bool
	header                                            [14]byte
	headerBytes                                       int
	payloadLeft                                       uint64
	inPayload, fragmented, fin, control               bool
}

func (c *messageConn) effectiveLocked() time.Time {
	d := c.outerDeadline
	for _, limit := range []time.Time{c.messageDeadline, c.transportDeadline} {
		if !limit.IsZero() && (d.IsZero() || limit.Before(d)) {
			d = limit
		}
	}
	return d
}
func (c *messageConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outerDeadline = t
	return c.Conn.SetReadDeadline(c.effectiveLocked())
}
func (c *messageConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	err := c.Conn.SetReadDeadline(c.effectiveLocked())
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	n, e := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.transportDeadline = time.Now().Add(60 * time.Second)
		c.observeLocked(p[:n])
		err := c.Conn.SetReadDeadline(c.effectiveLocked())
		c.mu.Unlock()
		if e == nil {
			e = err
		}
	}
	return n, e
}
func (c *messageConn) completeFrameLocked() {
	if !c.control {
		c.fragmented = !c.fin
	}
	if !c.fragmented {
		c.messageDeadline = time.Time{}
	}
	c.inPayload = false
	c.headerBytes = 0
}
func (c *messageConn) observeLocked(p []byte) {
	for len(p) > 0 {
		if c.inPayload {
			n := uint64(len(p))
			if n > c.payloadLeft {
				n = c.payloadLeft
			}
			p = p[int(n):]
			c.payloadLeft -= n
			if c.payloadLeft == 0 {
				c.completeFrameLocked()
			}
			continue
		}
		if c.headerBytes == 0 && c.messageDeadline.IsZero() {
			c.messageDeadline = time.Now().Add(30 * time.Second)
		}
		c.header[c.headerBytes] = p[0]
		c.headerBytes++
		p = p[1:]
		if c.headerBytes < 2 {
			continue
		}
		size := 2
		length := uint64(c.header[1] & 127)
		switch length {
		case 126:
			size += 2
		case 127:
			size += 8
		}
		if c.header[1]&128 != 0 {
			size += 4
		}
		if c.headerBytes < size {
			continue
		}
		switch length {
		case 126:
			length = uint64(binary.BigEndian.Uint16(c.header[2:4]))
		case 127:
			length = binary.BigEndian.Uint64(c.header[2:10])
		}
		c.fin = c.header[0]&128 != 0
		c.control = c.header[0]&15 >= 8
		c.payloadLeft = length
		c.inPayload = true
		if length == 0 {
			c.completeFrameLocked()
		}
	}
}

type timedHijacker struct{ http.ResponseWriter }

func (w timedHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, rw, e := hijacker.Hijack()
	if e != nil {
		return nil, nil, e
	}
	// Keep Gorilla's rejection of data buffered before the HTTP 101 handshake.
	return &messageConn{Conn: conn, transportDeadline: time.Now().Add(60 * time.Second)}, rw, nil
}
func (s *Server) dataHeartbeat(conn *websocket.Conn, f *forward) {
	defer s.workers.Done()
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-f.done:
			return
		case <-tick.C:
			if timed, ok := conn.NetConn().(*messageConn); ok && timed.readFinished.Load() {
				continue
			}
			if e := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); e != nil {
				s.mu.Lock()
				s.finishLocked(f, classifyDataError(e))
				s.mu.Unlock()
				return
			}
		}
	}
}
func readDataMessage(conn *websocket.Conn) (int, []byte, error) {
	kind, r, e := conn.NextReader()
	if e != nil {
		return 0, nil, e
	}
	b, e := io.ReadAll(io.LimitReader(r, maxDataMessage+1))
	if e == nil && len(b) > maxDataMessage {
		e = badProtocol("data message is too large")
	}
	return kind, b, e
}

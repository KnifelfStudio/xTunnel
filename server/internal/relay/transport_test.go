package relay

import (
	"net"
	"testing"
	"time"
)

func TestMessageDeadlineCannotBeClearedByProtocolInspection(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	c := &messageConn{Conn: left}
	go func() { _, _ = right.Write([]byte{0x82}) }()
	var b [1]byte
	if _, e := c.Read(b[:]); e != nil {
		t.Fatal(e)
	}
	if c.messageDeadline.IsZero() {
		t.Fatal("partial frame did not start bounded read")
	}
	c.mu.Lock()
	c.messageDeadline = time.Now().Add(20 * time.Millisecond)
	c.mu.Unlock()
	if e := c.SetReadDeadline(time.Time{}); e != nil {
		t.Fatal(e)
	}
	_, e := c.Read(b[:])
	if timeout, ok := e.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("incomplete message lacked deadline: %v", e)
	}
}
func TestIdleDataReaderDoesNotStartMessageDeadline(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	c := &messageConn{Conn: left}
	started := make(chan struct{})
	finished := make(chan struct{})
	go func() { close(started); var b [1]byte; _, _ = c.Read(b[:]); close(finished) }()
	<-started
	c.mu.Lock()
	deadline := c.messageDeadline
	c.mu.Unlock()
	if !deadline.IsZero() {
		t.Fatal("idle reader started message timeout")
	}
	left.Close()
	<-finished
}

func TestFrameReadAheadAndControlFramesKeepCorrectDeadline(t *testing.T) {
	c := &messageConn{}
	// A complete frame followed by one byte of the next header in the same read.
	c.observeLocked([]byte{0x82, 0x01, 0x00, 0x82})
	if c.messageDeadline.IsZero() || c.headerBytes != 1 {
		t.Fatal("read-ahead hid the next incomplete header")
	}
	fragmented := &messageConn{}
	fragmented.observeLocked([]byte{0x02, 0x01, 0x00})
	deadline := fragmented.messageDeadline
	if deadline.IsZero() {
		t.Fatal("fragment timer absent")
	}
	fragmented.observeLocked([]byte{0x89, 0x00})
	if fragmented.messageDeadline != deadline {
		t.Fatal("control frame extended unfinished message")
	}
	fragmented.observeLocked([]byte{0x80, 0x00})
	if !fragmented.messageDeadline.IsZero() {
		t.Fatal("completed message kept read timer")
	}
}

func TestStalledTransportBeforeAnyPlaintextHasHeartbeatDeadline(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	c := &messageConn{Conn: left, transportDeadline: time.Now().Add(20 * time.Millisecond)}
	result := make(chan error, 1)
	go func() { _, e := c.Read(make([]byte, 1)); result <- e }()
	var e error
	select {
	case e = <-result:
	case <-time.After(300 * time.Millisecond):
		left.Close()
		<-result
		t.Fatal("first transport read did not apply its deadline")
	}
	if timeout, ok := e.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("transport without plaintext could wait forever: %v", e)
	}
}

package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrackAPIRequiresTLSAndValidatesWholeConfig(t *testing.T) {
	s := New()
	defer s.Close()
	plain := httptest.NewRecorder()
	s.Handler().ServeHTTP(plain, httptest.NewRequest("POST", "/v1/tracks", bytes.NewBufferString(`{"rules":{}}`)))
	if plain.Code != http.StatusUpgradeRequired {
		t.Fatalf("plain HTTP status %d", plain.Code)
	}
	ts := httptest.NewTLSServer(s.Handler())
	defer ts.Close()
	r, err := ts.Client().Post(ts.URL+"/v1/tracks", "application/json", bytes.NewBufferString(`{"rules":{"ipv4_cidrs":["10.0.0.0/8"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("create status %d", r.StatusCode)
	}
	var track TrackView
	if err := json.NewDecoder(r.Body).Decode(&track); err != nil {
		t.Fatal(err)
	}
	if len(track.PairingCode) != 4 || len(track.ManagementToken) < 43 || track.ServiceSession == "" || track.ConfigVersion != 1 || track.Online {
		t.Fatalf("invalid initial track metadata")
	}
	r2, err := ts.Client().Post(ts.URL+"/v1/tracks", "application/json", bytes.NewBufferString(`{"rules":{"ipv4_cidrs":["10.0.0.0/8","bad"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid config status %d", r2.StatusCode)
	}
}

type blockedResponse struct {
	header           http.Header
	entered, release chan struct{}
}

func (w *blockedResponse) Header() http.Header { return w.header }
func (w *blockedResponse) WriteHeader(int)     {}
func (w *blockedResponse) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return len(p), nil
}
func TestSlowHTTPResponseDoesNotHoldSessionLock(t *testing.T) {
	s := New()
	defer s.Close()
	w := &blockedResponse{header: make(http.Header), entered: make(chan struct{}), release: make(chan struct{})}
	r := httptest.NewRequest("POST", "https://relay.test/v1/tracks", bytes.NewBufferString(`{"rules":{}}`))
	r.Header.Set("Content-Type", "application/json")
	finished := make(chan struct{})
	go func() { s.Handler().ServeHTTP(w, r); close(finished) }()
	<-w.entered
	locked := s.mu.TryLock()
	if locked {
		s.mu.Unlock()
	}
	close(w.release)
	<-finished
	if !locked {
		t.Fatal("response socket write holds global session lock")
	}
}

func TestInvalidRuleSnapshotCannotClearConfiguration(t *testing.T) {
	s := New()
	defer s.Close()
	ts := httptest.NewTLSServer(s.Handler())
	defer ts.Close()
	for _, body := range []string{`{}`, `null`, `{"rules":null}`, `{"rules":{"http_url_regex":[null]}}`, "{\"rules\":{\"http_url_regex\":[\"" + string([]byte{0xff}) + "\"]}}"} {
		r, e := ts.Client().Post(ts.URL+"/v1/tracks", "application/json", bytes.NewBufferString(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
		if r.StatusCode != 400 {
			t.Fatalf("invalid rule snapshot accepted: %d", r.StatusCode)
		}
	}
}

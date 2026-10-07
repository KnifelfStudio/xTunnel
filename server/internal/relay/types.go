package relay

// RuleConfig is an immutable, validated OR-list once committed to a track.
type RuleConfig struct {
	CIDRs    []string `json:"ipv4_cidrs"`
	Domains  []string `json:"domains"`
	URLRegex []string `json:"http_url_regex"`
}

// Target is a fixed IPv4 address or a domain resolved only by the server-mode client.
type Target struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// Inspection is derived from bytes, never from an agent's declared protocol or URL.
type Inspection struct {
	Kind    string
	Host    string
	Port    int
	URL     string
	Header  []byte
	Upgrade string
}

type protocolError struct{ reason string }

func (e *protocolError) Error() string { return e.reason }
func badProtocol(reason string) error  { return &protocolError{reason: reason} }

const (
	maxHeaderBytes = 32 << 10
	maxFirstPacket = 64 << 10
	maxDataMessage = 64 << 10
)

package relay

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func dnsQueryFixture(t *testing.T, typ dnsmessage.Type) []byte {
	t.Helper()
	return packDNSFixture(t, dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("Internal.Example."), Type: typ, Class: dnsmessage.ClassINET}},
	})
}

func packDNSFixture(t *testing.T, msg dnsmessage.Message) []byte {
	t.Helper()
	b, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDNSQueryRestrictsChannelToResolution(t *testing.T) {
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeCNAME, dnsmessage.TypeNS, dnsmessage.TypeSOA, dnsmessage.TypePTR, dnsmessage.TypeMX, dnsmessage.TypeTXT, dnsmessage.TypeSRV, dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS} {
		q, err := validateDNSQuery(dnsQueryFixture(t, typ))
		if err != nil || q.Name != "internal.example" || q.Type != uint16(typ) {
			t.Fatalf("type %d: question = %+v, error = %v", typ, q, err)
		}
	}
	var base dnsmessage.Message
	if err := base.Unpack(dnsQueryFixture(t, dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	edns := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232, TTL: 1 << 15}, Body: &dnsmessage.OPTResource{}}
	ednsQuery := base
	ednsQuery.Additionals = []dnsmessage.Resource{edns}
	if _, err := validateDNSQuery(packDNSFixture(t, ednsQuery)); err != nil {
		t.Fatalf("valid EDNS query: %v", err)
	}
	for _, options := range [][]dnsmessage.Option{{{Code: 10, Data: make([]byte, 8)}}, {{Code: 12, Data: make([]byte, 16)}}} {
		ednsQuery.Additionals[0].Body = &dnsmessage.OPTResource{Options: options}
		if _, err := validateDNSQuery(packDNSFixture(t, ednsQuery)); err != nil {
			t.Fatalf("valid EDNS options: %v", err)
		}
	}
	for name, mutate := range map[string]func(*dnsmessage.Message){
		"response":             func(m *dnsmessage.Message) { m.Response = true },
		"update opcode":        func(m *dnsmessage.Message) { m.OpCode = 5 },
		"query rcode":          func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeNameError },
		"multiple questions":   func(m *dnsmessage.Message) { m.Questions = append(m.Questions, m.Questions[0]) },
		"non IN class":         func(m *dnsmessage.Message) { m.Questions[0].Class = dnsmessage.ClassCHAOS },
		"AXFR":                 func(m *dnsmessage.Message) { m.Questions[0].Type = 252 },
		"IXFR":                 func(m *dnsmessage.Message) { m.Questions[0].Type = 251 },
		"ANY":                  func(m *dnsmessage.Message) { m.Questions[0].Type = 255 },
		"unknown query type":   func(m *dnsmessage.Message) { m.Questions[0].Type = 65000 },
		"Unicode case folding": func(m *dnsmessage.Message) { m.Questions[0].Name = dnsmessage.MustNewName("\u212A.example.") },
		"answer payload": func(m *dnsmessage.Message) {
			m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}}}}
		},
		"authority payload": func(m *dnsmessage.Message) {
			m.Authorities = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}}}}
		},
		"additional payload": func(m *dnsmessage.Message) {
			m.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Class: dnsmessage.ClassINET}, Body: &dnsmessage.TXTResource{TXT: []string{"payload"}}}}
		},
		"duplicate OPT": func(m *dnsmessage.Message) { m.Additionals = []dnsmessage.Resource{edns, edns} },
		"OPT nonroot": func(m *dnsmessage.Message) {
			opt := edns
			opt.Header.Name = m.Questions[0].Name
			m.Additionals = []dnsmessage.Resource{opt}
		},
		"OPT version": func(m *dnsmessage.Message) {
			opt := edns
			opt.Header.TTL |= 1 << 16
			m.Additionals = []dnsmessage.Resource{opt}
		},
		"OPT payload": func(m *dnsmessage.Message) {
			opt := edns
			opt.Body = &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 65000, Data: []byte("payload")}}}
			m.Additionals = []dnsmessage.Resource{opt}
		},
		"invalid cookie": func(m *dnsmessage.Message) {
			opt := edns
			opt.Body = &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 10, Data: make([]byte, 9)}}}
			m.Additionals = []dnsmessage.Resource{opt}
		},
		"padding payload": func(m *dnsmessage.Message) {
			opt := edns
			opt.Body = &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 12, Data: []byte{1}}}}
			m.Additionals = []dnsmessage.Resource{opt}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var msg dnsmessage.Message
			if err := msg.Unpack(dnsQueryFixture(t, dnsmessage.TypeA)); err != nil {
				t.Fatal(err)
			}
			mutate(&msg)
			if _, err := validateDNSQuery(packDNSFixture(t, msg)); err == nil {
				t.Fatal("invalid query accepted")
			}
		})
	}
	query := dnsQueryFixture(t, dnsmessage.TypeA)
	reserved := bytes.Clone(query)
	reserved[3] |= 0x40
	for name, raw := range map[string][]byte{
		"trailing":            append(bytes.Clone(query), 0),
		"oversized":           make([]byte, 4097),
		"truncated":           query[:len(query)-1],
		"compression loop":    {0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1},
		"header pointer":      {0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x04, 0, 1, 0, 1},
		"reserved header bit": reserved,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateDNSQuery(raw); err == nil {
				t.Fatal("invalid wire query accepted")
			}
		})
	}
}

func TestDNSResponseMatchesOriginalQueryAndKeepsIPv4(t *testing.T) {
	query := dnsQueryFixture(t, dnsmessage.TypeA)
	var msg dnsmessage.Message
	if err := msg.Unpack(query); err != nil {
		t.Fatal(err)
	}
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Questions[0].Name = dnsmessage.MustNewName("internal.example.")
	msg.Answers = []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Name: msg.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("backend.example.")}},
		{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("backend.example."), Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{10, 1, 2, 3}}},
	}
	response := packDNSFixture(t, msg)
	if err := validateDNSResponse(query, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, packDNSFixture(t, msg)) {
		t.Fatal("response bytes changed")
	}
	for name, mutate := range map[string]func(*dnsmessage.Message){
		"ID":                 func(m *dnsmessage.Message) { m.ID++ },
		"not response":       func(m *dnsmessage.Message) { m.Response = false },
		"opcode":             func(m *dnsmessage.Message) { m.OpCode = 1 },
		"name":               func(m *dnsmessage.Message) { m.Questions[0].Name = dnsmessage.MustNewName("other.example.") },
		"type":               func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeTXT },
		"class":              func(m *dnsmessage.Message) { m.Questions[0].Class = dnsmessage.ClassCHAOS },
		"multiple questions": func(m *dnsmessage.Message) { m.Questions = append(m.Questions, m.Questions[0]) },
		"IPv6 answer": func(m *dnsmessage.Message) {
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1}}})
		},
		"IPv6 additional": func(m *dnsmessage.Message) {
			m.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1}}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed dnsmessage.Message
			if err := changed.Unpack(response); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := validateDNSResponse(query, packDNSFixture(t, changed)); err == nil {
				t.Fatal("mismatched response accepted")
			}
		})
	}
	for name, raw := range map[string][]byte{"trailing": append(bytes.Clone(response), 0), "oversized": make([]byte, 4097), "truncated": response[:len(response)-1]} {
		t.Run(name, func(t *testing.T) {
			if err := validateDNSResponse(query, raw); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
	// A declared five-byte A record must not swallow another field or padding.
	var aOnly dnsmessage.Message
	if err := aOnly.Unpack(query); err != nil {
		t.Fatal(err)
	}
	aOnly.Response = true
	aOnly.Answers = msg.Answers[1:]
	badA := append(packDNSFixture(t, aOnly), 0)
	binary.BigEndian.PutUint16(badA[len(badA)-7:len(badA)-5], 5)
	if err := validateDNSResponse(query, badA); err == nil {
		t.Fatal("bad A RDATA length accepted")
	}
	tooMany := aOnly
	tooMany.Answers = make([]dnsmessage.Resource, 129)
	for i := range tooMany.Answers {
		tooMany.Answers[i] = msg.Answers[1]
	}
	if err := validateDNSResponse(query, packDNSFixture(t, tooMany)); err == nil {
		t.Fatal("record count limit not enforced")
	}
	// DNS wire labels use ASCII case folding; Unicode lookalikes cannot match.
	aOnly.Questions[0].Name = dnsmessage.MustNewName("k.example.")
	asciiQuery := aOnly
	asciiQuery.Response = false
	asciiQuery.Answers = nil
	asciiRaw := packDNSFixture(t, asciiQuery)
	aOnly.Questions[0].Name = dnsmessage.MustNewName("\u212A.example.")
	if err := validateDNSResponse(asciiRaw, packDNSFixture(t, aOnly)); err == nil {
		t.Fatal("Unicode case-folded response name accepted")
	}
}

func TestAAAAProducesEmptySuccessfulAnswer(t *testing.T) {
	query := dnsQueryFixture(t, dnsmessage.TypeAAAA)
	answer, err := emptyAAAAAnswer(query)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDNSResponse(query, answer); err != nil {
		t.Fatal(err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(answer); err != nil {
		t.Fatal(err)
	}
	if !msg.Response || msg.ID != 0x1234 || msg.RCode != dnsmessage.RCodeSuccess || msg.Truncated || len(msg.Answers) != 0 || len(msg.Authorities) != 0 || len(msg.Questions) != 1 || msg.Questions[0].Type != dnsmessage.TypeAAAA {
		t.Fatalf("invalid empty AAAA answer: %+v", msg)
	}
	if _, err := emptyAAAAAnswer(dnsQueryFixture(t, dnsmessage.TypeA)); err == nil {
		t.Fatal("non-AAAA query accepted")
	}
}

func TestDNSRejectsForbiddenServiceTargetCompression(t *testing.T) {
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeSRV, dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS} {
		query := dnsQueryFixture(t, typ)
		var msg dnsmessage.Message
		if err := msg.Unpack(query); err != nil {
			t.Fatal(err)
		}
		msg.Response = true
		prefix := []byte{0, 0}
		if typ == dnsmessage.TypeSRV {
			prefix = make([]byte, 6)
		}
		msg.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: msg.Questions[0].Name, Class: dnsmessage.ClassINET}, Body: &dnsmessage.UnknownResource{Type: typ, Data: append(prefix, 0xc0, 0x0c)}}}
		if err := validateDNSResponse(query, packDNSFixture(t, msg)); err == nil {
			t.Fatalf("compressed target allowed for type %d", typ)
		}
	}
}

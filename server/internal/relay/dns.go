package relay

import (
	"encoding/binary"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxDNSMessage = 4096
	maxDNSRecords = 128
)

// DNSQuestion identifies the original IN question, independent of DNS aliases.
type DNSQuestion struct {
	Name string
	Type uint16
	ID   uint16
}

// validateDNSQuery accepts one resolution operation, never DNS updates,
// transfers or arbitrary records to be sent to a caller-selected socket.
func validateDNSQuery(raw []byte) (DNSQuestion, error) {
	m, err := readDNSMessage(raw)
	if err != nil {
		return DNSQuestion{}, err
	}
	if m.Response || m.OpCode != 0 || m.RCode != dnsmessage.RCodeSuccess || m.Authoritative || m.Truncated || m.RecursionAvailable || len(m.Answers) != 0 || len(m.Authorities) != 0 || len(m.Additionals) > 1 {
		return DNSQuestion{}, badProtocol("invalid DNS resolution query")
	}
	q := m.Questions[0]
	if q.Class != dnsmessage.ClassINET || !dnsResolutionType(q.Type) {
		return DNSQuestion{}, badProtocol("unsupported DNS question")
	}
	for _, r := range m.Additionals {
		if err := validateDNSOPT(r, true); err != nil {
			return DNSQuestion{}, err
		}
	}
	name, err := dnsQuestionName(q.Name)
	if err != nil {
		return DNSQuestion{}, err
	}
	return DNSQuestion{Name: name, Type: uint16(q.Type), ID: m.ID}, nil
}

func dnsQuestionName(name dnsmessage.Name) (string, error) {
	text := name.String()
	for _, c := range text {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return "", badProtocol("DNS question must use ASCII DNS labels")
		}
	}
	if text == "." {
		return text, nil
	}
	return strings.TrimSuffix(strings.ToLower(text), "."), nil
}

func dnsResolutionType(typ dnsmessage.Type) bool {
	switch typ {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeCNAME, dnsmessage.TypeNS, dnsmessage.TypeSOA, dnsmessage.TypePTR, dnsmessage.TypeMX, dnsmessage.TypeTXT, dnsmessage.TypeSRV, dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		return true
	}
	return false
}

// validateDNSResponse binds a bounded response to its original question.
// The caller forwards the original bytes, preserving IPv4, CNAME and TTL data.
func validateDNSResponse(query, response []byte) error {
	original, err := validateDNSQuery(query)
	if err != nil {
		return err
	}
	m, err := readDNSMessage(response)
	if err != nil {
		return err
	}
	q := m.Questions[0]
	name, err := dnsQuestionName(q.Name)
	if err != nil {
		return err
	}
	if !m.Response || m.OpCode != 0 || m.ID != original.ID || q.Class != dnsmessage.ClassINET || uint16(q.Type) != original.Type || name != original.Name {
		return badProtocol("DNS response does not match question")
	}
	optCount := 0
	for section, records := range [][]dnsmessage.Resource{m.Answers, m.Authorities, m.Additionals} {
		for _, r := range records {
			if r.Header.Type == dnsmessage.TypeOPT {
				optCount++
				if section != 2 || optCount > 1 {
					return badProtocol("invalid DNS OPT placement")
				}
				if err := validateDNSOPT(r, false); err != nil {
					return err
				}
				continue
			}
			if r.Header.Class != dnsmessage.ClassINET || r.Header.Type == dnsmessage.TypeAAAA || r.Header.Type == 251 || r.Header.Type == 252 || r.Header.Type == 255 {
				return badProtocol("unsupported DNS response record")
			}
		}
	}
	return nil
}

func emptyAAAAAnswer(query []byte) ([]byte, error) {
	q, err := validateDNSQuery(query)
	if err != nil {
		return nil, err
	}
	if q.Type != uint16(dnsmessage.TypeAAAA) {
		return nil, badProtocol("empty DNS answer requires AAAA question")
	}
	m, err := readDNSMessage(query)
	if err != nil {
		return nil, err
	}
	answer := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: m.ID, Response: true, RecursionDesired: m.RecursionDesired, RecursionAvailable: true, CheckingDisabled: m.CheckingDisabled},
		Questions: m.Questions,
	}
	for _, r := range m.Additionals {
		r.Body = &dnsmessage.OPTResource{}
		answer.Additionals = append(answer.Additionals, r)
	}
	return answer.Pack()
}

func validateDNSOPT(r dnsmessage.Resource, query bool) error {
	opt, ok := r.Body.(*dnsmessage.OPTResource)
	if !ok || r.Header.Type != dnsmessage.TypeOPT || r.Header.Name.String() != "." || r.Header.Class < 512 || r.Header.Class > maxDNSMessage || r.Header.TTL&0x00ff7fff != 0 || query && r.Header.TTL>>24 != 0 || len(opt.Options) > 16 {
		return badProtocol("invalid EDNS0 record")
	}
	for _, option := range opt.Options {
		if len(option.Data) > 512 {
			return badProtocol("EDNS0 option too large")
		}
		if !query {
			continue
		}
		switch option.Code {
		case 10: // DNS COOKIE: eight-byte client cookie, optional server cookie.
			if len(option.Data) != 8 && (len(option.Data) < 16 || len(option.Data) > 40) {
				return badProtocol("invalid DNS cookie")
			}
		case 12: // PADDING carries no application payload.
			for _, b := range option.Data {
				if b != 0 {
					return badProtocol("invalid DNS padding")
				}
			}
		default:
			return badProtocol("unsupported EDNS0 query option")
		}
	}
	return nil
}

// dnsmessage validates DNS content but accepts trailing bytes and does not
// require fixed/name RDATA parsers to consume exactly the declared length.
func readDNSMessage(raw []byte) (dnsmessage.Message, error) {
	var m dnsmessage.Message
	if len(raw) < 12 || len(raw) > maxDNSMessage || raw[3]&0x40 != 0 || binary.BigEndian.Uint16(raw[4:6]) != 1 {
		return m, badProtocol("invalid DNS message size or header")
	}
	count := 0
	for _, off := range []int{6, 8, 10} {
		count += int(binary.BigEndian.Uint16(raw[off : off+2]))
	}
	if count > maxDNSRecords {
		return m, badProtocol("too many DNS records")
	}
	names := make(map[int]bool)
	off, err := dnsNameEnd(raw, 12, names, true)
	if err != nil || off+4 > len(raw) {
		return m, badProtocol("invalid DNS question name")
	}
	off += 4
	for i := 0; i < count; i++ {
		off, err = dnsNameEnd(raw, off, names, true)
		if err != nil || off+10 > len(raw) {
			return m, badProtocol("invalid DNS resource header")
		}
		typ := dnsmessage.Type(binary.BigEndian.Uint16(raw[off : off+2]))
		length := int(binary.BigEndian.Uint16(raw[off+8 : off+10]))
		off += 10
		end := off + length
		if end > len(raw) {
			return m, badProtocol("invalid DNS resource length")
		}
		pos := off
		switch typ {
		case dnsmessage.TypeA:
			pos += 4
		case dnsmessage.TypeAAAA:
			pos += 16
		case dnsmessage.TypeMX:
			pos += 2
			fallthrough
		case dnsmessage.TypeCNAME, dnsmessage.TypeNS, dnsmessage.TypePTR:
			pos, err = dnsNameEnd(raw, pos, names, true)
		case dnsmessage.TypeSRV:
			pos, err = dnsNameEnd(raw, pos+6, names, false)
		case dnsmessage.TypeSOA:
			pos, err = dnsNameEnd(raw, pos, names, true)
			if err == nil {
				pos, err = dnsNameEnd(raw, pos, names, true)
			}
			pos += 20
		case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
			pos, err = dnsNameEnd(raw, pos+2, names, false)
			if pos > end {
				err = badProtocol("invalid DNS service binding")
			}
			pos = end // dnsmessage validates the remaining service parameters.
		case dnsmessage.TypeOPT:
			for pos < end {
				if pos+4 > end {
					err = badProtocol("invalid DNS option length")
					break
				}
				pos += 4 + int(binary.BigEndian.Uint16(raw[pos+2:pos+4]))
			}
		default:
			pos = end // Variable and unknown DNS records remain bounded by RDLENGTH.
		}
		if err != nil || pos != end {
			return m, badProtocol("invalid DNS resource data")
		}
		off = end
	}
	if off != len(raw) {
		return m, badProtocol("trailing DNS message bytes")
	}
	if err := m.Unpack(raw); err != nil {
		return dnsmessage.Message{}, badProtocol("malformed DNS message")
	}
	return m, nil
}

func dnsNameEnd(raw []byte, off int, names map[int]bool, compression bool) (int, error) {
	for off < len(raw) {
		names[off] = true
		length := int(raw[off])
		switch length & 0xc0 {
		case 0:
			off++
			if length == 0 {
				return off, nil
			}
			off += length
		case 0xc0:
			if !compression {
				return 0, badProtocol("forbidden DNS target compression")
			}
			if off+1 >= len(raw) {
				return 0, badProtocol("truncated DNS pointer")
			}
			target := int(binary.BigEndian.Uint16(raw[off:off+2]) & 0x3fff)
			if target >= off || !names[target] {
				return 0, badProtocol("invalid DNS compression pointer")
			}
			return off + 2, nil
		default:
			return 0, badProtocol("invalid DNS label encoding")
		}
	}
	return 0, badProtocol("truncated DNS name")
}

package katapult

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/libdns/libdns"
)

var errUnsupportedRecordType = errors.New("unsupported record type")

// DNSRecord represents a DNS record in the API response.
type DNSRecord struct {
	ID                string            `json:"id"`
	Type              string            `json:"type"`
	Name              string            `json:"name"`
	FullName          string            `json:"full_name"`
	TTL               int               `json:"ttl"`
	Priority          uint16            `json:"priority"`
	Content           string            `json:"content"`
	ContentAttributes ContentAttributes `json:"content_attributes"`
}

// ContentAttributes holds the structured content of a record, keyed by record type.
// Only one field is populated, matching the record's type.
type ContentAttributes struct {
	A     *AddressContent  `json:"A,omitempty"`
	AAAA  *AddressContent  `json:"AAAA,omitempty"`
	CAA   *CAAContent      `json:"CAA,omitempty"`
	CNAME *HostnameContent `json:"CNAME,omitempty"`
	MX    *HostnameContent `json:"MX,omitempty"`
	NS    *HostnameContent `json:"NS,omitempty"`
	SRV   *SRVContent      `json:"SRV,omitempty"`
	TXT   *TXTContent      `json:"TXT,omitempty"`
}

type AddressContent struct {
	IPAddress string `json:"ip_address"`
}

type HostnameContent struct {
	Hostname string `json:"hostname"`
}

type TXTContent struct {
	Content string `json:"content"`
}

type CAAContent struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

type SRVContent struct {
	Weight uint16 `json:"weight"`
	Port   uint16 `json:"port"`
	Target string `json:"target"`
}

// DNSRecordAPIResponse represents an API response for a DNS record.
type DNSRecordAPIResponse struct {
	DNSRecord DNSRecord `json:"dns_record"`
}

// DNSRecordsAPIResponse represents an API response of DNS records.
type DNSRecordsAPIResponse struct {
	DNSRecords []DNSRecord `json:"dns_records"`
}

// DeletionAPIResponse represents an API response for a deletion.
type DeletionAPIResponse struct {
	Deleted bool `json:"deleted"`
}

// recordProperties is the request body for creating or updating a record.
type recordProperties struct {
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	TTL      *int           `json:"ttl,omitempty"`
	Priority *uint16        `json:"priority,omitempty"`
	Content  map[string]any `json:"content"`
}

// toLibDNSRecord converts a Katapult record to the matching libdns record type.
// Katapult-specific types (ALIAS, IPS, VirtualMachine etc.) are returned as a libdns.RR.
func toLibDNSRecord(r DNSRecord, zone string) libdns.Record {
	name := relativeName(r, zone)
	ttl := time.Duration(r.TTL) * time.Second
	attrs := r.ContentAttributes

	switch {
	case r.Type == "A" && attrs.A != nil:
		if ip, err := netip.ParseAddr(attrs.A.IPAddress); err == nil {
			return libdns.Address{Name: name, TTL: ttl, IP: ip, ProviderData: r.ID}
		}
	case r.Type == "AAAA" && attrs.AAAA != nil:
		if ip, err := netip.ParseAddr(attrs.AAAA.IPAddress); err == nil {
			return libdns.Address{Name: name, TTL: ttl, IP: ip, ProviderData: r.ID}
		}
	case r.Type == "CAA" && attrs.CAA != nil:
		return libdns.CAA{Name: name, TTL: ttl, Flags: attrs.CAA.Flag, Tag: attrs.CAA.Tag, Value: attrs.CAA.Value, ProviderData: r.ID}
	case r.Type == "CNAME" && attrs.CNAME != nil:
		return libdns.CNAME{Name: name, TTL: ttl, Target: attrs.CNAME.Hostname, ProviderData: r.ID}
	case r.Type == "MX" && attrs.MX != nil:
		return libdns.MX{Name: name, TTL: ttl, Preference: r.Priority, Target: attrs.MX.Hostname, ProviderData: r.ID}
	case r.Type == "NS" && attrs.NS != nil:
		return libdns.NS{Name: name, TTL: ttl, Target: attrs.NS.Hostname, ProviderData: r.ID}
	case r.Type == "SRV" && attrs.SRV != nil:
		// Leave Service/Transport empty so the underscored name is used as-is.
		return libdns.SRV{Name: name, TTL: ttl, Priority: r.Priority, Weight: attrs.SRV.Weight, Port: attrs.SRV.Port, Target: attrs.SRV.Target, ProviderData: r.ID}
	case r.Type == "TXT" && attrs.TXT != nil:
		return libdns.TXT{Name: name, TTL: ttl, Text: attrs.TXT.Content, ProviderData: r.ID}
	}

	return libdns.RR{Name: name, TTL: ttl, Type: r.Type, Data: r.Content}
}

// toRecordProperties converts a libdns record to a Katapult create/update request body.
func toRecordProperties(record libdns.Record) (recordProperties, error) {
	rr := record.RR()
	parsed, err := rr.Parse()
	if err != nil {
		return recordProperties{}, err
	}

	props := recordProperties{
		Name: apiName(rr.Name),
		Type: rr.Type,
		TTL:  ensureValidTTL(rr.TTL),
	}

	var content any
	switch rec := parsed.(type) {
	case libdns.Address:
		content = AddressContent{IPAddress: rec.IP.String()}
	case libdns.CAA:
		content = CAAContent{Flag: rec.Flags, Tag: rec.Tag, Value: rec.Value}
	case libdns.CNAME:
		content = HostnameContent{Hostname: rec.Target}
	case libdns.MX:
		props.Priority = &rec.Preference
		content = HostnameContent{Hostname: rec.Target}
	case libdns.NS:
		content = HostnameContent{Hostname: rec.Target}
	case libdns.SRV:
		props.Priority = &rec.Priority
		content = SRVContent{Weight: rec.Weight, Port: rec.Port, Target: rec.Target}
	case libdns.TXT:
		content = TXTContent{Content: rec.Text}
	default:
		return recordProperties{}, fmt.Errorf("%w: %s", errUnsupportedRecordType, rr.Type)
	}

	props.Content = map[string]any{rr.Type: content}
	return props, nil
}

// relativeName returns the libdns-style name ("@" for the apex) for a Katapult record.
func relativeName(r DNSRecord, zone string) string {
	if r.FullName != "" {
		return libdns.RelativeName(r.FullName, zone)
	}
	if r.Name == "" {
		return "@"
	}
	return r.Name
}

// apiName converts a libdns name to the form Katapult expects, where the apex is blank.
func apiName(name string) string {
	if name == "@" {
		return ""
	}
	return name
}

func ensureValidTTL(rawTTL time.Duration) *int {
	ttl := int(rawTTL.Seconds())
	if ttl == 0 {
		return nil
	} else if ttl < 60 {
		minTTL := 60
		return &minTTL
	}
	return &ttl
}

package katapult

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

const testZone = "example.com."

// fakeKatapult is an in-memory stand-in for the parts of the Katapult DNS API the provider uses.
type fakeKatapult struct {
	mu      sync.Mutex
	nextID  int
	records []DNSRecord
	calls   []string
}

func newFakeKatapult(t *testing.T, records ...DNSRecord) *fakeKatapult {
	t.Helper()

	f := &fakeKatapult{records: records, nextID: 100}
	server := httptest.NewServer(f)
	t.Cleanup(server.Close)

	previous := baseURL
	baseURL = server.URL
	t.Cleanup(func() { baseURL = previous })

	return f
}

func (f *fakeKatapult) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, r.Method)

	if r.Header.Get("Authorization") != "Bearer token" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusForbidden)
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/dns_zones/_/records":
		if got := r.URL.Query().Get("dns_zone[name]"); got != "example.com" {
			http.Error(w, "unknown zone "+got, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(DNSRecordsAPIResponse{DNSRecords: f.records})

	case r.Method == http.MethodPost && r.URL.Path == "/dns_zones/_/records":
		var body struct {
			Properties struct {
				Name     string                     `json:"name"`
				Type     string                     `json:"type"`
				TTL      *int                       `json:"ttl"`
				Priority *uint16                    `json:"priority"`
				Content  map[string]json.RawMessage `json:"content"`
			} `json:"properties"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		props := body.Properties

		f.nextID++
		record := DNSRecord{
			ID:       fmt.Sprintf("dnsrec_%d", f.nextID),
			Type:     props.Type,
			Name:     props.Name,
			FullName: strings.TrimPrefix(props.Name+".example.com", "."),
			TTL:      3600,
		}
		if props.TTL != nil {
			record.TTL = *props.TTL
		}
		if props.Priority != nil {
			record.Priority = *props.Priority
		}

		// Content attributes are returned in the same shape they're sent.
		attrs, _ := json.Marshal(props.Content)
		if err := json.Unmarshal(attrs, &record.ContentAttributes); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f.records = append(f.records, record)
		json.NewEncoder(w).Encode(DNSRecordAPIResponse{DNSRecord: record})

	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/dns_records/"):
		id := strings.TrimPrefix(r.URL.Path, "/dns_records/")
		for i, record := range f.records {
			if record.ID == id {
				f.records = append(f.records[:i], f.records[i+1:]...)
				json.NewEncoder(w).Encode(DeletionAPIResponse{Deleted: true})
				return
			}
		}
		http.Error(w, `{"error":"dns_record_not_found"}`, http.StatusNotFound)

	default:
		http.Error(w, "unexpected request "+r.Method+" "+r.URL.Path, http.StatusNotImplemented)
	}
}

func txtRecord(id, name, content string) DNSRecord {
	return DNSRecord{
		ID:                id,
		Type:              "TXT",
		Name:              name,
		FullName:          strings.TrimPrefix(name+".example.com", "."),
		TTL:               60,
		Content:           `"` + content + `"`,
		ContentAttributes: ContentAttributes{TXT: &TXTContent{Content: content}},
	}
}

func rrs(records []libdns.Record) []libdns.RR {
	out := make([]libdns.RR, len(records))
	for i, r := range records {
		out[i] = r.RR()
		out[i].TTL = out[i].TTL.Truncate(time.Second)
	}
	return out
}

func assertRRs(t *testing.T, got []libdns.Record, want ...libdns.RR) {
	t.Helper()

	gotRRs := rrs(got)
	if len(gotRRs) != len(want) {
		t.Fatalf("expected %d records, got %d: %+v", len(want), len(gotRRs), gotRRs)
	}
	for i := range want {
		if gotRRs[i] != want[i] {
			t.Errorf("record %d: expected %+v, got %+v", i, want[i], gotRRs[i])
		}
	}
}

func TestGetRecordsConvertsTypes(t *testing.T) {
	newFakeKatapult(t,
		DNSRecord{ID: "1", Type: "A", Name: "", FullName: "example.com", TTL: 300,
			ContentAttributes: ContentAttributes{A: &AddressContent{IPAddress: "192.0.2.1"}}},
		DNSRecord{ID: "2", Type: "AAAA", Name: "www", FullName: "www.example.com", TTL: 300,
			ContentAttributes: ContentAttributes{AAAA: &AddressContent{IPAddress: "2001:db8::1"}}},
		DNSRecord{ID: "3", Type: "MX", Name: "", FullName: "example.com", TTL: 3600, Priority: 10,
			ContentAttributes: ContentAttributes{MX: &HostnameContent{Hostname: "mail.example.net"}}},
		DNSRecord{ID: "4", Type: "SRV", Name: "_sip._tcp", FullName: "_sip._tcp.example.com", TTL: 3600, Priority: 5,
			ContentAttributes: ContentAttributes{SRV: &SRVContent{Weight: 10, Port: 5060, Target: "sip.example.net"}}},
		DNSRecord{ID: "5", Type: "CAA", Name: "", FullName: "example.com", TTL: 3600,
			ContentAttributes: ContentAttributes{CAA: &CAAContent{Flag: 0, Tag: "issue", Value: "letsencrypt.org"}}},
		DNSRecord{ID: "6", Type: "ALIAS", Name: "", FullName: "example.com", TTL: 3600, Content: "lb.example.net"},
		txtRecord("7", "_acme-challenge", "token"),
	)

	p := &Provider{APIToken: "token"}
	records, err := p.GetRecords(context.Background(), testZone)
	if err != nil {
		t.Fatal(err)
	}

	assertRRs(t, records,
		libdns.RR{Name: "@", TTL: 300 * time.Second, Type: "A", Data: "192.0.2.1"},
		libdns.RR{Name: "www", TTL: 300 * time.Second, Type: "AAAA", Data: "2001:db8::1"},
		libdns.RR{Name: "@", TTL: time.Hour, Type: "MX", Data: "10 mail.example.net"},
		libdns.RR{Name: "_sip._tcp", TTL: time.Hour, Type: "SRV", Data: "5 10 5060 sip.example.net"},
		libdns.RR{Name: "@", TTL: time.Hour, Type: "CAA", Data: `0 issue "letsencrypt.org"`},
		libdns.RR{Name: "@", TTL: time.Hour, Type: "ALIAS", Data: "lb.example.net"},
		libdns.RR{Name: "_acme-challenge", TTL: time.Minute, Type: "TXT", Data: "token"},
	)

	if _, ok := records[0].(libdns.Address); !ok {
		t.Errorf("expected A record to be a libdns.Address, got %T", records[0])
	}
	if id := records[6].(libdns.TXT).ProviderData; id != "7" {
		t.Errorf("expected ProviderData to hold the record ID, got %v", id)
	}
}

func TestAppendRecords(t *testing.T) {
	f := newFakeKatapult(t)
	p := &Provider{APIToken: "token"}

	added, err := p.AppendRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", TTL: 10 * time.Second, Text: "abc"},
		libdns.Address{Name: "@", IP: netip.MustParseAddr("192.0.2.1")},
		libdns.MX{Name: "@", TTL: time.Hour, Preference: 20, Target: "mx.example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}

	assertRRs(t, added,
		libdns.RR{Name: "_acme-challenge", TTL: time.Minute, Type: "TXT", Data: "abc"},
		libdns.RR{Name: "@", TTL: time.Hour, Type: "A", Data: "192.0.2.1"},
		libdns.RR{Name: "@", TTL: time.Hour, Type: "MX", Data: "20 mx.example.net"},
	)

	if f.records[1].Name != "" {
		t.Errorf("expected apex to be sent as a blank name, got %q", f.records[1].Name)
	}
	if f.records[2].Priority != 20 {
		t.Errorf("expected MX priority to be sent, got %d", f.records[2].Priority)
	}
}

func TestAppendRecordsRejectsUnsupportedTypes(t *testing.T) {
	newFakeKatapult(t)
	p := &Provider{APIToken: "token"}

	_, err := p.AppendRecords(context.Background(), testZone, []libdns.Record{
		libdns.RR{Name: "@", Type: "HTTPS", Data: `1 . alpn="h2"`},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported record type") {
		t.Fatalf("expected unsupported record type error, got %v", err)
	}
}

func TestSetRecordsReplacesOnlyMatchingNameAndType(t *testing.T) {
	f := newFakeKatapult(t,
		txtRecord("1", "_acme-challenge", "old"),
		txtRecord("2", "_acme-challenge", "keep"),
		txtRecord("3", "other", "untouched"),
		DNSRecord{ID: "4", Type: "CNAME", Name: "_acme-challenge", FullName: "_acme-challenge.example.com", TTL: 60,
			ContentAttributes: ContentAttributes{CNAME: &HostnameContent{Hostname: "elsewhere.example.net"}}},
	)
	p := &Provider{APIToken: "token"}

	set, err := p.SetRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", TTL: time.Minute, Text: "keep"},
		libdns.TXT{Name: "_acme-challenge", TTL: time.Minute, Text: "new"},
	})
	if err != nil {
		t.Fatal(err)
	}

	assertRRs(t, set,
		libdns.RR{Name: "_acme-challenge", TTL: time.Minute, Type: "TXT", Data: "keep"},
		libdns.RR{Name: "_acme-challenge", TTL: time.Minute, Type: "TXT", Data: "new"},
	)

	remaining, _ := p.GetRecords(context.Background(), testZone)
	assertRRs(t, remaining,
		libdns.RR{Name: "_acme-challenge", TTL: time.Minute, Type: "TXT", Data: "keep"},
		libdns.RR{Name: "other", TTL: time.Minute, Type: "TXT", Data: "untouched"},
		libdns.RR{Name: "_acme-challenge", TTL: time.Minute, Type: "CNAME", Data: "elsewhere.example.net"},
		libdns.RR{Name: "_acme-challenge", TTL: time.Minute, Type: "TXT", Data: "new"},
	)

	if f.records[0].ID != "2" {
		t.Errorf("expected the unchanged record to be kept rather than recreated, got ID %s", f.records[0].ID)
	}
}

func TestDeleteRecordsMatching(t *testing.T) {
	newFakeKatapult(t,
		txtRecord("1", "_acme-challenge", "one"),
		txtRecord("2", "_acme-challenge", "two"),
		txtRecord("3", "www", "three"),
	)
	p := &Provider{APIToken: "token"}

	deleted, err := p.DeleteRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "one"},
		libdns.TXT{Name: "_acme-challenge", Text: "missing"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertRRs(t, deleted, libdns.RR{Name: "_acme-challenge", TTL: time.Minute, Type: "TXT", Data: "one"})

	// An empty type and value act as wildcards.
	deleted, err = p.DeleteRecords(context.Background(), testZone, []libdns.Record{
		libdns.RR{Name: "www"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertRRs(t, deleted, libdns.RR{Name: "www", TTL: time.Minute, Type: "TXT", Data: "three"})

	remaining, _ := p.GetRecords(context.Background(), testZone)
	assertRRs(t, remaining, libdns.RR{Name: "_acme-challenge", TTL: time.Minute, Type: "TXT", Data: "two"})
}

func TestDeleteRecordsRespectsTTL(t *testing.T) {
	newFakeKatapult(t, txtRecord("1", "_acme-challenge", "one"))
	p := &Provider{APIToken: "token"}

	deleted, err := p.DeleteRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", TTL: time.Hour, Text: "one"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 0 {
		t.Fatalf("expected no records deleted when TTL differs, got %+v", rrs(deleted))
	}
}

func TestAPIErrorsAreReturned(t *testing.T) {
	newFakeKatapult(t)
	p := &Provider{APIToken: "wrong"}

	_, err := p.GetRecords(context.Background(), testZone)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected a 403 error, got %v", err)
	}
}

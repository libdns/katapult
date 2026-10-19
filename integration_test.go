//go:build integration

package katapult

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// Runs against the real Katapult API. Use a test zone: records under the
// "libdns-test" names are created and removed.
//
//	LIBDNS_KATAPULT_API_TOKEN=... LIBDNS_KATAPULT_ZONE=example.com go test -tags integration -run Integration -v
func TestIntegration(t *testing.T) {
	token := os.Getenv("LIBDNS_KATAPULT_API_TOKEN")
	zone := os.Getenv("LIBDNS_KATAPULT_ZONE")
	if token == "" || zone == "" {
		t.Skip("LIBDNS_KATAPULT_API_TOKEN and LIBDNS_KATAPULT_ZONE must be set")
	}
	zone = libdns.AbsoluteName(zone, "") + "."

	ctx := context.Background()
	p := &Provider{APIToken: token}
	const name = "_acme-challenge.libdns-test"

	cleanup := func() {
		if _, err := p.DeleteRecords(ctx, zone, []libdns.Record{libdns.RR{Name: name}, libdns.RR{Name: "libdns-test"}}); err != nil {
			t.Errorf("cleanup failed: %v", err)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	t.Run("GetRecords", func(t *testing.T) {
		records, err := p.GetRecords(ctx, zone)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range records {
			t.Logf("%T %+v", r, r.RR())
		}
	})

	t.Run("AppendRecords", func(t *testing.T) {
		added, err := p.AppendRecords(ctx, zone, []libdns.Record{
			libdns.TXT{Name: name, TTL: time.Minute, Text: "first"},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertRRs(t, added, libdns.RR{Name: name, TTL: time.Minute, Type: "TXT", Data: "first"})
	})

	// Tokens restricted to ACME challenges can only manage _acme-challenge TXT records.
	t.Run("AppendOtherTypes", func(t *testing.T) {
		added, err := p.AppendRecords(ctx, zone, []libdns.Record{
			libdns.MX{Name: "libdns-test", TTL: time.Hour, Preference: 15, Target: "mail.example.net"},
			libdns.CAA{Name: "libdns-test", TTL: time.Hour, Tag: "issue", Value: "letsencrypt.org"},
		})
		if err != nil && strings.Contains(err.Error(), "permission_denied") {
			t.Skip("token is not permitted to create non-ACME records")
		}
		if err != nil {
			t.Fatal(err)
		}
		assertRRs(t, added,
			libdns.RR{Name: "libdns-test", TTL: time.Hour, Type: "MX", Data: "15 mail.example.net"},
			libdns.RR{Name: "libdns-test", TTL: time.Hour, Type: "CAA", Data: `0 issue "letsencrypt.org"`},
		)
	})

	t.Run("SetRecords", func(t *testing.T) {
		set, err := p.SetRecords(ctx, zone, []libdns.Record{
			libdns.TXT{Name: name, TTL: time.Minute, Text: "second"},
			libdns.TXT{Name: name, TTL: time.Minute, Text: "third"},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertRRs(t, set,
			libdns.RR{Name: name, TTL: time.Minute, Type: "TXT", Data: "second"},
			libdns.RR{Name: name, TTL: time.Minute, Type: "TXT", Data: "third"},
		)

		assertRRs(t, recordsNamed(t, p, zone, name),
			libdns.RR{Name: name, TTL: time.Minute, Type: "TXT", Data: "second"},
			libdns.RR{Name: name, TTL: time.Minute, Type: "TXT", Data: "third"},
		)
	})

	t.Run("DeleteRecords", func(t *testing.T) {
		deleted, err := p.DeleteRecords(ctx, zone, []libdns.Record{libdns.TXT{Name: name, Text: "second"}})
		if err != nil {
			t.Fatal(err)
		}
		assertRRs(t, deleted, libdns.RR{Name: name, TTL: time.Minute, Type: "TXT", Data: "second"})

		assertRRs(t, recordsNamed(t, p, zone, name),
			libdns.RR{Name: name, TTL: time.Minute, Type: "TXT", Data: "third"},
		)
	})
}

func recordsNamed(t *testing.T, p *Provider, zone, name string) []libdns.Record {
	t.Helper()

	all, err := p.GetRecords(context.Background(), zone)
	if err != nil {
		t.Fatal(err)
	}
	var matching []libdns.Record
	for _, r := range all {
		if r.RR().Name == name {
			matching = append(matching, r)
		}
	}
	return matching
}

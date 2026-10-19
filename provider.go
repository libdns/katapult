package katapult

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with Katapult.
//
// None of the operations are atomic: Katapult has no batch API, so a failure part way
// through SetRecords or DeleteRecords can leave some changes applied.
type Provider struct {
	APIToken string `json:"api_token,omitempty"`
}

var errFailedToDeleteRecord = errors.New("failed to delete record")

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	existing, err := p.getRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	records := make([]libdns.Record, 0, len(existing))
	for _, record := range existing {
		records = append(records, toLibDNSRecord(record, zone))
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var added []libdns.Record

	for _, record := range records {
		created, err := p.createRecord(ctx, zone, record)
		if err != nil {
			return added, err
		}
		added = append(added, created)
	}

	return added, nil
}

// SetRecords ensures that, for each (name, type) pair in the input, the zone's records
// with that pair are exactly those provided. It returns the records that were set.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	existing, err := p.getRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	type nameType struct{ name, recType string }
	inputPairs := map[nameType]bool{}
	for _, record := range records {
		rr := record.RR()
		inputPairs[nameType{rr.Name, rr.Type}] = true
	}

	var toDelete []DNSRecord
	unchanged := map[int]libdns.Record{}

	for _, ex := range existing {
		exRecord := toLibDNSRecord(ex, zone)
		exRR := exRecord.RR()
		if !inputPairs[nameType{exRR.Name, exRR.Type}] {
			continue
		}

		kept := false
		for i, record := range records {
			if _, done := unchanged[i]; !done && recordsEqual(exRR, record.RR()) {
				unchanged[i] = exRecord
				kept = true
				break
			}
		}
		if !kept {
			toDelete = append(toDelete, ex)
		}
	}

	// Delete first so that replacing a CNAME doesn't conflict with the old one.
	for _, ex := range toDelete {
		if err := p.deleteRecord(ctx, ex.ID); err != nil {
			return nil, err
		}
	}

	var set []libdns.Record
	for i, record := range records {
		if ex, ok := unchanged[i]; ok {
			set = append(set, ex)
			continue
		}
		created, err := p.createRecord(ctx, zone, record)
		if err != nil {
			return set, err
		}
		set = append(set, created)
	}

	return set, nil
}

// DeleteRecords deletes records from the zone that match the input. Type, TTL and value
// may be left empty to match any. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	existing, err := p.getRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	var deleted []libdns.Record
	for _, ex := range existing {
		exRecord := toLibDNSRecord(ex, zone)
		for _, record := range records {
			if !recordMatches(exRecord.RR(), record.RR()) {
				continue
			}
			if err := p.deleteRecord(ctx, ex.ID); err != nil {
				return deleted, err
			}
			deleted = append(deleted, exRecord)
			break
		}
	}

	return deleted, nil
}

func (p *Provider) getRecords(ctx context.Context, zone string) ([]DNSRecord, error) {
	path := "/dns_zones/_/records?dns_zone[name]=" + url.QueryEscape(RemoveTrailingDot(zone))

	var apiResponse DNSRecordsAPIResponse
	if err := p.DoRequest(ctx, http.MethodGet, path, nil, &apiResponse); err != nil {
		return nil, err
	}

	return apiResponse.DNSRecords, nil
}

func (p *Provider) createRecord(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	properties, err := toRecordProperties(record)
	if err != nil {
		return nil, err
	}

	requestBody := map[string]any{
		"dns_zone":   map[string]string{"name": RemoveTrailingDot(zone)},
		"properties": properties,
	}

	var apiResponse DNSRecordAPIResponse
	if err := p.DoRequest(ctx, http.MethodPost, "/dns_zones/_/records", requestBody, &apiResponse); err != nil {
		return nil, err
	}

	return toLibDNSRecord(apiResponse.DNSRecord, zone), nil
}

func (p *Provider) deleteRecord(ctx context.Context, id string) error {
	var apiResponse DeletionAPIResponse
	if err := p.DoRequest(ctx, http.MethodDelete, "/dns_records/"+url.PathEscape(id), nil, &apiResponse); err != nil {
		return err
	}
	if !apiResponse.Deleted {
		return fmt.Errorf("%w: %s", errFailedToDeleteRecord, id)
	}
	return nil
}

// recordsEqual reports whether two records are identical in name, type, TTL and value.
func recordsEqual(a, b libdns.RR) bool {
	return a.Name == b.Name && a.Type == b.Type && ttlEqual(a, b) && a.Data == b.Data
}

// recordMatches reports whether an existing record matches a deletion filter, where an
// empty type, zero TTL or empty value in the filter matches anything.
func recordMatches(existing, filter libdns.RR) bool {
	return existing.Name == filter.Name &&
		(filter.Type == "" || existing.Type == filter.Type) &&
		(filter.TTL == 0 || ttlEqual(existing, filter)) &&
		(filter.Data == "" || existing.Data == filter.Data)
}

// ttlEqual compares TTLs after applying the same rounding Katapult does on write.
// A zero TTL means "use the default" so it matches whatever the existing record has.
func ttlEqual(existing, input libdns.RR) bool {
	want := ensureValidTTL(input.TTL)
	return want == nil || int(existing.TTL.Seconds()) == *want
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)

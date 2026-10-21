package carrel

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// A record's fields in alphabetical order encode like its map even where
// encoded() is bypassed, such as the MCP SDK's structured content.
func TestRecordFieldsAreSorted(t *testing.T) {
	for _, record := range []any{sshKey{}, certificateRecord{}, storageUsage{}, guestReport{}, portGrant{}, peerGrant{}, domainRecord{}, snapshotRecord{}, vipRecord{}, cloudInitRecord{}, imageRecord{}} {
		typ := reflect.TypeOf(record)
		names := []string{}
		for i := range typ.NumField() {
			names = append(names, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
		}
		if !sort.StringsAreSorted(names) {
			t.Errorf("%s fields are not in JSON name order: %v", typ.Name(), names)
		}
	}
}

func TestRecordsReadTheirRows(t *testing.T) {
	p, _ := fixture(t)
	p.Store.Put("guest_reports", 10100, 1, D{"vmid": 10100, "boot_id": "b", "reported_at": 1.5, "failed_step": nil, "checks": []D{}, "interfaces": []D{{"mac": "m", "ip": "i", "mtu": 1450}}, "initialization_status": "complete", "application_status": "healthy"})
	r := p.Store.guestReport(10100)
	if r.BootID != "b" || *r.ReportedAt != 1.5 || r.FailedStep != nil || r.Checks == nil || len(r.Interfaces) != 1 {
		t.Fatalf("%+v", r)
	}
	if missing := p.Store.guestReport(10199); missing.ReportedAt != nil || missing.BootID != "" {
		t.Fatalf("%+v", missing)
	}
	if got := roundTrip[guestReport](string(encoded(p.Store.Get("guest_reports", "10100")))); got != string(encoded(p.Store.Get("guest_reports", "10100"))) {
		t.Fatal(got)
	}
}

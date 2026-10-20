package carrel

import "encoding/json"

// Stored records. Each lists its JSON fields in alphabetical order, so it
// encodes exactly like its map form. TestGolden and TestLiveRows hold the
// bytes; TestRecordFieldsAreSorted holds the order.

type sshKey struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

type certificateRecord struct {
	ID       string `json:"id"`
	IssuedAt int64  `json:"issued_at,omitempty"`
	Slug     string `json:"slug"`
	TenantN  int    `json:"tenant_n"`
}

// storageUsage is a tenant's snapshot storage, added across nodes.
type storageUsage struct {
	Accounting            string  `json:"accounting"`
	Available             bool    `json:"available"`
	OperationID           string  `json:"operation_id,omitempty"`
	RetainedSnapshotBytes int64   `json:"retained_snapshot_bytes"`
	SampledAt             float64 `json:"sampled_at"`
	TenantN               int     `json:"tenant_n"`
	UniqueTotalBytes      int64   `json:"unique_total_bytes"`
}

// guestReport is what the guest reporter last sent. A missing report reads
// as the zero value: no boot, no time, nothing checked.
type guestReport struct {
	ApplicationStatus    string   `json:"application_status"`
	BootID               string   `json:"boot_id"`
	Checks               []D      `json:"checks"`
	FailedStep           *int     `json:"failed_step"`
	InitializationStatus string   `json:"initialization_status"`
	Interfaces           []D      `json:"interfaces"`
	ReportedAt           *float64 `json:"reported_at"`
	VMID                 int      `json:"vmid"`
}

// certificateOf finds the tenant's certificate record.
func certificateOf(s *Store, n int, slug string) (certificateRecord, bool) {
	for _, c := range rowsOf[certificateRecord](s, "certificates", n) {
		if c.Slug == slug {
			return c, true
		}
	}
	return certificateRecord{}, false
}

// recentIssuance lists certificates issued in the last 7 days, the window of
// Let's Encrypt's per-account limits.
func recentIssuance(s *Store) []certificateRecord {
	out := []certificateRecord{}
	for _, c := range rowsOf[certificateRecord](s, "certificates") {
		if float64(c.IssuedAt) > now()-7*86400 {
			out = append(out, c)
		}
	}
	return out
}

func (s *Store) guestReport(vmid any) guestReport {
	r, _ := rowOf[guestReport](s, "guest_reports", str(vmid))
	return r
}

// rowOf reads one stored record as T.
func rowOf[T any](s *Store, kind, id string) (T, bool) {
	var v T
	r := s.Rows("SELECT data FROM objects WHERE kind=? AND id=?", kind, id)
	if len(r) == 0 {
		return v, false
	}
	must(json.Unmarshal([]byte(str(r[0]["data"])), &v))
	return v, true
}

// rowsOf reads a kind's records as T, in ID order, optionally of one tenant.
func rowsOf[T any](s *Store, kind string, tenant ...int) []T {
	out := []T{}
	for _, data := range s.objectData(kind, tenant...) {
		var v T
		must(json.Unmarshal([]byte(data), &v))
		out = append(out, v)
	}
	return out
}

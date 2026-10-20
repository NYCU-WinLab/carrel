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

// portGrant forwards a public port on the exit node to a machine.
type portGrant struct {
	ID          string `json:"id"`
	IP          string `json:"ip"`
	OperationID string `json:"operation_id,omitempty"`
	Port        int    `json:"port"`
	Proto       string `json:"proto"`
	PublicPort  int    `json:"public_port"`
	State       string `json:"state,omitempty"`
	TenantN     int    `json:"tenant_n"`
	VMID        int    `json:"vmid"`
}

// D gives the grant as the map the presentation code takes.
func (g portGrant) D() D { return decode(string(encoded(g))) }

func (e *Execution) ports(n int) []portGrant { return rowsOf[portGrant](e.S, "ports", n) }

// peerGrant lets a source address reach one port of a machine. A deployment
// connection also records both machine names.
type peerGrant struct {
	FromMachine string `json:"from_machine,omitempty"`
	ID          string `json:"id"`
	Machine     string `json:"machine,omitempty"`
	OperationID string `json:"operation_id,omitempty"`
	Port        int    `json:"port"`
	Proto       string `json:"proto,omitempty"`
	Source      string `json:"source"`
	State       string `json:"state,omitempty"`
	Target      string `json:"target"`
	TenantN     int    `json:"tenant_n"`
}

func (g peerGrant) D() D { return decode(string(encoded(g))) }

func (e *Execution) peers(n ...int) []peerGrant { return rowsOf[peerGrant](e.S, "peers", n...) }

// protocol reads grants written before proto was recorded as TCP.
func (g peerGrant) protocol() string { return or(g.Proto, "tcp") }

// domainRecord routes https://<sub>.<slug>.winlab.tw to a machine's port.
type domainRecord struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	OperationID string  `json:"operation_id,omitempty"`
	ReadyAt     float64 `json:"ready_at"`
	Slug        string  `json:"slug"`
	State       string  `json:"state"`
	Sub         string  `json:"sub"`
	TargetPort  int     `json:"target_port"`
	TenantN     int     `json:"tenant_n"`
	VMID        int     `json:"vmid"`
}

func (d domainRecord) D() D { return decode(string(encoded(d))) }

func (e *Execution) domains(n int) []domainRecord {
	return rowsOf[domainRecord](e.S, "domains", n)
}

// domainNamed finds a domain by its full name.
func domainNamed(domains []domainRecord, name string) (domainRecord, bool) {
	for _, d := range domains {
		if d.Name == name {
			return d, true
		}
	}
	return domainRecord{}, false
}

// snapshotRecord is a disk snapshot and the machine configuration it was
// taken with; a rollback needs that configuration unchanged.
type snapshotRecord struct {
	Configuration D      `json:"configuration,omitempty"`
	DiskGB        int    `json:"disk_gb"`
	ID            string `json:"id"`
	Name          string `json:"name"`
	OperationID   string `json:"operation_id,omitempty"`
	State         string `json:"state,omitempty"`
	VMID          int    `json:"vmid"`
}

func (e *Execution) snapshots(n ...int) []snapshotRecord {
	return rowsOf[snapshotRecord](e.S, "snapshots", n...)
}

// ownedBy reports whether a record's operation ID is the running job's.
func (e *Execution) ownedBy(operationID string) bool {
	return e.Op != nil && operationID != "" && operationID == e.Op["id"]
}

// orNil gives nil for an empty text, as a missing field reads.
func orNil(s string) any {
	if s == "" {
		return nil
	}
	return s
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

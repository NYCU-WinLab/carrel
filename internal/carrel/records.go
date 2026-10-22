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

// portGrant forwards a public port on the exit node to a machine, or to a
// virtual address (VIP holds its id, VMID is 0, IP its address; issue #146).
type portGrant struct {
	ID          string `json:"id"`
	IP          string `json:"ip"`
	OperationID string `json:"operation_id,omitempty"`
	Port        int    `json:"port"`
	Proto       string `json:"proto"`
	PublicPort  int    `json:"public_port"`
	State       string `json:"state,omitempty"`
	TenantN     int    `json:"tenant_n"`
	VIP         string `json:"vip,omitempty"`
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

// domainRecord routes https://<sub>.<slug>.winlab.tw to a machine's port, or
// to a port of a virtual address (VIP holds its id, VMID is 0; issue #146).
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
	VIP         string  `json:"vip,omitempty"`
	VMID        int     `json:"vmid"`
}

func (d domainRecord) D() D { return decode(string(encoded(d))) }

// target is the domain_add argument that names the domain's target again.
func (d domainRecord) target() D {
	if d.VIP != "" {
		return D{"vip": d.VIP}
	}
	return D{"machine": str(d.VMID)}
}

func (e *Execution) domains(n int) []domainRecord {
	return rowsOf[domainRecord](e.S, "domains", n)
}

// vipRecord is a virtual address in a tenant network (issue #96): every
// machine in VMIDs may claim it, and software in the guests moves it.
type vipRecord struct {
	Address     string `json:"address"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	OperationID string `json:"operation_id,omitempty"`
	State       string `json:"state,omitempty"`
	TenantN     int    `json:"tenant_n"`
	VMIDs       []int  `json:"vmids"`
}

func (v vipRecord) D() D { return decode(string(encoded(v))) }

func (e *Execution) vips(n int) []vipRecord { return rowsOf[vipRecord](e.S, "vips", n) }

// publishTarget resolves where a public port or domain points: a machine,
// or a virtual address that one of its holders answers for (issue #146).
// Exactly one of machine and vip is given.
func (e *Execution) publishTarget(t, a D) (vmid int, ip string, vip vipRecord) {
	if (a["machine"] == nil) == (a["vip"] == nil) {
		fail("invalid", "Give exactly one of machine and vip", D{"recovery": "revise_request"})
	}
	if a["machine"] != nil {
		m := e.Machine(t, a["machine"])
		return integer(m["vmid"]), str(m["ip"]), vip
	}
	for _, v := range e.vips(integer(t["n"])) {
		if v.Name == a["vip"] || v.ID == a["vip"] {
			if v.State == "deleting" {
				fail("conflict", "This virtual address is being removed", D{"recovery": "revise_request"})
			}
			if len(v.VMIDs) == 0 {
				fail("invalid", "Add a machine to the virtual address with vip_add first", D{"recovery": "resolve_prerequisite"})
			}
			return 0, v.Address, v
		}
	}
	fail("not_found", "Virtual address not found in this tenant")
	return
}

// vipHosts are the host numbers kept for virtual addresses, above every
// machine address (10 + slot, at most 100 machines per tenant).
var vipHosts = []int{251, 252, 253, 254}

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

// cloudInitRecord keeps the exact cloud-init files of a VM (issue #93).
// Proxmox makes the instance id the SHA-1 of these bytes, so the copy a node
// gets back must be these bytes; regenerating them reruns cloud-init.
type cloudInitRecord struct {
	Network       string `json:"network"`
	NetworkSHA256 string `json:"network_sha256"`
	User          string `json:"user"`
	UserSHA256    string `json:"user_sha256"`
	VMID          int    `json:"vmid"`
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

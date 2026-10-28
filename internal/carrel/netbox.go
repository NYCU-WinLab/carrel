package carrel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// NetBox inventory sync (issue #141, PLAN 9.4). carrel pushes its machines,
// networks and addresses to a NetBox instance. The platform database stays the
// only source of truth: every pass derives the wanted NetBox objects from it,
// compares them with the objects that carry carrel's ownership marker, and
// creates, updates or deletes the difference. Nothing here sits on the path of
// a machine operation; a NetBox outage costs inventory freshness only.

const (
	nbVMType    = "virtualization.virtualmachine"
	nbIfaceType = "virtualization.vminterface"
	nbGroupType = "ipam.fhrpgroup"
	// nbDeviceIfaceType is the termination type of a device interface.
	nbDeviceIfaceType = "dcim.interface"
	// nbPassInterval is the periodic full reconcile that repairs drift.
	nbPassInterval = 5 * time.Minute
	nbSettle       = 2 * time.Second
)

type nbConfig struct {
	URL       string
	Token     string
	TokenFile string
	Cluster   string
	VRF       string
	VMIDField string
	// DeviceField names the custom field of a NetBox device that holds the
	// Proxmox node name; empty matches the device name.
	DeviceField string
	Public      string
	// PublicTenant and PublicRole name the NetBox tenant and role of the IP
	// ranges that make up the public address pool (PLAN 6.12).
	PublicTenant string
	PublicRole   string
	// TunnelGroup names the NetBox tunnel group that holds the client VPN
	// tunnels (issue #184, phase 2); empty leaves WireGuard out of NetBox.
	TunnelGroup string
	Marker      nbMarker
}

// nbMarker is the ownership mark every created object carries: the `owner`
// field of NetBox 4.5+. Operators scope the token's permissions with it.
type nbMarker struct {
	Value string
	owner int
}

// netboxConfig reads the "netbox" section. Sync is off unless it is enabled
// and complete; the second result says why an enabled section is unusable.
func (p *Platform) netboxConfig() (nbConfig, bool, error) {
	section := obj(p.Config["netbox"])
	if !boolean(section["enabled"]) {
		return nbConfig{}, false, nil
	}
	c := nbConfig{
		URL:          strings.TrimRight(str(section["url"]), "/"),
		Token:        str(section["token"]),
		TokenFile:    str(section["token_file"]),
		Cluster:      str(section["cluster"]),
		VRF:          textAt(section, "vrf", "Carrel"),
		VMIDField:    textAt(section, "vmid_field", "vmid"),
		DeviceField:  str(section["device_field"]),
		Public:       str(p.Config["public_address"]),
		PublicTenant: textAt(section, "public_tenant", "Carrel"),
		PublicRole:   textAt(section, "public_role", "User"),
		TunnelGroup:  str(section["tunnel_group"]),
		Marker:       nbMarker{Value: str(section["owner"])},
	}
	switch {
	case !strings.HasPrefix(c.URL, "http://") && !strings.HasPrefix(c.URL, "https://"):
		return c, false, fmt.Errorf("netbox.url must be an http(s) URL")
	case c.Token == "" && c.TokenFile == "":
		return c, false, fmt.Errorf("netbox needs token or token_file")
	case c.Cluster == "":
		return c, false, fmt.Errorf("netbox.cluster is required")
	case c.Marker.Value == "" || len(c.Marker.Value) > 100:
		return c, false, fmt.Errorf("netbox.owner is required (an existing NetBox owner, at most 100 characters)")
	}
	return c, true, nil
}

// authorization is read for every pass so a rotated token needs no restart. The
// token reaches no log and no error text.
func (c nbConfig) authorization() string {
	token := c.Token
	if c.TokenFile != "" {
		data, err := os.ReadFile(c.TokenFile)
		if err != nil {
			panic(nbError{Msg: "NetBox token file is unreadable"})
		}
		token = strings.TrimSpace(string(data))
	}
	switch {
	case strings.Contains(token, " "):
		return token
	case strings.HasPrefix(token, "nbt_"):
		return "Bearer " + token
	}
	return "Token " + token
}

type nbError struct {
	Status int
	Msg    string
}

func (e nbError) Error() string { return e.Msg }

func describe(err any) string {
	if e, ok := err.(error); ok {
		return e.Error()
	}
	return fmt.Sprint(err)
}

type nbClient struct {
	base, auth string
	http       *http.Client
	ctx        context.Context
	marker     nbMarker
	writes     int
}

func (c *nbClient) do(method, path string, query url.Values, body any) D {
	var data io.Reader
	if body != nil {
		data = bytes.NewReader(encoded(body))
	}
	target := c.base + "/api/" + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(c.ctx, method, target, data)
	must(err)
	req.Header.Set("Authorization", c.auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if method != "GET" {
		c.writes++
	}
	resp, err := c.http.Do(req)
	if err != nil {
		panic(nbError{Msg: "NetBox request could not complete"})
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if method == "DELETE" && resp.StatusCode == 404 {
		return D{}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := strings.TrimSpace(string(raw))
		if len(detail) > 300 {
			detail = detail[:300]
		}
		panic(nbError{Status: resp.StatusCode, Msg: fmt.Sprintf("NetBox %s %s returned %d: %s", method, path, resp.StatusCode, detail)})
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return D{}
	}
	var out D
	if json := decodeBytes(raw); json != nil {
		out = json
	} else {
		panic(nbError{Msg: "NetBox returned an invalid response"})
	}
	return out
}

func decodeBytes(raw []byte) (d D) {
	defer func() {
		if recover() != nil {
			d = nil
		}
	}()
	return decode(string(raw))
}

// list reads every page of a collection.
func (c *nbClient) list(path string, query url.Values) []D {
	out := []D{}
	for offset := 0; ; {
		q := url.Values{"limit": {"500"}, "offset": {strconv.Itoa(offset)}}
		for k, v := range query {
			q[k] = v
		}
		page := c.do("GET", path, q, nil)
		results := dicts(page["results"])
		out = append(out, results...)
		offset += len(results)
		if page["next"] == nil || len(results) == 0 {
			return out
		}
	}
}

func (c *nbClient) create(path string, want D) D {
	return c.do("POST", path, nil, merge(want, c.marker.fields()))
}

// ensure makes have match want, creating the object when there is none. have
// always comes from the marked inventory.
func (c *nbClient) ensure(path string, have, want D) D {
	want = clone(want)
	if have == nil {
		return c.create(path, want)
	}
	if !nbSame(want, have) {
		return c.do("PATCH", fmt.Sprintf("%s%d/", path, integer(have["id"])), nil, want)
	}
	return have
}

func (m nbMarker) fields() D { return D{"owner": D{"name": m.Value}} }

// marked reports whether carrel created the object. A listing is filtered
// server side as well; this check keeps a foreign object out even when the
// server ignores a filter.
func (c *nbClient) marked(o D) bool {
	return c.marker.owner != 0 && integer(obj(o["owner"])["id"]) == c.marker.owner
}

func (c *nbClient) markedList(path string, extra url.Values) []D {
	q := url.Values{"owner_id": {strconv.Itoa(c.marker.owner)}}
	for k, v := range extra {
		q[k] = v
	}
	return filter(c.list(path, q), c.marked)
}

// prepare resolves the owner. The NetBox operator creates it, since an owner
// needs a group. The name is compared here too: a server that ignored the
// filter must not hand carrel someone else's owner to prune.
func (c *nbClient) prepare() {
	found := find(c.list("users/owners/", url.Values{"name": {c.marker.Value}}), func(o D) bool { return o["name"] == c.marker.Value })
	if found == nil {
		panic(nbError{Msg: "NetBox owner " + c.marker.Value + " does not exist; the NetBox operator creates it"})
	}
	c.marker.owner = integer(found["id"])
}

// nbSame reports whether have already holds every field of want. Nested
// objects compare by id, choices by value.
func nbSame(want, have any) bool {
	switch w := want.(type) {
	case map[string]any:
		h, _ := have.(map[string]any)
		for k, v := range w {
			if !nbSame(v, h[k]) {
				return false
			}
		}
		return true
	case []any:
		h, _ := have.([]any)
		a, b := nbSet(w), nbSet(h)
		return strings.Join(a, "\x00") == strings.Join(b, "\x00")
	case float64:
		return w == num(nbScalar(have))
	}
	return fmt.Sprint(want) == fmt.Sprint(nbScalar(have))
}

func nbScalar(v any) any {
	if m, ok := v.(map[string]any); ok {
		if id, ok := m["id"]; ok {
			return id
		}
		return m["value"]
	}
	return v
}

func nbSet(xs []any) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, fmt.Sprint(x))
	}
	sort.Strings(out)
	return out
}

// The wanted state, derived from the platform database.

type nbPrefix struct{ vrf, prefix, description string }

type nbAddress struct {
	vrf, address, description string
	iface                     string // key of the interface it is bound to
	dns                       string // the infra resolver's name, for the machine address
}

type nbIface struct {
	name, description, vrf, mac string
	addresses                   []nbAddress
}

// nbTunnel is a tenant's client VPN interface as a NetBox tunnel, with the
// exit node's interface of the same name as its hub (issue #184, phase 2).
type nbTunnel struct{ name, description string }

type nbService struct {
	name, protocol, description string
	port                        int
}

type nbMachine struct {
	vmid, tenantN                       int
	name, tenant, kind, status, comment string
	image, node, onBoot, diskVolume     string
	publicIP                            string // address/length bound to the machine (issue #91)
	cpu                                 float64
	memoryMB, diskMB                    int
	primary                             nbAddress
	ifaces                              []nbIface
	services                            []nbService
}

type nbVIP struct {
	name, tenant, vrf, address string
	groupID                    int
	vmids                      []int
	// Public ports and domains at the address (issue #146).
	services []nbService
}

type nbTenant struct {
	n        int
	vrf      string // the shared VRF of the tenant segment
	vrfs     []string
	oldVRF   map[string][]string // VRF name -> the names it had before names read like words
	prefixes []nbPrefix
	machines []nbMachine
	vips     []nbVIP
	// vpnClients are the addresses of the tenant's client VPN (issue #184).
	vpnClients []nbAddress
	tunnel     *nbTunnel // nil without clients, or without netbox.tunnel_group
}

func nbStatus(m D) string {
	switch {
	case m["power_state"] == "running":
		return "active"
	case m["state"] == "provisioning":
		return "planned"
	}
	return "offline"
}

// nbOnBoot mirrors the Proxmox onboot flag, which follows the owner's last
// power action, not what the guest does by itself. A machine without a recorded
// action falls back to its observed power state.
func nbOnBoot(m D) string {
	if m["onboot"] != nil {
		if boolean(m["onboot"]) {
			return "on"
		}
		return "off"
	}
	if m["power_state"] == "running" {
		return "on"
	}
	return "off"
}

// nbSlug turns an image name into a NetBox slug.
func nbSlug(name string) string {
	return strings.Trim(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return '-'
	}, strings.ToLower(name)), "-")
}

// nbTitle is the platform name of an image: the image with its first letter capitalized.
func nbTitle(name string) string {
	if name == "" {
		return name
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

func (e *Execution) netboxWanted(c nbConfig) []nbTenant {
	out := []nbTenant{}
	live := func(o D) bool { return o["state"] != "deleting" }
	for _, t := range e.S.Tenants() {
		n, slug := integer(t["n"]), str(t["slug"])
		machines := filter(e.S.Objects("machines", n), live)
		networks := filter(e.S.Objects("networks", n), live)
		ports := filter(dicts(portsAsD(e.ports(n))), live)
		domains := filter(dicts(domainsAsD(e.domains(n))), live)
		vips := filter(dicts(vipsAsD(e.vips(n))), live)
		// A client that is expiring or being removed has left the desired state.
		clients := filter(dicts(vpnClientsAsD(e.vpnClients(n))), vpnClientLive)
		if len(machines) == 0 && len(networks) == 0 && len(vips) == 0 && len(clients) == 0 {
			continue
		}
		tn := nbTenant{n: n, vrf: c.VRF, oldVRF: map[string][]string{c.VRF: {strings.ToLower(c.VRF)}}}
		used := map[string]bool{tn.vrf: true}
		tn.prefixes = append(tn.prefixes, nbPrefix{tn.vrf, fmt.Sprintf("10.200.%d.0/24", n), "Carrel tenant " + slug})
		// Client VPN addresses come from 10.201.N.0/24 and are as unique as the
		// tenant segment, so they share its VRF. No interface: a client is not a machine.
		if len(clients) > 0 {
			tn.prefixes = append(tn.prefixes, nbPrefix{tn.vrf, fmt.Sprintf("10.201.%d.0/24", n), "Carrel VPN clients of tenant " + slug})
		}
		if len(clients) > 0 && c.TunnelGroup != "" {
			tn.tunnel = &nbTunnel{vpnInterface(n), fmt.Sprintf("Carrel client VPN of tenant %s, endpoint %s:%d", slug, c.Public, vpnPortBase+n)}
		}
		for _, cl := range clients {
			expires := time.Unix(int64(num(cl["expires_at"])), 0).UTC().Format("2006-01-02")
			tn.vpnClients = append(tn.vpnClients, nbAddress{vrf: tn.vrf, address: str(cl["address"]) + "/32", description: fmt.Sprintf("Carrel VPN client %s of tenant %s, expires %s", cl["name"], slug, expires)})
		}
		// Only a private network can overlap another tenant's CIDR, so each one
		// that has addresses gets a VRF of its own; the tenant segment is unique
		// platform-wide and shares one.
		names, netVRF := map[string]string{}, map[string]string{}
		for _, nw := range networks {
			names[str(nw["id"])] = str(nw["name"])
			// A raw_l2 segment has no carrel-managed addressing: only the attachment is recorded.
			if cidr := str(nw["cidr"]); cidr != "" && nw["mode"] == "managed" {
				if p, err := netip.ParsePrefix(cidr); err == nil {
					netVRF[str(nw["id"])] = fmt.Sprintf("%s %s %s", c.VRF, nbTitle(slug), nw["name"])
					tn.oldVRF[netVRF[str(nw["id"])]] = []string{fmt.Sprintf("%s-%s-%s", c.VRF, slug, nw["name"]), fmt.Sprintf("%s-%s-%s", strings.ToLower(c.VRF), slug, nw["name"])}
					used[netVRF[str(nw["id"])]] = true
					tn.prefixes = append(tn.prefixes, nbPrefix{netVRF[str(nw["id"])], p.Masked().String(), fmt.Sprintf("Carrel network %s (tenant %s)", nw["name"], slug)})
				}
			}
		}
		for _, m := range machines {
			vmid := integer(m["vmid"])
			nm := nbMachine{vmid: vmid, tenantN: n, name: str(m["name"]) + "." + slug, tenant: slug, kind: str(m["kind"]), status: nbStatus(m),
				image: str(m["image"]), node: str(m["node"]), onBoot: nbOnBoot(m), diskVolume: str(m["disk_volume"]),
				cpu: num(m["cpu"]), memoryMB: integer(m["memory_mb"]), diskMB: integer(m["disk_gb"]) * 1024}
			nm.comment = fmt.Sprintf("Carrel %s, tenant %s, Proxmox VMID %d", nm.kind, slug, vmid)
			if b := e.machinePublicIP(m); b != nil {
				nm.publicIP = e.publicIPPrefix(str(b["address"]))
			}
			key := fmt.Sprintf("%d/eth0", vmid)
			primary := nbAddress{tn.vrf, str(m["ip"]) + "/24", "Carrel address of " + nm.name, key, nm.name + ".internal"}
			nm.primary = primary
			nm.ifaces = append(nm.ifaces, nbIface{name: "eth0", vrf: tn.vrf, mac: str(m["mac"]), description: "Carrel primary NIC", addresses: []nbAddress{primary}})
			for _, nic := range dicts(m["nics"]) {
				network := str(nic["network"])
				iface := nbIface{name: fmt.Sprintf("eth%d", integer(nic["index"])), vrf: netVRF[network], mac: str(nic["mac"]), description: fmt.Sprintf("Carrel network %s (%s)", names[network], nic["mode"])}
				if ip := str(nic["ip"]); ip != "" {
					iface.addresses = append(iface.addresses, nbAddress{netVRF[network], fmt.Sprintf("%s/%d", ip, integer(nic["prefix"])), "Carrel address of " + nm.name, fmt.Sprintf("%d/%s", vmid, iface.name), ""})
				}
				nm.ifaces = append(nm.ifaces, iface)
			}
			nm.services = nbServices(c, ports, domains, func(g D) bool { return g["vip"] == nil && integer(g["vmid"]) == vmid })
			tn.machines = append(tn.machines, nm)
		}
		for _, v := range vips {
			address := str(v["address"])
			last, _ := strconv.Atoi(address[strings.LastIndex(address, ".")+1:])
			vip := nbVIP{name: str(v["name"]) + "." + slug, tenant: slug, vrf: tn.vrf, address: address + "/24", groupID: n*4 + max(0, last-251)}
			for _, id := range arr(v["vmids"]) {
				vip.vmids = append(vip.vmids, integer(id))
			}
			vip.services = nbServices(c, ports, domains, func(g D) bool { return g["vip"] == v["id"] })
			tn.vips = append(tn.vips, vip)
		}
		for name := range used {
			tn.vrfs = append(tn.vrfs, name)
		}
		sort.Strings(tn.vrfs)
		out = append(out, tn)
	}
	return out
}

// nbServices lists the public ports and domains that pick selects.
func nbServices(c nbConfig, ports, domains []D, pick func(D) bool) []nbService {
	out := []nbService{}
	for _, p := range filter(ports, pick) {
		out = append(out, nbService{fmt.Sprintf("public-%s-%d", p["proto"], integer(p["public_port"])), str(p["proto"]), fmt.Sprintf("Public %s:%d/%s", c.Public, integer(p["public_port"]), p["proto"]), integer(p["port"])})
	}
	for _, d := range filter(domains, pick) {
		out = append(out, nbService{"https://" + str(d["name"]), "tcp", "HTTPS route " + str(d["name"]), integer(d["target_port"])})
	}
	return out
}

// netboxServices keeps the services of one parent, a machine or a virtual
// address's FHRP group. The parent's type is part of its identity: a VM and
// a group can share an id.
func netboxServices(c *nbClient, s *nbState, services []nbService, parentType string, parentID int) {
	for _, sv := range services {
		have := one(s.services, func(o D) bool {
			return o["name"] == sv.name && o["parent_object_type"] == parentType && integer(o["parent_object_id"]) == parentID
		})
		svc := c.ensure("ipam/services/", have, D{"parent_object_type": parentType, "parent_object_id": parentID, "name": sv.name, "port_mappings": []string{fmt.Sprintf("%s/%d", sv.protocol, sv.port)}, "description": sv.description})
		s.kept("services", integer(svc["id"]))
	}
}

func portsAsD(xs []portGrant) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x.D()
	}
	return out
}

func domainsAsD(xs []domainRecord) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x.D()
	}
	return out
}

func vpnClientsAsD(xs []vpnClient) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x.D()
	}
	return out
}

func vipsAsD(xs []vipRecord) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x.D()
	}
	return out
}

// nbState is what the pass found in NetBox and what it kept.
type nbState struct {
	vrfs, prefixes, ips, ifaces, vms, services, groups, assignments []D
	platforms, macs, disks                                          []D
	tunnels, terminations, deviceIfaces                             []D // the client VPN tunnels, their ends, and the exit node's interfaces
	tunnelGroup, exitDevice                                         int // NetBox ids; 0 when phase 2 is off or the object is missing
	exitNode                                                        string
	devices                                                         map[string]int // lower-case node name -> NetBox device id
	platformIDs                                                     map[string]int // image -> NetBox platform id
	keep                                                            map[string]map[int]bool
}

func (s *nbState) kept(kind string, id int) {
	if s.keep[kind] == nil {
		s.keep[kind] = map[int]bool{}
	}
	s.keep[kind][id] = true
}

func (s *nbState) protect(kind string, objects []D, matches func(D) bool) {
	for _, o := range objects {
		if matches(o) {
			s.kept(kind, integer(o["id"]))
		}
	}
}

func one(objects []D, f func(D) bool) D { return find(objects, f) }

func refID(v any) int { return integer(obj(v)["id"]) }

type nbResult struct {
	Writes int
	Errors []string
}

// SyncNetBox runs one pass and says what it could not do. A machine that fails
// keeps its objects in NetBox as they are and shows the error in machine_get.
func (e *Execution) SyncNetBox(cfg nbConfig) (result nbResult) {
	var c *nbClient
	err := attempt(func() {
		c = &nbClient{base: cfg.URL, auth: cfg.authorization(), http: e.P.HTTP, ctx: e.Ctx, marker: cfg.Marker}
		c.prepare()
		result = e.netboxPass(c, cfg)
	})
	if c != nil {
		result.Writes = c.writes
	}
	if err != nil {
		result.Errors = append(result.Errors, describe(err))
	}
	e.netboxRecord(result)
	return result
}

func (e *Execution) netboxPass(c *nbClient, cfg nbConfig) nbResult {
	var result nbResult
	fail := func(what string, err any) string {
		msg := what + ": " + describe(err)
		result.Errors = append(result.Errors, msg)
		return msg
	}
	cluster := c.list("virtualization/clusters/", url.Values{"name": {cfg.Cluster}})
	if len(cluster) == 0 {
		panic(nbError{Msg: "NetBox cluster " + cfg.Cluster + " does not exist"})
	}
	clusterID := integer(cluster[0]["id"])
	s := &nbState{keep: map[string]map[int]bool{}, devices: map[string]int{}, platformIDs: map[string]int{}}
	s.vrfs = c.markedList("ipam/vrfs/", nil)
	s.prefixes = c.markedList("ipam/prefixes/", nil)
	s.ips = c.markedList("ipam/ip-addresses/", nil)
	s.ifaces = c.markedList("virtualization/interfaces/", nil)
	s.vms = c.markedList("virtualization/virtual-machines/", url.Values{"cluster_id": {strconv.Itoa(clusterID)}})
	s.services = c.markedList("ipam/services/", nil)
	s.groups = c.markedList("ipam/fhrp-groups/", nil)
	s.assignments = c.list("ipam/fhrp-group-assignments/", nil)
	s.platforms = c.markedList("dcim/platforms/", nil)
	s.macs = c.markedList("dcim/mac-addresses/", nil)
	s.disks = c.markedList("virtualization/virtual-disks/", nil)
	if cfg.TunnelGroup != "" {
		s.tunnels = c.markedList("vpn/tunnels/", nil)
		s.terminations = c.list("vpn/tunnel-terminations/", nil)
		s.deviceIfaces = c.markedList("dcim/interfaces/", nil)
	}
	if err := attempt(func() { e.netboxPool(c, cfg) }); err != nil {
		// The last pool read stays; bound addresses are not touched.
		fail("public address pool", err)
	}
	// The cluster's devices are the hypervisor nodes. They belong to the NetBox
	// operator: carrel only points a machine at the one it runs on.
	for _, d := range c.list("dcim/devices/", url.Values{"cluster_id": {strconv.Itoa(clusterID)}}) {
		node := str(d["name"])
		if cfg.DeviceField != "" {
			node = str(obj(d["custom_fields"])[cfg.DeviceField])
		}
		s.devices[strings.ToLower(node)] = integer(d["id"])
	}

	if cfg.TunnelGroup != "" {
		// The group is the operator's: a missing one fails phase 2 and creates
		// nothing, and what NetBox holds stays until the group is back.
		group := find(c.list("vpn/tunnel-groups/", url.Values{"name": {cfg.TunnelGroup}}), func(o D) bool { return o["name"] == cfg.TunnelGroup })
		if group == nil {
			fail("VPN tunnels", "NetBox tunnel group "+cfg.TunnelGroup+" does not exist; the NetBox operator creates it")
			s.protect("tunnels", s.tunnels, func(D) bool { return true })
			s.protect("terminations", s.terminations, func(D) bool { return true })
			s.protect("deviceIfaces", s.deviceIfaces, func(D) bool { return true })
		} else {
			s.tunnelGroup = integer(group["id"])
		}
		// The exit node is the first node; its device is the operator's.
		if nodes := e.P.Nodes(); len(nodes) > 0 {
			s.exitNode = nodes[0].Name
			s.exitDevice = s.devices[strings.ToLower(s.exitNode)]
		}
	}

	wanted := e.netboxWanted(cfg)
	synced := map[int]string{} // vmid -> error, "" for a clean machine
	tenantOf := map[int]int{}
	vmNB := map[int]int{} // vmid -> NetBox VM id
	ifaceNB := map[string]int{}
	for _, t := range wanted {
		tenantErr := attempt(func() { e.netboxTenant(c, s, &t, clusterID, cfg, synced, tenantOf, vmNB, ifaceNB, fail) })
		if tenantErr != nil {
			msg := fail("tenant "+strconv.Itoa(t.n), tenantErr)
			for _, m := range t.machines {
				if synced[m.vmid] == "" {
					synced[m.vmid] = msg
				}
			}
			// Everything of the tenant stays as it is until the next pass.
			for _, name := range t.vrfs {
				v := nbFindVRF(s.vrfs, name, t.oldVRF[name])
				if v == nil {
					continue
				}
				id := integer(v["id"])
				s.kept("vrfs", id)
				if name != t.vrf {
					// A private network's VRF holds only this tenant's objects.
					s.protect("prefixes", s.prefixes, func(o D) bool { return refID(o["vrf"]) == id })
					s.protect("ips", s.ips, func(o D) bool { return refID(o["vrf"]) == id })
				}
			}
			for _, p := range t.prefixes {
				s.protect("prefixes", s.prefixes, func(o D) bool { return o["prefix"] == p.prefix })
			}
			for _, a := range t.vpnClients {
				s.protect("ips", s.ips, func(o D) bool { return o["address"] == a.address })
			}
			if t.tunnel != nil {
				netboxProtectTunnel(s, t.tunnel)
			}
			for _, m := range t.machines {
				e.netboxProtectMachine(s, m.name)
			}
			for _, v := range t.vips {
				e.netboxProtectVIP(s, v)
			}
		}
	}
	for _, m := range e.netboxMachines(wanted) {
		if synced[m.vmid] != "" {
			e.netboxProtectMachine(s, m.name)
		}
	}
	for _, m := range e.netboxMachines(wanted) {
		e.netboxMachineStatus(m, synced[m.vmid])
	}
	e.netboxForget(wanted)
	e.netboxPrune(c, s, fail)
	return result
}

func (e *Execution) netboxMachines(wanted []nbTenant) []nbMachine {
	out := []nbMachine{}
	for _, t := range wanted {
		out = append(out, t.machines...)
	}
	return out
}

// netboxTenant syncs one tenant: its VRF, prefixes, machines and virtual
// addresses. A failing machine is recorded and skipped; a failing VRF or prefix
// fails the tenant.
// nbFindVRF finds a VRF by its name, or by an old name (before names read like
// words, "carrel-alice-back") so it is renamed in place instead of replaced.
func nbFindVRF(vrfs []D, name string, old []string) D {
	if v := one(vrfs, func(v D) bool { return v["name"] == name }); v != nil {
		return v
	}
	return one(vrfs, func(v D) bool { return contains(old, v["name"]) })
}

func (e *Execution) netboxTenant(c *nbClient, s *nbState, t *nbTenant, clusterID int, cfg nbConfig, synced map[int]string, tenantOf map[int]int, vmNB map[int]int, ifaceNB map[string]int, fail func(string, any) string) {
	vrfIDs := map[string]int{}
	for _, name := range t.vrfs {
		vrf := nbFindVRF(s.vrfs, name, t.oldVRF[name])
		if vrf == nil && len(c.list("ipam/vrfs/", url.Values{"name": {name}})) > 0 {
			panic(nbError{Msg: "NetBox VRF " + name + " exists but carrel did not create it"})
		}
		created := vrf == nil
		vrf = c.ensure("ipam/vrfs/", vrf, D{"name": name, "description": "Carrel"})
		if created {
			s.vrfs = append(s.vrfs, vrf)
		}
		vrfIDs[name] = integer(vrf["id"])
		s.kept("vrfs", vrfIDs[name])
	}
	for _, p := range t.prefixes {
		vrfID := vrfIDs[p.vrf]
		have := one(s.prefixes, func(o D) bool { return o["prefix"] == p.prefix && refID(o["vrf"]) == vrfID })
		got := c.ensure("ipam/prefixes/", have, D{"prefix": p.prefix, "vrf": vrfID, "status": "active", "description": p.description})
		s.kept("prefixes", integer(got["id"]))
	}
	// A client address that fails keeps what NetBox holds and fails alone.
	for _, a := range t.vpnClients {
		if err := attempt(func() {
			vrfID := vrfIDs[a.vrf]
			haveIP := one(s.ips, func(o D) bool { return o["address"] == a.address && refID(o["vrf"]) == vrfID })
			ip := c.ensure("ipam/ip-addresses/", haveIP, D{"address": a.address, "vrf": vrfID, "status": "active", "description": a.description})
			s.kept("ips", integer(ip["id"]))
		}); err != nil {
			fail("VPN client "+a.address, err)
			s.protect("ips", s.ips, func(o D) bool { return o["address"] == a.address })
		}
	}
	// A tunnel that fails keeps what NetBox holds and fails alone.
	if t.tunnel != nil && s.tunnelGroup != 0 {
		if err := attempt(func() { netboxTunnel(c, s, *t.tunnel) }); err != nil {
			fail("VPN tunnel "+t.tunnel.name, err)
			netboxProtectTunnel(s, t.tunnel)
		}
	}
	for _, m := range t.machines {
		tenantOf[m.vmid] = t.n
		if err := attempt(func() { e.netboxMachine(c, s, m, vrfIDs, clusterID, cfg, vmNB, ifaceNB) }); err != nil {
			synced[m.vmid] = fail("machine "+m.name, err)
		} else {
			synced[m.vmid] = ""
		}
	}
	for _, v := range t.vips {
		if err := attempt(func() { e.netboxVIP(c, s, v, vrfIDs[v.vrf], ifaceNB) }); err != nil {
			fail("virtual address "+v.name, err)
			e.netboxProtectVIP(s, v)
		}
	}
}

// vpnInterface names a tenant's WireGuard interface on the exit node.
func vpnInterface(n int) string { return fmt.Sprintf("wg-t%03d", n) }

// netboxTunnel syncs one tenant's tunnel: the tunnel in the operator's group,
// the exit node's interface of the same name, and the hub end that binds them.
// The tunnel is kept first, so a missing exit node leaves it in place.
func netboxTunnel(c *nbClient, s *nbState, t nbTunnel) {
	haveTunnel := one(s.tunnels, func(o D) bool { return o["name"] == t.name && refID(o["group"]) == s.tunnelGroup })
	tunnel := c.ensure("vpn/tunnels/", haveTunnel, D{"name": t.name, "group": s.tunnelGroup, "status": "active", "encapsulation": "wireguard", "description": t.description})
	tunnelID := integer(tunnel["id"])
	s.kept("tunnels", tunnelID)
	if s.exitDevice == 0 {
		panic(nbError{Msg: "NetBox has no device for the exit node " + s.exitNode})
	}
	haveIface := one(s.deviceIfaces, func(o D) bool { return o["name"] == t.name && refID(o["device"]) == s.exitDevice })
	iface := c.ensure("dcim/interfaces/", haveIface, D{"device": s.exitDevice, "name": t.name, "type": "virtual", "description": "Carrel client VPN"})
	ifaceID := integer(iface["id"])
	s.kept("deviceIfaces", ifaceID)
	// An end has no owner field: it is carrel's when its tunnel is.
	end := D{"tunnel": tunnelID, "role": "hub", "termination_type": nbDeviceIfaceType, "termination_id": ifaceID}
	haveEnd := one(s.terminations, func(o D) bool { return refID(o["tunnel"]) == tunnelID })
	switch {
	case haveEnd == nil:
		haveEnd = c.do("POST", "vpn/tunnel-terminations/", nil, end)
	case !nbSame(end, haveEnd):
		haveEnd = c.do("PATCH", fmt.Sprintf("vpn/tunnel-terminations/%d/", integer(haveEnd["id"])), nil, end)
	}
	s.kept("terminations", integer(haveEnd["id"]))
}

// netboxProtectTunnel keeps what NetBox holds for a tunnel that could not be synced.
func netboxProtectTunnel(s *nbState, t *nbTunnel) {
	s.protect("tunnels", s.tunnels, func(o D) bool { return o["name"] == t.name && refID(o["group"]) == s.tunnelGroup })
	s.protect("deviceIfaces", s.deviceIfaces, func(o D) bool { return o["name"] == t.name && refID(o["device"]) == s.exitDevice })
	for _, tunnel := range s.tunnels {
		if tunnel["name"] == t.name {
			s.protect("terminations", s.terminations, func(o D) bool { return refID(o["tunnel"]) == integer(tunnel["id"]) })
		}
	}
}

func (e *Execution) netboxMachine(c *nbClient, s *nbState, m nbMachine, vrfIDs map[string]int, clusterID int, cfg nbConfig, vmNB map[int]int, ifaceNB map[string]int) {
	// The VMID first: a renamed machine keeps its NetBox object, history and
	// all (machine_rename). The name finds objects from before the field.
	have := one(s.vms, func(o D) bool { return integer(obj(o["custom_fields"])[cfg.VMIDField]) == m.vmid })
	if have == nil {
		have = one(s.vms, func(o D) bool { return o["name"] == m.name })
	}
	if have == nil && len(c.list("virtualization/virtual-machines/", url.Values{"name": {m.name}, "cluster_id": {strconv.Itoa(clusterID)}})) > 0 {
		panic(nbError{Msg: "a NetBox virtual machine named " + m.name + " exists but carrel did not create it"})
	}
	// A machine without a platform or device in NetBox is recorded without one.
	var platform, device any
	if m.image != "" {
		platform = e.netboxPlatform(c, s, m.tenant, m.image)
	}
	if id, ok := s.devices[strings.ToLower(m.node)]; ok {
		device = id
	}
	// The disk size comes from the virtual disk below; NetBox sums it into the machine.
	want := D{"name": m.name, "cluster": clusterID, "status": m.status, "vcpus": m.cpu, "memory": m.memoryMB, "start_on_boot": m.onBoot, "platform": platform, "device": device, "description": m.comment, "custom_fields": D{cfg.VMIDField: m.vmid}}
	vm := c.ensure("virtualization/virtual-machines/", have, want)
	vmID := integer(vm["id"])
	s.kept("vms", vmID)
	vmNB[m.vmid] = vmID
	if m.diskMB > 0 {
		// The disk is named by its Proxmox volume once a node reported it
		// (issue #175), else by its config key. A machine has one root
		// disk, found by its machine, so a new name patches it.
		name := m.diskVolume
		if name == "" {
			name = "scsi0"
			if m.kind == "ct" {
				name = "rootfs"
			}
		}
		haveDisk := one(s.disks, func(o D) bool { return refID(o["virtual_machine"]) == vmID })
		disk := c.ensure("virtualization/virtual-disks/", haveDisk, D{"virtual_machine": vmID, "name": name, "size": m.diskMB, "description": "Carrel root disk"})
		s.kept("disks", integer(disk["id"]))
	}
	var primaryID int
	for _, f := range m.ifaces {
		haveIface := one(s.ifaces, func(o D) bool { return o["name"] == f.name && refID(o["virtual_machine"]) == vmID })
		var ifaceVRF any
		if f.vrf != "" {
			ifaceVRF = vrfIDs[f.vrf]
		}
		iface := c.ensure("virtualization/interfaces/", haveIface, D{"virtual_machine": vmID, "name": f.name, "enabled": true, "vrf": ifaceVRF, "description": f.description})
		ifaceID := integer(iface["id"])
		s.kept("ifaces", ifaceID)
		ifaceNB[fmt.Sprintf("%d/%s", m.vmid, f.name)] = ifaceID
		if f.mac != "" {
			mac := strings.ToUpper(f.mac)
			haveMAC := one(s.macs, func(o D) bool {
				return strings.EqualFold(str(o["mac_address"]), mac) && o["assigned_object_type"] == nbIfaceType && integer(o["assigned_object_id"]) == ifaceID
			})
			got := c.ensure("dcim/mac-addresses/", haveMAC, D{"mac_address": mac, "assigned_object_type": nbIfaceType, "assigned_object_id": ifaceID})
			s.kept("macs", integer(got["id"]))
			c.ensure("virtualization/interfaces/", iface, D{"primary_mac_address": integer(got["id"])})
		}
		for _, a := range f.addresses {
			vrfID := vrfIDs[a.vrf]
			haveIP := one(s.ips, func(o D) bool { return o["address"] == a.address && refID(o["vrf"]) == vrfID })
			ip := c.ensure("ipam/ip-addresses/", haveIP, D{"address": a.address, "vrf": vrfID, "status": "active", "assigned_object_type": nbIfaceType, "assigned_object_id": ifaceID, "description": a.description, "dns_name": a.dns})
			s.kept("ips", integer(ip["id"]))
			if a.address == m.primary.address {
				primaryID = integer(ip["id"])
			}
		}
	}
	if primaryID != 0 {
		c.ensure("virtualization/virtual-machines/", vm, D{"primary_ip4": primaryID})
	}
	if m.publicIP != "" && primaryID != 0 {
		// A bound public address is the outside of its machine's primary
		// address, 1:1 NAT as the exit node does it (issue #91).
		haveIP := one(s.ips, func(o D) bool { return o["address"] == m.publicIP && o["vrf"] == nil })
		ip := c.ensure("ipam/ip-addresses/", haveIP, D{"address": m.publicIP, "status": "active", "nat_inside": primaryID, "description": "Carrel public address of " + m.name})
		s.kept("ips", integer(ip["id"]))
	}
	netboxServices(c, s, m.services, nbVMType, vmID)
}

// netboxPlatform makes sure the NetBox platform of an image exists, once per
// pass. carrel creates and owns these, keyed by slug so a rename of the name
// follows; an unowned platform with the same slug or name is not touched.
func (e *Execution) netboxPlatform(c *nbClient, s *nbState, tenant, image string) int {
	// Tenant and ISO images ("tenant:" or "iso:" prefix) belong to one tenant, so
	// each tenant gets its own platform; catalog images are shared and get
	// "catalog:" so no catalog name can share a slug with them.
	label := tenant + "/" + image
	if !strings.Contains(image, ":") {
		label = "catalog:" + image
	}
	if id, ok := s.platformIDs[label]; ok {
		return id
	}
	// Name and slug both start with carrel, so neither can meet a platform made
	// by hand. A tenant's image and ISO of one name can both exist (deleting an
	// ISO does not touch machines that used it), and NetBox keeps names unique,
	// so an ISO's name says so. A platform from before the prefix is found by its
	// old slug and renamed in place.
	old := nbSlug(label)
	slug, name := "carrel-"+old, "Carrel: "+nbTitle(strings.ReplaceAll(image, "-", " "))
	if kind, rest, ok := strings.Cut(image, ":"); ok {
		name = "Carrel: " + nbTitle(tenant) + "/" + rest
		if kind == "iso" {
			name += " (ISO)"
		}
	}
	have := one(s.platforms, func(o D) bool { return o["slug"] == slug })
	if have == nil {
		have = one(s.platforms, func(o D) bool { return o["slug"] == old })
	}
	if have == nil && len(c.list("dcim/platforms/", url.Values{"slug": {slug}})) > 0 {
		panic(nbError{Msg: "a NetBox platform with slug " + slug + " exists but carrel did not create it"})
	}
	created := have == nil
	description := "Carrel image " + image
	if strings.Contains(image, ":") {
		description += " of tenant " + tenant
	}
	got := c.ensure("dcim/platforms/", have, D{"name": name, "slug": slug, "description": description})
	if created {
		s.platforms = append(s.platforms, got)
	}
	id := integer(got["id"])
	s.kept("platforms", id)
	s.platformIDs[label] = id
	return id
}

func (e *Execution) netboxVIP(c *nbClient, s *nbState, v nbVIP, vrfID int, ifaceNB map[string]int) {
	haveGroup := one(s.groups, func(o D) bool { return o["name"] == v.name })
	group := c.ensure("ipam/fhrp-groups/", haveGroup, D{"name": v.name, "protocol": "other", "group_id": v.groupID, "description": "Carrel virtual address of tenant " + v.tenant})
	groupID := integer(group["id"])
	s.kept("groups", groupID)
	haveIP := one(s.ips, func(o D) bool { return o["address"] == v.address && refID(o["vrf"]) == vrfID })
	ip := c.ensure("ipam/ip-addresses/", haveIP, D{"address": v.address, "vrf": vrfID, "status": "active", "role": "vip", "assigned_object_type": nbGroupType, "assigned_object_id": groupID, "description": "Carrel virtual address " + v.name})
	s.kept("ips", integer(ip["id"]))
	for _, vmid := range v.vmids {
		ifaceID := ifaceNB[fmt.Sprintf("%d/eth0", vmid)]
		if ifaceID == 0 {
			continue
		}
		member := one(s.assignments, func(o D) bool {
			return refID(o["group"]) == groupID && integer(o["interface_id"]) == ifaceID && o["interface_type"] == nbIfaceType
		})
		if member == nil {
			member = c.do("POST", "ipam/fhrp-group-assignments/", nil, D{"group": groupID, "interface_type": nbIfaceType, "interface_id": ifaceID, "priority": 100})
			s.assignments = append(s.assignments, member)
		}
		s.kept("assignments", integer(member["id"]))
	}
	netboxServices(c, s, v.services, nbGroupType, groupID)
}

// netboxProtectMachine keeps what NetBox holds for a machine that could not be
// synced, so a failed update never deletes its inventory.
// netboxPool reads the public address pool (PLAN 6.12): the active IP ranges
// of the public tenant and role.
func (e *Execution) netboxPool(c *nbClient, cfg nbConfig) {
	ranges := []any{}
	for _, r := range c.list("ipam/ip-ranges/", nil) {
		if str(obj(r["tenant"])["name"]) == cfg.PublicTenant && str(obj(r["role"])["name"]) == cfg.PublicRole && str(obj(r["status"])["value"]) == "active" && r["vrf"] == nil {
			ranges = append(ranges, D{"start": r["start_address"], "end": r["end_address"]})
		}
	}
	e.S.SitePut("public_pool", "netbox", D{"ranges": ranges, "read_at": now()})
}

// publicIPPrefix is a pool address with the length of its NetBox range.
func (e *Execution) publicIPPrefix(address string) string {
	a, err := netip.ParseAddr(address)
	for _, r := range dicts(obj(e.S.SiteGet("public_pool", "netbox"))["ranges"]) {
		if p, perr := netip.ParsePrefix(str(r["start"])); err == nil && perr == nil && p.Masked().Contains(a) {
			return fmt.Sprintf("%s/%d", address, p.Bits())
		}
	}
	return address + "/32"
}

func (e *Execution) netboxProtectMachine(s *nbState, name string) {
	vm := one(s.vms, func(o D) bool { return o["name"] == name })
	if vm == nil {
		return
	}
	id := integer(vm["id"])
	s.kept("vms", id)
	if platform := refID(vm["platform"]); platform != 0 {
		s.kept("platforms", platform)
	}
	s.protect("disks", s.disks, func(o D) bool { return refID(o["virtual_machine"]) == id })
	ifaces := filter(s.ifaces, func(o D) bool { return refID(o["virtual_machine"]) == id })
	for _, f := range ifaces {
		s.kept("ifaces", integer(f["id"]))
		s.protect("macs", s.macs, func(o D) bool {
			return o["assigned_object_type"] == nbIfaceType && integer(o["assigned_object_id"]) == integer(f["id"])
		})
		inside := map[int]bool{}
		s.protect("ips", s.ips, func(o D) bool {
			mine := o["assigned_object_type"] == nbIfaceType && integer(o["assigned_object_id"]) == integer(f["id"])
			if mine {
				inside[integer(o["id"])] = true
			}
			return mine
		})
		// The public address outside of one of them (issue #91).
		s.protect("ips", s.ips, func(o D) bool { return inside[refID(o["nat_inside"])] })
		s.protect("assignments", s.assignments, func(o D) bool {
			return o["interface_type"] == nbIfaceType && integer(o["interface_id"]) == integer(f["id"])
		})
	}
	s.protect("services", s.services, func(o D) bool {
		return o["parent_object_type"] == nbVMType && integer(o["parent_object_id"]) == id
	})
}

func (e *Execution) netboxProtectVIP(s *nbState, v nbVIP) {
	group := one(s.groups, func(o D) bool { return o["name"] == v.name })
	if group == nil {
		return
	}
	id := integer(group["id"])
	s.kept("groups", id)
	s.protect("ips", s.ips, func(o D) bool {
		return o["assigned_object_type"] == nbGroupType && integer(o["assigned_object_id"]) == id
	})
	s.protect("assignments", s.assignments, func(o D) bool { return refID(o["group"]) == id })
	s.protect("services", s.services, func(o D) bool {
		return o["parent_object_type"] == nbGroupType && integer(o["parent_object_id"]) == id
	})
}

// netboxPrune deletes what carrel created and no longer wants, dependents
// first: NetBox refuses to delete an object that is still referenced.
func (e *Execution) netboxPrune(c *nbClient, s *nbState, fail func(string, any) string) {
	ours := map[int]bool{}
	for _, g := range s.groups {
		ours[integer(g["id"])] = true
	}
	ourTunnels := map[int]bool{}
	for _, t := range s.tunnels {
		ourTunnels[integer(t["id"])] = true
	}
	steps := []struct {
		kind, path string
		objects    []D
	}{
		{"services", "ipam/services/", s.services},
		// An end is ours when its tunnel is.
		{"terminations", "vpn/tunnel-terminations/", filter(s.terminations, func(o D) bool { return ourTunnels[refID(o["tunnel"])] })},
		// A membership cannot carry the marker; it is ours when its group is.
		{"assignments", "ipam/fhrp-group-assignments/", filter(s.assignments, func(o D) bool { return ours[refID(o["group"])] })},
		{"ips", "ipam/ip-addresses/", s.ips},
		{"macs", "dcim/mac-addresses/", s.macs},
		{"ifaces", "virtualization/interfaces/", s.ifaces},
		{"disks", "virtualization/virtual-disks/", s.disks},
		{"vms", "virtualization/virtual-machines/", s.vms},
		{"tunnels", "vpn/tunnels/", s.tunnels},
		{"deviceIfaces", "dcim/interfaces/", s.deviceIfaces},
		{"platforms", "dcim/platforms/", s.platforms},
		{"groups", "ipam/fhrp-groups/", s.groups},
		{"prefixes", "ipam/prefixes/", s.prefixes},
		{"vrfs", "ipam/vrfs/", s.vrfs},
	}
	for _, step := range steps {
		for _, o := range step.objects {
			id := integer(o["id"])
			if s.keep[step.kind][id] {
				continue
			}
			if err := attempt(func() { c.do("DELETE", fmt.Sprintf("%s%d/", step.path, id), nil, nil) }); err != nil {
				fail("delete "+step.kind+" "+strconv.Itoa(id), err)
			}
		}
	}
}

// Sync status. Each machine records when it last synced and the last error;
// the platform's own status keeps the pass as a whole.

func (e *Execution) netboxMachineStatus(m nbMachine, failure string) {
	old, _ := rowOf[D](e.S, "netbox_sync", strconv.Itoa(m.vmid))
	record := D{"vmid": m.vmid, "last_attempt": stamp(), "last_error": orNil(failure)}
	record["last_synced"] = old["last_synced"]
	if failure == "" {
		record["last_synced"] = stamp()
	} else if old["last_error"] != failure {
		e.S.Log("netbox", m.tenantN, "netbox_sync", D{"machine": m.name}, "failed: "+failure)
	}
	e.S.Put("netbox_sync", m.vmid, m.tenantN, record)
}

// netboxForget drops the status of machines that no longer exist.
func (e *Execution) netboxForget(wanted []nbTenant) {
	live := map[int]bool{}
	for _, m := range e.netboxMachines(wanted) {
		live[m.vmid] = true
	}
	for _, r := range e.S.Objects("netbox_sync") {
		if !live[integer(r["vmid"])] {
			e.S.Remove("netbox_sync", r["vmid"])
		}
	}
}

func (e *Execution) netboxRecord(r nbResult) {
	status := D{"last_pass": stamp(), "writes": r.Writes, "errors": len(r.Errors)}
	old := e.S.SiteGet("netbox", "status")
	last := strings.Join(r.Errors, "; ")
	if len(last) > 500 {
		last = last[:500]
	}
	if len(r.Errors) > 0 {
		status["last_error"] = last
		if old == nil || old["last_error"] != last {
			e.S.Log("netbox", nil, "netbox_sync", D{}, "failed: "+last)
		}
		slog.Error("netbox_sync_failed", "event", "netbox_sync_failed", "errors", len(r.Errors))
	}
	e.S.SitePut("netbox", "status", status)
}

// netboxStatus is the sync status machine_get shows, or nil when sync is off.
func (e *Execution) netboxStatus(vmid any) any {
	if _, ok, _ := e.P.netboxConfig(); !ok {
		return nil
	}
	r, _ := rowOf[D](e.S, "netbox_sync", str(vmid))
	return D{"last_synced": r["last_synced"], "last_error": r["last_error"]}
}

// NetBoxKick asks for a pass soon. It never blocks: a pass already asked for
// covers this change too.
func (p *Platform) NetBoxKick() {
	select {
	case p.netboxKick <- struct{}{}:
	default:
	}
}

func (p *Platform) startNetBox() {
	cfg, ok, err := p.netboxConfig()
	if err != nil {
		slog.Error("netbox_config_invalid", "event", "netbox_config_invalid", "error", err.Error())
		return
	}
	if !ok {
		return
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		retry := time.Duration(0)
		for {
			if p.ctx.Err() != nil {
				return
			}
			if result := p.execution(p.ctx).SyncNetBox(cfg); len(result.Errors) > 0 {
				retry = min(max(2*retry, 15*time.Second), nbPassInterval)
			} else {
				retry = 0
			}
			wait := nbPassInterval
			if retry > 0 {
				wait = retry
			}
			timer := time.NewTimer(wait)
			select {
			case <-p.ctx.Done():
				timer.Stop()
				return
			case <-p.netboxKick:
				timer.Stop()
				// Changes arrive in bursts; one pass covers them.
				if !sleep(p.ctx, nbSettle) {
					return
				}
				select {
				case <-p.netboxKick:
				default:
				}
			case <-timer.C:
			}
		}
	}()
}

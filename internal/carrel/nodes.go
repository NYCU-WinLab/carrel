package carrel

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

// Nodes come from config "nodes" (PLAN 15.15): each entry names a PVE node and
// the SSH alias of its node adapter. A configuration without nodes is the
// single R640 node behind carrel-node, and its machine records carry no node.
type nodeRef struct{ Name, Target string }

var nodeName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidateNodes rejects a node list that could route a machine to the wrong
// adapter; the control plane refuses to start with it.
func ValidateNodes(c D) error {
	if v := c["ingress"]; v != nil && v != "edge" && v != "exit" {
		return errors.New("ingress must be edge or exit")
	}
	if v, ok := c["nodes"]; ok && v != nil {
		if _, list := v.([]any); !list {
			return errors.New("nodes must be a list")
		}
	}
	names, targets := map[string]bool{}, map[string]bool{}
	for _, v := range arr(c["nodes"]) {
		n, ok := v.(map[string]any)
		name, target := str(n["name"]), str(n["target"])
		if !ok || !nodeName.MatchString(name) || !nodeName.MatchString(target) {
			return errors.New("each node needs a name and an SSH target")
		}
		if names[name] || targets[target] {
			return fmt.Errorf("duplicate node %s", name)
		}
		names[name], targets[target] = true, true
	}
	return nil
}

func (p *Platform) Nodes() []nodeRef {
	out := []nodeRef{}
	for _, v := range dicts(p.Config["nodes"]) {
		out = append(out, nodeRef{str(v["name"]), str(v["target"])})
	}
	if len(out) == 0 {
		out = append(out, nodeRef{"", "carrel-node"})
	}
	return out
}

// nodeOf returns the node that holds a machine. Records without a node belong
// to the first node, where every machine lived before placement existed.
func (p *Platform) nodeOf(m D) nodeRef {
	n, ok := p.lookupNode(m)
	if !ok {
		fail("backend_unavailable", "The machine's node is not configured", D{"recovery": "retry_infrastructure"})
	}
	return n
}

func (p *Platform) lookupNode(m D) (nodeRef, bool) {
	nodes := p.Nodes()
	name := str(m["node"])
	if name == "" {
		return nodes[0], true
	}
	for _, n := range nodes {
		if n.Name == name {
			return n, true
		}
	}
	return nodeRef{}, false
}

func (p *Platform) inventoryCache(target string) *ObservationCache {
	p.inventoryMu.Lock()
	defer p.inventoryMu.Unlock()
	if p.inventories == nil {
		p.inventories = map[string]*ObservationCache{}
	}
	if p.inventories[target] == nil {
		p.inventories[target] = &ObservationCache{}
	}
	return p.inventories[target]
}

func (p *Platform) invalidateInventory() {
	for _, n := range p.Nodes() {
		p.inventoryCache(n.Target).Invalidate()
	}
}

func (e *Execution) nodeCapacity(node nodeRef, proposed D, cached bool) D {
	reservations, snapshots := e.nodeLoad(node, proposed)
	var inventory any
	at := time.Now()
	if cached {
		var err error
		inventory, at, err = e.P.inventoryCache(node.Target).Get(e.Ctx, 2*time.Second, func(ctx context.Context) (any, error) {
			return e.P.Backend.Call(ctx, D{"op": "inventory"}, node.Target)
		})
		must(err)
	} else {
		inventory = e.Call(D{"op": "inventory"}, node.Target)
	}
	return summarize(obj(inventory), reservations, snapshots, at)
}

// nodeLoad lists what admission counts against a node: its machines, with
// proposed in place of its stored record, and the snapshots of its machines.
func (e *Execution) nodeLoad(node nodeRef, proposed D) ([]D, []D) {
	// A record on a node missing from the config counts nowhere; requests for
	// that machine still fail, but every other machine keeps its capacity view.
	on := func(m D) bool { n, ok := e.P.lookupNode(m); return ok && n.Name == node.Name }
	reservations := filter(e.S.Objects("machines"), on)
	if proposed != nil {
		reservations = filter(reservations, func(m D) bool { return integer(m["vmid"]) != integer(proposed["vmid"]) })
		if on(proposed) {
			reservations = append(reservations, proposed)
		}
	}
	snapshots := filter(e.S.Objects("snapshots"), func(s D) bool {
		m := e.S.Get("machines", str(s["vmid"]))
		return m == nil && node == e.P.Nodes()[0] || m != nil && on(m)
	})
	return reservations, snapshots
}

// nodeCapacities summarizes every node. Store reads stay on this goroutine;
// only the node adapters are asked in parallel.
func (e *Execution) nodeCapacities(proposed D, cached bool) ([]D, int) {
	nodes := e.P.Nodes()
	if len(nodes) == 1 {
		return []D{e.nodeCapacity(nodes[0], proposed, cached)}, 0
	}
	inventories := make([]any, len(nodes))
	times := make([]time.Time, len(nodes))
	failures := make([]any, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			failures[i] = attempt(func() {
				fetch := func(ctx context.Context) (any, error) { return e.P.Backend.Call(ctx, D{"op": "inventory"}, n.Target) }
				var err error
				if cached {
					inventories[i], times[i], err = e.P.inventoryCache(n.Target).Get(e.Ctx, 2*time.Second, fetch)
				} else {
					inventories[i], err = fetch(e.Ctx)
					times[i] = time.Now()
				}
				must(err)
			})
		}()
	}
	wg.Wait()
	out := []D{}
	var failure any
	for i, n := range nodes {
		if failures[i] != nil {
			failure = failures[i]
			continue
		}
		reservations, snapshots := e.nodeLoad(n, proposed)
		out = append(out, summarize(obj(inventories[i]), reservations, snapshots, times[i]))
	}
	// Observations skip an unreachable node; fresh reads fail closed.
	if failure != nil && (!cached || len(out) == 0) {
		panic(failure)
	}
	return out, len(nodes) - len(out)
}

// combine sums node summaries for members and the public status page. Each
// machine still has to fit on one node, so every dimension also reports the
// most any single node has left.
func combine(nodes []D) D {
	if len(nodes) == 1 {
		return nodes[0]
	}
	out := copyValue(nodes[0]).(map[string]any)
	sum := func(path ...string) float64 {
		total := 0.0
		for _, c := range nodes {
			v := any(c)
			for _, k := range path {
				v = obj(v)[k]
			}
			total += num(v)
		}
		return total
	}
	at := func(v any, path ...string) D {
		for _, k := range path {
			v = obj(v)[k]
		}
		return obj(v)
	}
	cpus := sum("physical", "cpu", "logical_cpus")
	utilization := 0.0
	for _, c := range nodes {
		utilization += num(at(c, "physical", "cpu")["utilization"]) * num(at(c, "physical", "cpu")["logical_cpus"])
	}
	cpu := at(out, "physical", "cpu")
	cpu["logical_cpus"], cpu["cores"] = cpus, sum("physical", "cpu", "cores")
	if cpus > 0 {
		cpu["utilization"] = utilization / cpus
	}
	for _, k := range []string{"total", "used", "free"} {
		at(out, "physical", "memory")[k] = sum("physical", "memory", k)
	}
	disk := at(out, "physical", "disk")
	for _, k := range []string{"total", "used", "free", "snapshot_reserved_gib"} {
		disk[k] = sum("physical", "disk", k)
	}
	metadata := 0.0
	for _, c := range nodes {
		metadata = max(metadata, num(at(c, "physical", "disk")["metadata_fraction"]))
	}
	disk["metadata_fraction"] = metadata
	for _, dim := range []string{"vcpu", "memory_gib", "disk_gib"} {
		a := at(out, "allocatable", dim)
		largest := 0.0
		for _, c := range nodes {
			largest = max(largest, num(at(c, "allocatable", dim)["remaining"]))
		}
		for _, k := range []string{"limit", "committed", "remaining"} {
			a[k] = sum("allocatable", dim, k)
		}
		a["largest_node_remaining"] = largest
	}
	policy := at(out, "policy")
	policy["snapshot_headroom_gib"] = sum("policy", "snapshot_headroom_gib")
	blocked := true
	for _, c := range nodes {
		blocked = blocked && boolean(at(c, "policy")["storage_admission_blocked"])
	}
	policy["storage_admission_blocked"] = blocked
	policy["placement"] = "each machine runs on one node; the node with the most memory left that admits it"
	out["scope"] = fmt.Sprintf("%d nodes; shared with infrastructure and other tenants", len(nodes))
	out["node_count"] = len(nodes)
	return out
}

func (e *Execution) admitOn(node nodeRef, cpu, memory, disk float64, proposed D, snapshot bool) (D, D) {
	c := e.nodeCapacity(node, proposed, false)
	for k, amount := range map[string]float64{"vcpu": cpu, "memory_gib": memory / 1024, "disk_gib": disk} {
		allocation := obj(obj(c["allocatable"])[k])
		if amount+num(allocation["committed"]) > num(allocation["limit"]) {
			fail("capacity_exhausted", "Node admission limit", D{"dimension": k, "requested": amount, "remaining": allocation["remaining"]})
		}
	}
	policy := obj(c["policy"])
	if snapshot && disk > num(policy["snapshot_headroom_gib"]) {
		fail("capacity_exhausted", "Snapshot worst-case reservation exceeds safe physical headroom")
	}
	growing := disk > 0
	if proposed != nil {
		old := e.S.Get("machines", str(proposed["vmid"]))
		growing = growing || num(proposed["disk_gb"]) > num(old["disk_gb"])
	}
	if growing && boolean(policy["storage_admission_blocked"]) {
		fail("capacity_exhausted", "Storage usage exceeds admission ceiling")
	}
	return D{"accepted": true, "checked_at": c["checked_at"], "reserved": false}, c
}

// Place picks the node for new machines: among the nodes that admit the whole
// request, the one with the most memory left after it. Nothing is reserved;
// apply places again inside its own admission check.
func (e *Execution) Place(cpu, memory, disk float64) (nodeRef, D) {
	nodes := e.P.Nodes()
	if len(nodes) == 1 {
		admission, _ := e.admitOn(nodes[0], cpu, memory, disk, nil, false)
		return nodes[0], admission
	}
	var best nodeRef
	var admission D
	var refusal any
	most := -1.0
	for _, n := range nodes {
		var accepted, c D
		if f := attempt(func() { accepted, c = e.admitOn(n, cpu, memory, disk, nil, false) }); f != nil {
			if _, ok := f.(Failure); !ok {
				panic(f)
			}
			refusal = f
			continue
		}
		if left := num(obj(obj(c["allocatable"])["memory_gib"])["remaining"]) - memory/1024; left > most {
			best, admission, most = n, accepted, left
		}
	}
	if most < 0 {
		panic(refusal)
	}
	return best, admission
}

// record stores the node on a machine; the unnamed legacy node stores none.
func (n nodeRef) record(spec D) D {
	if n.Name == "" {
		return spec
	}
	return merge(spec, D{"node": n.Name})
}

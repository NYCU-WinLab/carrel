package carrel

import (
	"context"
	"testing"
)

func TestCloudInitBytesAreKeptAndSentBackOnBoot(t *testing.T) {
	p, b := fixture(t)
	files := D{"user": "#cloud-config\n{\"hostname\":\"web\"}", "network": "{\"version\":2}"}
	var actions []D
	b.call = func(r D, _ string) (any, error) {
		switch r["op"] {
		case "create":
			return D{"state": "running", "cloud_init": files}, nil
		case "action":
			actions = append(actions, r)
			if r["action"] == "shutdown" {
				return D{"power_state": "stopped", "changed": true}, nil
			}
			return D{"power_state": "running", "changed": true}, nil
		}
		return D{}, nil
	}
	e := p.execution(context.Background())
	m := seedMachine(p, "web", 10100)
	e.Provision(m, false)
	r, ok := rowOf[cloudInitRecord](p.Store, "cloud_init", "10100")
	if !ok || r.User != files["user"] || r.NetworkSHA256 != digest(str(files["network"])) {
		t.Fatalf("%+v", r)
	}
	tenant := p.Store.TenantN(1)
	attempt(func() { e.PowerMachine(p.Store.Get("machines", "10100"), D{"action": "shutdown"}, tenant) })
	attempt(func() { e.PowerMachine(p.Store.Get("machines", "10100"), D{"action": "start"}, tenant) })
	if len(actions) != 2 || actions[0]["cloud_init"] != nil || !equal(actions[1]["cloud_init"], files) {
		t.Fatal("start must carry the stored files and shutdown must not", actions)
	}
	// A changed copy is never sent: the node keeps what it has.
	r.User += " "
	p.Store.Put("cloud_init", 10100, 1, decode(string(encoded(r))))
	if e.cloudInitFiles(p.Store.Get("machines", "10100")) != nil {
		t.Fatal("sent files that do not match their checksum")
	}
}

func TestCollectCloudInitReadsOnlyVMsWithoutACopy(t *testing.T) {
	p, b := fixture(t)
	seedMachine(p, "old", 10100)
	ct := seedMachine(p, "box", 10101)
	ct["kind"] = "ct"
	p.Store.Put("machines", 10101, 1, ct)
	reads := 0
	b.call = func(r D, _ string) (any, error) {
		if r["op"] == "cloud_init_read" {
			reads++
			return D{"cloud_init": D{"user": "u", "network": "n"}}, nil
		}
		return D{}, nil
	}
	e := p.execution(context.Background())
	if e.CollectCloudInit() != 1 || e.CollectCloudInit() != 0 || reads != 1 {
		t.Fatal("collect must read each VM once", reads)
	}
}

package carrel

import (
	"context"
	"errors"
	"testing"
)

func TestAFailedVIPRemovalCanBeRetried(t *testing.T) {
	p, b := fixture(t)
	seedMachine(p, "cp1", 10100)
	runQueue(p)
	ctx, who := context.Background(), person("alice", false)
	r := p.Execute(ctx, "vip_add", D{"name": "api", "machines": []any{"cp1"}}, who)
	if obj(r["operation"])["state"] != "succeeded" {
		t.Fatal(r)
	}
	b.call = func(r D, _ string) (any, error) {
		if r["op"] == "reconcile" {
			return nil, errors.New("node down")
		}
		return D{}, nil
	}
	r = p.Execute(ctx, "vip_remove", D{"name": "api"}, who)
	if obj(r["operation"])["state"] != "failed" || p.Store.Objects("vips", 1)[0]["state"] != "deleting" {
		t.Fatal("the failed removal must leave the address visible", r)
	}
	if r := p.Execute(ctx, "vip_add", D{"name": "api", "machines": []any{"cp1"}}, who); obj(obj(r["operation"])["error"])["recovery"] != "finish_cleanup" {
		t.Fatal("the name came back while it was being removed", r)
	}
	b.call = nil
	r = p.Execute(ctx, "vip_remove", D{"name": "api"}, who)
	if obj(r["operation"])["state"] != "succeeded" || len(p.Store.Objects("vips", 1)) != 0 {
		t.Fatal("a second removal must finish", r)
	}
}

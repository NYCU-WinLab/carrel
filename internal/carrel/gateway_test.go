package carrel

import (
	"context"
	"strings"
	"testing"
)

func gatewayState(t *testing.T) (D, D) {
	crt, key := testPair(t, "*.zyx1121.winlab.tw")
	originCrt, originKey := testPair(t, "carrel.winlab.tw")
	state := D{
		"tenants":      []any{D{"n": 3, "slug": "zyx1121"}},
		"machines":     []any{D{"vmid": 10300, "tenant_n": 3, "name": "book", "ip": "10.200.3.10"}},
		"domains":      []any{D{"id": "7", "vmid": 10300, "sub": "book", "name": "book.zyx1121.winlab.tw", "target_port": 3000, "state": "ready"}},
		"certificates": []any{D{"slug": "zyx1121", "fullchain": string(crt), "privkey": string(key)}},
	}
	return state, D{"fullchain": string(originCrt), "privkey": string(originKey)}
}

func TestGatewayServesTheOriginAndTenantWildcardsOverTLS(t *testing.T) {
	state, origin := gatewayState(t)
	caddy, hosts, certificates := gatewayConfig(state, "carrel.winlab.tw", origin, dicts(state["certificates"]))
	if len(certificates) != 2 || certificates["_origin"] == nil || certificates["zyx1121"] == nil {
		t.Fatal("certificates", len(certificates))
	}
	if hosts != "10.200.3.10 book.zyx1121.internal\n" {
		t.Fatalf("hosts %q", hosts)
	}
	if !strings.Contains(caddy, "http:// {\n redir https://{host}{uri} 308\n}") {
		t.Fatal("no HTTPS redirect")
	}
	block := strings.SplitN(strings.SplitN(caddy, "https://carrel.winlab.tw {", 2)[1], "\n}\n", 2)[0]
	for _, want := range []string{
		"tls /etc/caddy/carrel-certs/_origin/fullchain.pem /etc/caddy/carrel-certs/_origin/privkey.pem",
		"@control path /mcp /mcp/* /oauth/* /.well-known/* /healthz /status /internal/* /apps/*",
		"reverse_proxy 10.200.0.3:8080", "flush_interval -1", "stream_close_delay 5m", "root * /srv/carrel-site", "hide .*",
	} {
		if !strings.Contains(block, want) {
			t.Fatalf("origin block lacks %q", want)
		}
	}
	tenant := strings.SplitN(caddy, "https://*.zyx1121.winlab.tw {", 2)[1]
	for _, want := range []string{"@d7 host book.zyx1121.winlab.tw", "reverse_proxy 10.200.3.10:3000", "respond 404"} {
		if !strings.Contains(tenant, want) {
			t.Fatalf("tenant block lacks %q", want)
		}
	}
}

func TestGatewayRefusesWrongCertificates(t *testing.T) {
	for name, change := range map[string]func(D, D){
		"another name": func(s, _ D) {
			crt, key := testPair(t, "*.bensonho.winlab.tw")
			s["certificates"] = []any{D{"slug": "zyx1121", "fullchain": string(crt), "privkey": string(key)}}
		},
		"another key": func(s, _ D) {
			_, key := testPair(t, "*.zyx1121.winlab.tw")
			obj(arr(s["certificates"])[0])["privkey"] = string(key)
		},
		"missing tenant pair": func(s, _ D) { s["certificates"] = []any{} },
		"origin for another name": func(_, origin D) {
			crt, key := testPair(t, "other.winlab.tw")
			origin["fullchain"], origin["privkey"] = string(crt), string(key)
		},
		"domain outside its tenant": func(s, _ D) { obj(arr(s["domains"])[0])["name"] = "book.bensonho.winlab.tw" },
	} {
		state, origin := gatewayState(t)
		change(state, origin)
		if attempt(func() { gatewayConfig(state, "carrel.winlab.tw", origin, dicts(state["certificates"])) }) == nil {
			t.Fatalf("accepted %s", name)
		}
	}
}

func TestGatewayWithoutAnOriginPairServesTenantsOnly(t *testing.T) {
	state, _ := gatewayState(t)
	caddy, _, certificates := gatewayConfig(state, "carrel.winlab.tw", nil, dicts(state["certificates"]))
	if strings.Contains(caddy, "carrel.winlab.tw {") || len(certificates) != 1 {
		t.Fatal(caddy)
	}
}

func TestATenantNamedOriginKeepsItsOwnCertificate(t *testing.T) {
	state, origin := gatewayState(t)
	crt, key := testPair(t, "*.origin.winlab.tw")
	state["tenants"] = []any{D{"n": 3, "slug": "origin"}}
	obj(arr(state["domains"])[0])["name"] = "book.origin.winlab.tw"
	state["certificates"] = []any{D{"slug": "origin", "fullchain": string(crt), "privkey": string(key)}}
	caddy, _, certificates := gatewayConfig(state, "carrel.winlab.tw", origin, dicts(state["certificates"]))
	if len(certificates) != 2 || certificates["_origin"]["fullchain"] == certificates["origin"]["fullchain"] {
		t.Fatal("the tenant took carrel's pair")
	}
	if !strings.Contains(caddy, "/etc/caddy/carrel-certs/origin/fullchain.pem") || !strings.Contains(caddy, "/etc/caddy/carrel-certs/_origin/fullchain.pem") {
		t.Fatal(caddy)
	}
}

func TestSyncGatewayReturnsTheFingerprintsItSent(t *testing.T) {
	p, b, _ := originFixture(t)
	var sent D
	b.call = func(r D, target string) (any, error) {
		if target == "carrel-gateway" {
			sent = r
		}
		return D{}, nil
	}
	state, _ := gatewayState(t)
	held := p.execution(context.Background()).SyncGateway(state)
	pair := obj(obj(sent["certificates"])["_origin"])
	if sent["op"] != "sync" || held["_origin"] != fingerprint(pair["fullchain"]) || held["zyx1121"] == nil {
		t.Fatal(held)
	}
}

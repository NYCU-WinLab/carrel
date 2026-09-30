import asyncio
import base64
import hashlib
import re
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.requests import Request

from carrel.auth import OAuth, Verifier, challenge, digest, identity
from carrel.pages import consent_page
from carrel.platform import Platform
from carrel.server import build
from carrel.store import Store, mask


def person(name="alice", admin=False, projects=()):
    return {"sub": name, "username": name, "admin": admin, "projects": list(projects)}


class Backend:
    def __init__(self):
        self.calls = []

    async def call(self, request, target=None):
        self.calls.append(request)
        if request["op"] == "inventory":
            return {
                "status": {"cpuinfo": {"cpus": 32}, "memory": {"total": 192 * 1024**3}},
                "storage": {"total": 1500 * 1024**3, "used": 10 * 1024**3},
                "resources": [],
            }
        return {"status": "running"}

    async def reconcile(self, state):
        self.calls.append({"op": "reconcile", "state": state})
        return {"changed": []}


@pytest.fixture
def platform():
    store = Store(":memory:")
    store.register("user:alice", "alice")
    store.register("user:bob", "bob")
    store.register("winlab-projects/shared", "shared")
    return Platform(store, Backend(), {})


def test_group_boundaries():
    base = {"sub": "x", "preferred_username": "x"}
    for groups in [
        ["/vm-users"],
        ["/lab-member/alumni"],
        ["/winlab-admin/child"],
        ["/lab-member/master/child"],
        "winlab-admin",
    ]:
        with pytest.raises(ValueError):
            identity({**base, "groups": groups})
    assert identity({**base, "groups": ["/lab-member/master", "/winlab-projects/shared"]})["projects"] == [
        "winlab-projects/shared"
    ]


@pytest.mark.asyncio
async def test_signature_audience_and_authorized_party():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = Verifier("https://issuer.test/realm", "carrel-mcp")
    verifier.jwks = SimpleNamespace(get_signing_key_from_jwt=lambda _: SimpleNamespace(key=key.public_key()))
    claims = {
        "iss": verifier.issuer,
        "aud": "carrel-mcp",
        "azp": "carrel-mcp",
        "sub": "alice",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
        "preferred_username": "alice",
        "groups": ["/lab-member/master"],
    }
    assert (await verifier.verify(jwt.encode(claims, key, algorithm="RS256")))["sub"] == "alice"
    for mutation in [
        {"aud": "other-service"},
        {"azp": "other-client"},
        {"exp": 1},
        {"iss": "https://evil.test"},
    ]:
        with pytest.raises((jwt.PyJWTError, ValueError)):
            await verifier.verify(jwt.encode({**claims, **mutation}, key, algorithm="RS256"))


@pytest.mark.asyncio
async def test_tenant_idor_and_admin_tools(platform):
    for op, args in [
        ("quota_get", {"tenant": "bob"}),
        ("quota_set", {"tenant": "alice", "dimension": "vcpu", "amount": 100}),
        ("quota_get", {"tenant": "shared"}),
    ]:
        result = await platform.execute(op, args, person())
        assert result["error"]["code"] == "forbidden"
    result = await platform.execute(
        "quota_get", {"tenant": "shared"}, person(projects=["winlab-projects/shared"])
    )
    assert result["ok"]


@pytest.mark.asyncio
async def test_dry_run_reserves_nothing_and_quota_precedes_backend(platform):
    args = {"name": "test", "kind": "vm", "ssh_keys": ["ssh-ed25519 " + "A" * 44], "dry_run": True}
    assert (await platform.execute("machine_create", args, person()))["ok"]
    assert not platform.store.objects("machines")
    assert not platform.store.objects("ports")
    assert all(c["op"] == "inventory" for c in platform.backend.calls)
    platform.backend.calls.clear()
    result = await platform.execute("machine_create", {**args, "cpu": 64}, person())
    assert result["error"]["code"] == "quota_exceeded"
    assert not platform.backend.calls


@pytest.mark.asyncio
async def test_private_network_ownership_and_attached_delete(platform):
    r = await platform.execute("network_create", {"name": "lan"}, person())
    net = r["network"]
    platform.store.put(
        "machines",
        10100,
        1,
        {
            "vmid": 10100,
            "name": "router",
            "tenant_n": 1,
            "cpu": 2,
            "memory_mb": 2048,
            "disk_gb": 20,
            "nics": [{"index": 1, "network": net["id"]}],
        },
    )
    r = await platform.execute("network_delete", {"network": "lan", "confirm": "lan"}, person())
    assert r["error"]["code"] == "conflict"
    r = await platform.execute("network_delete", {"network": net["id"], "confirm": "lan"}, person("bob"))
    assert r["error"]["code"] == "not_found"


@pytest.mark.asyncio
async def test_concurrent_network_quota(platform):
    results = await asyncio.gather(
        *[platform.execute("network_create", {"name": f"lan{i}"}, person()) for i in range(6)]
    )
    assert sum(r["ok"] for r in results) == 4
    assert len(platform.store.objects("networks", 1)) == 4


def request(path, method="GET", body=b"", headers=()):
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": method,
            "path": path.split("?")[0],
            "query_string": path.partition("?")[2].encode(),
            "headers": list(headers),
            "scheme": "https",
            "server": ("carrel.test", 443),
        },
        receive,
    )


@pytest.mark.asyncio
async def test_oauth_redirect_and_pkce_binding():
    store = Store(":memory:")
    oauth = OAuth(store, "https://carrel.test", "https://issuer.test", "carrel-mcp", None)
    for url in [
        "https://evil.test/callback",
        "http://127.0.0.1.evil.test:123/cb",
        "http://user@localhost:123/cb",
        "http://localhost:123/cb#fragment",
    ]:
        assert not oauth.allowed_redirect(url)
    assert oauth.allowed_redirect("http://127.0.0.1:12345/callback")
    store.oauth_put("client", "a", {"client_id": "a", "redirect_uris": ["http://localhost:1234/cb"]}, 600)
    store.oauth_put("client", "b", {"client_id": "b", "redirect_uris": ["http://localhost:1234/cb"]}, 600)
    v = "x" * 50
    store.oauth_put(
        "code",
        digest("code"),
        {"client": "a", "redirect": "http://localhost:1234/cb", "challenge": challenge(v)},
        120,
    )
    body = f"grant_type=authorization_code&client_id=b&code=code&redirect_uri=http://localhost:1234/cb&code_verifier={v}".encode()
    result = await oauth.route(
        request("/oauth/token", "POST", body, [(b"content-type", b"application/x-www-form-urlencoded")])
    )
    assert result.status_code == 400
    assert store.oauth_get("code", digest("code"))  # foreign client cannot consume it
    # Callback with no browser cookie, even with known state, is rejected.
    store.oauth_put("state", "state", {"cookie": digest("real-cookie")}, 600)
    result = await oauth.route(request("/oauth/callback?state=state&code=code&iss=https://issuer.test"))
    assert result.status_code == 400


def test_audit_redaction():
    assert mask(
        {"password": "secret", "nested": {"refresh_token": "secret"}, "runcmd": [["echo", "secret"]]}
    ) == {"password": "[redacted]", "nested": {"refresh_token": "[redacted]"}, "runcmd": "[redacted]"}


@pytest.mark.asyncio
async def test_browser_consent_referrer_policy_and_csrf_boundaries():
    store = Store(":memory:")
    origin = "https://carrel.test"
    app = build(
        {"origin": origin, "issuer": "https://issuer.test", "database": ":memory:"},
        backend=Backend(),
        store=store,
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=origin) as client:
        client.cookies.set("carrel_oauth", "browser-cookie", domain="carrel.test", path="/oauth")

        async def begin():
            store.oauth_put(
                "state",
                "state",
                {
                    "client": "desktop",
                    "name": '<script>alert("x")</script>',
                    "redirect": "http://127.0.0.1:12345/callback",
                    "state": "client-state",
                    "challenge": challenge("v" * 50),
                    "cookie": digest("browser-cookie"),
                },
                300,
            )
            page = await client.get(
                "/oauth/callback",
                params={"state": "state", "code": "upstream-code", "iss": "https://issuer.test"},
            )
            assert page.status_code == 200
            # no-referrer causes browser navigation POSTs to send Origin: null.
            # Preserve an origin-only referrer and the strict origin guard.
            assert page.headers["referrer-policy"] == "strict-origin"
            assert page.headers["cache-control"] == "no-store"
            assert '<script>alert("x")</script>' not in page.text
            assert "&lt;script&gt;" in page.text
            assert "upstream-code" not in page.text
            css = re.search(r"<style>(.*?)</style>", page.text, re.DOTALL)[1]
            css_hash = base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()
            assert f"style-src 'sha256-{css_hash}'" in page.headers["content-security-policy"]
            assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
            assert "form-action 'self' http://127.0.0.1:12345;" in page.headers["content-security-policy"]
            return re.search(r'name="consent" value="([^"]+)"', page.text)[1]

        nonce = await begin()
        for bad_origin in ["https://evil.test", "null"]:
            result = await client.post(
                "/oauth/consent",
                data={"consent": nonce, "allow": "yes"},
                headers={"Origin": bad_origin},
            )
            assert result.status_code == 403
            assert not store.oauth_get("code", digest("upstream-code"))
            assert store.oauth_get("consent", nonce)

        result = await client.post(
            "/oauth/consent", data={"consent": nonce, "allow": "yes"}, headers={"Origin": origin}
        )
        assert result.status_code == 302
        query = parse_qs(urlsplit(result.headers["location"]).query)
        assert query == {"state": ["client-state"], "iss": [origin], "code": ["upstream-code"]}
        result = await client.post(
            "/oauth/consent", data={"consent": nonce, "allow": "yes"}, headers={"Origin": origin}
        )
        assert result.status_code == 400  # consent is one-use
        store.oauth_pop("code", digest("upstream-code"))

        nonce = await begin()
        result = await client.post("/oauth/consent", data={"consent": nonce, "allow": "yes"})
        assert result.status_code == 400  # absent Origin does not bypass the guard

        nonce = await begin()
        client.cookies.set("carrel_oauth", "another-browser", domain="carrel.test", path="/oauth")
        result = await client.post(
            "/oauth/consent", data={"consent": nonce, "allow": "yes"}, headers={"Origin": origin}
        )
        assert result.status_code == 400  # origin alone is not authorization
        assert not store.oauth_get("code", digest("upstream-code"))

        client.cookies.set("carrel_oauth", "browser-cookie", domain="carrel.test", path="/oauth")
        nonce = await begin()
        result = await client.post(
            "/oauth/consent", data={"consent": nonce, "allow": "no"}, headers={"Origin": origin}
        )
        assert result.status_code == 302
        assert parse_qs(urlsplit(result.headers["location"]).query)["error"] == ["access_denied"]
        assert not store.oauth_get("code", digest("upstream-code"))


@pytest.mark.parametrize(
    ("redirect", "origin"),
    [
        ("http://localhost:1234/callback", "http://localhost:1234"),
        ("http://[::1]:1234/callback", "http://[::1]:1234"),
        ("https://client.test/cb?next=;script-src%20*", "https://client.test"),
    ],
)
def test_consent_csp_allows_only_registered_callback_origin(redirect, origin):
    policy = consent_page("client", redirect, "nonce").headers["content-security-policy"]
    assert f"form-action 'self' {origin};" in policy
    assert "script-src" not in policy


@pytest.mark.parametrize(
    "redirect",
    [
        "https://client.test;script-src*/cb",
        "http://[::1%zone;script-src*]:1234/cb",
        "javascript:alert(1)",
        "https://user@client.test/cb",
    ],
)
def test_consent_csp_rejects_invalid_origin(redirect):
    with pytest.raises(ValueError):
        consent_page("client", redirect, "nonce")


@pytest.mark.asyncio
async def test_real_mcp_transport_requires_identity_and_hides_admin_tools():
    class TestVerifier:
        async def verify(self, token):
            if token != "test":
                raise ValueError("invalid")
            return person()

    app = build(
        {"origin": "https://carrel.test", "issuer": "https://issuer.test", "database": ":memory:"},
        backend=Backend(),
        verifier=TestVerifier(),
    )
    async with (
        app.app.router.lifespan_context(app.app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="https://carrel.test") as client,
    ):
        r = await client.post("/mcp", json={})
        assert r.status_code == 401 and "resource_metadata=" in r.headers["www-authenticate"]
        headers = {"Authorization": "Bearer test", "Accept": "application/json, text/event-stream"}
        r = await client.post(
            "/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        )
        assert r.status_code == 200, r.text
        names = {t["name"] for t in r.json()["result"]["tools"]}
        assert "machine_create" in names and "quota_set" not in names
        r = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "quota_set",
                    "arguments": {"tenant": "alice", "dimension": "vcpu", "amount": 100},
                },
            },
        )
        assert r.json()["result"]["structuredContent"]["error"]["code"] == "forbidden"


@pytest.mark.asyncio
async def test_expired_quota_blocks_restart_until_allocations_fit(platform):
    platform.store.put(
        "machines",
        10100,
        1,
        {
            "vmid": 10100,
            "name": "test",
            "tenant_n": 1,
            "cpu": 9,
            "memory_mb": 1024,
            "disk_gb": 12,
            "state": "stopped",
        },
    )
    r = await platform.execute("machine_power", {"machine": "test", "action": "start"}, person())
    assert r["error"]["code"] == "quota_exceeded"
    assert not platform.backend.calls


@pytest.mark.asyncio
async def test_snapshot_cannot_restore_outdated_network_configuration(platform):
    platform.store.put(
        "machines",
        10100,
        1,
        {
            "vmid": 10100,
            "name": "test",
            "tenant_n": 1,
            "cpu": 1,
            "memory_mb": 1024,
            "disk_gb": 12,
            "nics": [{"index": 1, "network": "p00101"}],
        },
    )
    platform.store.put(
        "snapshots",
        "10100-before",
        1,
        {
            "id": "10100-before",
            "vmid": 10100,
            "name": "before",
            "disk_gb": 12,
            "configuration": {"cpu": 1, "memory_mb": 1024, "disk_gb": 12, "nics": []},
        },
    )
    r = await platform.execute(
        "snapshot_rollback", {"machine": "test", "name": "before", "confirm": "before"}, person()
    )
    assert r["error"]["code"] == "conflict"
    assert not platform.backend.calls


@pytest.mark.asyncio
async def test_interrupted_snapshot_keeps_disk_reservation(platform):
    platform.store.put(
        "machines",
        10100,
        1,
        {
            "vmid": 10100,
            "name": "test",
            "tenant_n": 1,
            "cpu": 1,
            "memory_mb": 1024,
            "disk_gb": 12,
            "nics": [],
        },
    )

    async def interrupted(request):
        raise RuntimeError("adapter interrupted after snapshot creation")

    platform.backend.call = interrupted
    r = await platform.execute("snapshot_create", {"machine": "test", "name": "before"}, person())
    assert not r["ok"]
    assert platform.quota(platform.store.tenant("user:alice"))["used"]["disk_gb"] == 24
    assert platform.store.objects("snapshots", 1)[0]["state"] == "creating"


@pytest.mark.asyncio
async def test_interrupted_resize_keeps_reservation_and_can_retry(platform):
    platform.store.put(
        "machines",
        10100,
        1,
        {
            "vmid": 10100,
            "name": "test",
            "tenant_n": 1,
            "cpu": 1,
            "memory_mb": 1024,
            "disk_gb": 12,
            "nics": [],
        },
    )
    original = platform.backend.call

    async def interrupted(request):
        if request["op"] == "action":
            raise RuntimeError("adapter interrupted after disk growth")
        return await original(request)

    platform.backend.call = interrupted
    r = await platform.execute("machine_resize", {"machine": "test", "disk_gb": 30}, person())
    assert not r["ok"]
    assert platform.quota(platform.store.tenant("user:alice"))["used"]["disk_gb"] == 30
    platform.backend.call = original
    r = await platform.execute("machine_resize", {"machine": "test", "disk_gb": 30}, person())
    assert r["ok"] and "resize_from" not in platform.store.objects("machines", 1)[0]

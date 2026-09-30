import asyncio
import time
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.requests import Request

from carrel.auth import OAuth, Verifier, challenge, digest, identity
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

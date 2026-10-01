import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
import pytest
from starlette.requests import Request

from carrel.auth import CLIENT_TTL, OAuth, challenge, digest
from carrel.server import build
from carrel.store import Store


def request(path, **data):
    async def receive():
        return {"type": "http.request", "body": urlencode(data).encode(), "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST" if data else "GET",
            "path": path.split("?")[0],
            "query_string": path.partition("?")[2].encode(),
            "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
            "scheme": "https",
            "server": ("carrel.test", 443),
        },
        receive,
    )


@pytest.fixture
def flow(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "auth.db"))
    verifier = SimpleNamespace(verify=AsyncMock(return_value={"sub": "alice"}))
    oauth = OAuth(store, "https://carrel.test", "https://issuer.test", "carrel-mcp", verifier)
    client = {"client_id": "desktop", "client_name": "Codex", "redirect_uris": ["http://localhost:1234/cb"]}
    store.oauth_put("client", "desktop", client, CLIENT_TTL)
    store.oauth_put("client", "other", {**client, "client_id": "other"}, CLIENT_TTL)
    store.oauth_put("refresh", digest("old-refresh"), {"client": "desktop"}, 1800)
    tokens = {
        "access_token": "access",
        "refresh_token": "new-refresh",
        "expires_in": 300,
        "refresh_expires_in": 0,
        "scope": "openid profile email offline_access",
    }
    state = SimpleNamespace(oauth=oauth, store=store, verifier=verifier, calls=[], tokens=tokens, error=None)

    def upstream(req):
        state.calls.append(req)
        if isinstance(state.error, Exception):
            raise state.error
        return state.error if state.error is not None else httpx.Response(200, json=state.tokens)

    client_class = httpx.AsyncClient
    monkeypatch.setattr(
        "carrel.auth.httpx.AsyncClient",
        lambda **kw: client_class(transport=httpx.MockTransport(upstream), **kw),
    )
    return state


def refresh(token="old-refresh", client="desktop"):
    return request("/oauth/token", grant_type="refresh_token", client_id=client, refresh_token=token)


def expiry(store, kind, id):
    return store.db.execute("SELECT expires FROM oauth WHERE kind=? AND id=?", (kind, id)).fetchone()[0]


@pytest.mark.asyncio
async def test_offline_discovery_and_authorization(flow):
    for path in ["/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource/mcp"]:
        metadata = json.loads((await flow.oauth.route(request(path))).body)
        assert "offline_access" in metadata["scopes_supported"]
    assert metadata["resource"] == "https://carrel.test/mcp"
    params = urlencode(
        {
            "client_id": "desktop",
            "redirect_uri": "http://localhost:1234/cb",
            "response_type": "code",
            "code_challenge": challenge("x" * 50),
            "code_challenge_method": "S256",
        }
    )
    result = await flow.oauth.route(request("/oauth/authorize?" + params))
    assert result.status_code == 302
    assert "offline_access" in parse_qs(urlsplit(result.headers["location"]).query)["scope"][0].split()


@pytest.mark.asyncio
async def test_offline_code_exchange_survives_restart_and_local_time_limits(flow, monkeypatch):
    flow.store.oauth_put(
        "code",
        digest("code"),
        {"client": "desktop", "redirect": "http://localhost:1234/cb", "challenge": challenge("x" * 50)},
        120,
    )
    result = await flow.oauth.route(
        request(
            "/oauth/token",
            grant_type="authorization_code",
            client_id="desktop",
            code="code",
            redirect_uri="http://localhost:1234/cb",
            code_verifier="x" * 50,
        )
    )
    assert result.status_code == 200
    assert not flow.store.oauth_get("code", digest("code"))
    assert expiry(flow.store, "refresh", digest("new-refresh")) == 0
    assert expiry(flow.store, "client", "desktop") == 0
    assert "new-refresh" not in flow.store.db.execute("SELECT group_concat(data) FROM oauth").fetchone()[0]
    path = flow.store.db.execute("PRAGMA database_list").fetchone()[2]
    flow.store.db.close()
    flow.oauth.store = reopened = Store(path)
    # Only the facade clock changes: Keycloak remains the authority on idle/revocation.
    monkeypatch.setattr("carrel.store.time.time", lambda: 4_000_000_000)
    reopened.purge_oauth()
    assert reopened.oauth_get("client", "desktop")
    assert not reopened.oauth_get("client", "other")  # unused DCR registrations expire
    assert (await flow.oauth.route(refresh("new-refresh"))).status_code == 200
    assert expiry(reopened, "refresh", digest("new-refresh")) == 0
    assert expiry(reopened, "client", "desktop") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("rotation", ["same", "new", "omitted"])
async def test_refresh_rotation_and_omitted_replacement(flow, rotation):
    if rotation == "same":
        flow.tokens["refresh_token"] = "old-refresh"
    elif rotation == "omitted":
        del flow.tokens["refresh_token"]
    result = await flow.oauth.route(refresh())
    assert result.status_code == 200
    assert bool(flow.store.oauth_get("refresh", digest("old-refresh"))) == (rotation != "new")
    if rotation == "new":
        assert (await flow.oauth.route(refresh())).status_code == 400
        assert len(flow.calls) == 1
    assert flow.verifier.verify.await_count == 1


@pytest.mark.asyncio
async def test_online_refresh_honors_expiry_and_renews_registration(flow, monkeypatch):
    monkeypatch.setattr("carrel.store.time.time", lambda: 100)
    flow.tokens.update(scope="openid profile email", refresh_expires_in=86400 * 45)
    assert (await flow.oauth.route(refresh())).status_code == 200
    assert expiry(flow.store, "refresh", digest("new-refresh")) == 100 + 86400 * 45
    assert expiry(flow.store, "client", "desktop") == 100 + CLIENT_TTL
    monkeypatch.setattr("carrel.store.time.time", lambda: 101 + 86400 * 45)
    assert (await flow.oauth.route(refresh("new-refresh"))).status_code == 400
    assert len(flow.calls) == 1


@pytest.mark.asyncio
async def test_refresh_client_binding_and_membership_are_still_checked(flow):
    assert (await flow.oauth.route(refresh(client="other"))).status_code == 400
    assert not flow.calls
    flow.verifier.verify.side_effect = ValueError("current lab membership required")
    result = await flow.oauth.route(refresh())
    assert result.status_code == 400 and json.loads(result.body)["error"] == "invalid_grant"
    assert not flow.store.oauth_get("refresh", digest("new-refresh"))


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [503, 429, 401, "timeout", "bad-json", "invalid_client", "jwks"])
async def test_transient_errors_preserve_credentials(flow, failure):
    if isinstance(failure, int):
        flow.error = httpx.Response(failure, text="temporarily unavailable")
    elif failure == "timeout":
        flow.error = httpx.ReadTimeout("issuer unavailable")
    elif failure == "bad-json":
        flow.error = httpx.Response(200, text="not json")
    elif failure == "jwks":
        flow.verifier.verify.side_effect = jwt.PyJWKClientConnectionError("issuer unavailable")
    else:
        flow.error = httpx.Response(400, json={"error": failure})
    result = await flow.oauth.route(refresh())
    assert result.status_code == 503 and json.loads(result.body)["error"] == "temporarily_unavailable"
    assert flow.store.oauth_get("refresh", digest("old-refresh"))
    assert not flow.store.oauth_get("refresh", digest("new-refresh"))


@pytest.mark.asyncio
async def test_upstream_revocation_invalidates_local_binding(flow):
    flow.error = httpx.Response(400, json={"error": "invalid_grant"})
    result = await flow.oauth.route(refresh())
    assert result.status_code == 400 and json.loads(result.body)["error"] == "invalid_grant"
    assert not flow.store.oauth_get("refresh", digest("old-refresh"))
    assert (await flow.oauth.route(refresh())).status_code == 400
    assert len(flow.calls) == 1


@pytest.mark.asyncio
async def test_zero_expiry_requires_offline_scope(flow):
    flow.tokens["scope"] = "openid"
    assert (await flow.oauth.route(refresh())).status_code == 503
    assert not flow.store.oauth_get("refresh", digest("new-refresh"))
    assert expiry(flow.store, "client", "desktop") > 0


@pytest.mark.asyncio
async def test_refresh_can_omit_unchanged_scope(flow):
    assert (await flow.oauth.route(refresh())).status_code == 200
    del flow.tokens["scope"]
    assert (await flow.oauth.route(refresh("new-refresh"))).status_code == 200
    assert expiry(flow.store, "refresh", digest("new-refresh")) == 0
    assert expiry(flow.store, "client", "desktop") == 0


@pytest.mark.asyncio
async def test_revocation_is_client_bound_idempotent_and_retryable(flow):
    async def revoke(client="desktop", token="old-refresh"):
        return await flow.oauth.route(request("/oauth/revoke", client_id=client, token=token))

    assert (await revoke(client="other")).status_code == 200
    assert (await revoke(token="unknown")).status_code == 200
    assert not flow.calls and flow.store.oauth_get("refresh", digest("old-refresh"))
    flow.error = httpx.Response(503)
    assert (await revoke()).status_code == 503
    assert flow.store.oauth_get("refresh", digest("old-refresh"))
    flow.error = httpx.Response(200)
    assert (await revoke()).status_code == 200
    assert not flow.store.oauth_get("refresh", digest("old-refresh"))
    assert flow.calls[-1].url.path.endswith("/revoke")
    assert parse_qs(flow.calls[-1].content.decode())["client_id"] == ["carrel-mcp"]
    assert (await revoke()).status_code == 200 and len(flow.calls) == 2
    assert (await flow.oauth.route(refresh())).status_code == 400


@pytest.mark.asyncio
async def test_mcp_jwks_outage_does_not_request_reauthentication():
    verifier = SimpleNamespace(verify=AsyncMock(side_effect=jwt.PyJWKClientConnectionError("unavailable")))
    app = build(
        {"origin": "https://carrel.test", "issuer": "https://issuer.test", "database": ":memory:"},
        verifier=verifier,
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="https://carrel.test") as c:
        result = await c.post("/mcp", json={}, headers={"Authorization": "Bearer test"})
        assert result.status_code == 503 and "www-authenticate" not in result.headers
        metadata = (await c.get("/.well-known/oauth-authorization-server")).json()
        assert metadata["revocation_endpoint"] == "https://carrel.test/oauth/revoke"
        result = await c.post("/oauth/revoke", data={"client_id": "unknown", "token": "token"})
        assert result.status_code == 400 and result.json()["error"] == "invalid_client"

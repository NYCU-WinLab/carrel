"""Keycloak verification and a bounded, durable OAuth registration/PKCE facade.

The retired winfra-paas flow informed this design. Unlike its stateless shared
client shim, registrations, redirect URIs, PKCE, browser consent, authorization
codes and refresh tokens are bound to a specific client. No upstream token is
accepted without the carrel audience, issuer and authorized party.
"""

import asyncio
import base64
import hashlib
import re
import secrets
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from starlette.responses import JSONResponse, RedirectResponse

from .pages import consent_page

ACTIVE = {"112", "113", "114", "115", "master", "doctoral", "undergrad", "assistant", "teacher"}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def challenge(value):
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).rstrip(b"=").decode()


def identity(claims):
    groups = claims.get("groups", [])
    if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
        raise ValueError("missing groups claim")
    groups = [g.removeprefix("/") for g in groups]
    admin = "winlab-admin" in groups
    active = any(g == "lab-member/" + name for name in ACTIVE for g in groups)
    if not (admin or active):
        raise ValueError("current lab membership required")
    username = claims.get("preferred_username")
    if not isinstance(username, str) or not claims.get("sub"):
        raise ValueError("missing identity")
    projects = [g for g in groups if re.fullmatch(r"winlab-projects/[^/]+", g)]
    return {"sub": claims["sub"], "username": username, "admin": admin, "projects": projects}


class Verifier:
    def __init__(self, issuer, audience):
        self.issuer, self.audience = issuer, audience
        self.jwks = jwt.PyJWKClient(issuer + "/protocol/openid-connect/certs", timeout=8, lifespan=300)

    async def verify(self, token):
        key = await asyncio.to_thread(self.jwks.get_signing_key_from_jwt, token)
        claims = jwt.decode(
            token,
            key.key,
            algorithms=["RS256"],
            audience=self.audience,
            issuer=self.issuer,
            leeway=10,
            options={"require": ["exp", "iat", "sub", "azp"]},
        )
        if claims["azp"] != self.audience:
            raise ValueError("wrong authorized party")
        return identity(claims)


class OAuth:
    def __init__(self, store, origin, issuer, client_id, verifier, hosted_redirects=()):
        self.store, self.origin, self.issuer = store, origin, issuer
        self.client_id, self.verifier = client_id, verifier
        self.hosted_redirects = set(hosted_redirects)
        self.resource = origin + "/mcp"
        self.callback = origin + "/oauth/callback"

    def allowed_redirect(self, value):
        try:
            u = urlsplit(value)
            return (
                not u.username
                and not u.password
                and not u.fragment
                and (
                    (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1") and bool(u.port))
                    or value in self.hosted_redirects
                )
            )
        except ValueError:
            return False

    @staticmethod
    def error(code="invalid_request", status=400):
        return JSONResponse({"error": code}, status_code=status, headers={"Cache-Control": "no-store"})

    async def route(self, request):
        path, method = request.url.path, request.method
        self.store.purge_oauth()
        if path.startswith("/.well-known/oauth-protected-resource") and method == "GET":
            return JSONResponse(
                {
                    "resource": self.resource,
                    "authorization_servers": [self.origin],
                    "scopes_supported": ["openid", "profile", "email"],
                    "bearer_methods_supported": ["header"],
                }
            )
        if (
            path in ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"]
            and method == "GET"
        ):
            return JSONResponse(
                {
                    "issuer": self.origin,
                    "authorization_endpoint": self.origin + "/oauth/authorize",
                    "token_endpoint": self.origin + "/oauth/token",
                    "registration_endpoint": self.origin + "/oauth/register",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "code_challenge_methods_supported": ["S256"],
                    "token_endpoint_auth_methods_supported": ["none"],
                    "authorization_response_iss_parameter_supported": True,
                    "scopes_supported": ["openid", "profile", "email"],
                }
            )
        if path == "/oauth/register" and method == "POST":
            if self.store.db.execute("SELECT count(*) FROM oauth WHERE kind='client'").fetchone()[0] >= 10000:
                return self.error("temporarily_unavailable", 503)
            try:
                data = await request.json()
                redirects = data["redirect_uris"]
                if not 1 <= len(redirects) <= 5 or not all(self.allowed_redirect(u) for u in redirects):
                    return self.error("invalid_redirect_uri")
                if data.get("token_endpoint_auth_method", "none") != "none":
                    return self.error("invalid_client_metadata")
                client = {
                    "client_id": "carrel-" + secrets.token_urlsafe(24),
                    "redirect_uris": redirects,
                    "client_name": str(data.get("client_name", "MCP client"))[:100],
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                }
                self.store.oauth_put("client", client["client_id"], client, 86400 * 90)
                return JSONResponse(client, status_code=201, headers={"Cache-Control": "no-store"})
            except (ValueError, KeyError, TypeError):
                return self.error()
        if path == "/oauth/authorize" and method == "GET":
            q = request.query_params
            c = self.store.oauth_get("client", q.get("client_id", ""))
            if not c or q.get("redirect_uri") not in c["redirect_uris"]:
                return self.error("invalid_client")
            if (
                q.get("response_type") != "code"
                or q.get("code_challenge_method") != "S256"
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", q.get("code_challenge", ""))
                or q.get("resource", self.resource) != self.resource
                or len(q.get("state", "")) > 4096
            ):
                return self.error()
            state, cookie = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            txn = {
                "client": c["client_id"],
                "name": c["client_name"],
                "redirect": q["redirect_uri"],
                "state": q.get("state", ""),
                "challenge": q["code_challenge"],
                "cookie": digest(cookie),
            }
            self.store.oauth_put("state", state, txn, 600)
            params = {
                "client_id": self.client_id,
                "redirect_uri": self.callback,
                "response_type": "code",
                "scope": "openid profile email",
                "state": state,
                "code_challenge": txn["challenge"],
                "code_challenge_method": "S256",
            }
            r = RedirectResponse(
                self.issuer + "/protocol/openid-connect/auth?" + urlencode(params), status_code=302
            )
            r.set_cookie(
                "carrel_oauth", cookie, max_age=600, httponly=True, secure=True, samesite="lax", path="/oauth"
            )
            return r
        if path == "/oauth/callback" and method == "GET":
            q = request.query_params
            txn = self.store.oauth_pop("state", q.get("state", ""))
            if (
                not txn
                or not secrets.compare_digest(txn["cookie"], digest(request.cookies.get("carrel_oauth", "")))
                or q.get("iss") != self.issuer
                or not q.get("code")
                or q.get("error")
            ):
                return self.error("access_denied")
            consent = secrets.token_urlsafe(32)
            txn["code"] = q["code"]
            self.store.oauth_put("consent", consent, txn, 300)
            return consent_page(txn["name"], txn["redirect"], consent)
        if path == "/oauth/consent" and method == "POST":
            data = await request.form()
            txn = self.store.oauth_pop("consent", str(data.get("consent", "")))
            if (
                request.headers.get("origin") != self.origin
                or not txn
                or not secrets.compare_digest(txn["cookie"], digest(request.cookies.get("carrel_oauth", "")))
            ):
                return self.error("access_denied")
            out = {"state": txn["state"], "iss": self.origin}
            if data.get("allow") == "yes":
                self.store.oauth_put("code", digest(txn["code"]), txn, 120)
                out["code"] = txn["code"]
            else:
                out["error"] = "access_denied"
            return RedirectResponse(
                txn["redirect"] + ("&" if "?" in txn["redirect"] else "?") + urlencode(out), status_code=302
            )
        if path == "/oauth/token" and method == "POST":
            data = await request.form()
            cid = str(data.get("client_id", ""))
            client = self.store.oauth_get("client", cid)
            if not client or data.get("resource", self.resource) != self.resource:
                return self.error("invalid_client")
            grant = data.get("grant_type")
            body = {"client_id": self.client_id, "grant_type": grant}
            if grant == "authorization_code":
                code = str(data.get("code", ""))
                txn = self.store.oauth_get("code", digest(code))
                verifier = str(data.get("code_verifier", ""))
                if (
                    not txn
                    or txn["client"] != cid
                    or data.get("redirect_uri") != txn["redirect"]
                    or not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier)
                    or not secrets.compare_digest(challenge(verifier), txn["challenge"])
                ):
                    return self.error("invalid_grant")
                self.store.oauth_pop("code", digest(code))
                body.update(code=code, code_verifier=verifier, redirect_uri=self.callback)
            elif grant == "refresh_token":
                refresh = str(data.get("refresh_token", ""))
                txn = self.store.oauth_get("refresh", digest(refresh))
                if not txn or txn["client"] != cid:
                    return self.error("invalid_grant")
                body["refresh_token"] = refresh
            else:
                return self.error("unsupported_grant_type")
            try:
                async with httpx.AsyncClient(timeout=15) as http:
                    r = await http.post(self.issuer + "/protocol/openid-connect/token", data=body)
                if r.status_code != 200:
                    return self.error("invalid_grant")
                tokens = r.json()
                await self.verifier.verify(tokens["access_token"])
                if tokens.get("refresh_token"):
                    self.store.oauth_put(
                        "refresh",
                        digest(tokens["refresh_token"]),
                        {"client": cid},
                        min(tokens.get("refresh_expires_in", 1800), 86400 * 30),
                    )
                if grant == "refresh_token" and body["refresh_token"] != tokens.get("refresh_token"):
                    self.store.oauth_pop("refresh", digest(body["refresh_token"]))
                return JSONResponse(tokens, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
            except (httpx.HTTPError, jwt.PyJWTError, ValueError, KeyError):
                return self.error("access_denied")
        return self.error("invalid_request", 404)

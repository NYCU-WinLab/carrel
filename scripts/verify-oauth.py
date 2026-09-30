#!/usr/bin/env python3
"""Exercise real Keycloak authorization-code + S256 + user consent.

Administrator supplies disposable test accounts in a 0600 JSON file. Tokens are
saved privately for follow-on acceptance tests; no password or token is printed.
"""

import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
import secrets
from urllib.parse import parse_qs, urlsplit

import httpx
from carrel.auth import challenge


class Form(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.action = None
        self.fields = {}
        self.in_form = False
        self.found_form = False
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and not self.found_form:
            self.action = a.get("action")
            self.in_form = True
            self.found_form = True
        if self.in_form and tag == "input" and a.get("name"):
            self.fields[a["name"]] = a.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.in_form = False


def login(user, origin):
    client = httpx.Client(timeout=30, follow_redirects=False)
    r = client.post(
        origin + "/oauth/register",
        json={
            "client_name": "Carrel acceptance test",
            "redirect_uris": ["http://127.0.0.1:49231/callback"],
            "token_endpoint_auth_method": "none",
        },
    )
    r.raise_for_status()
    cid = r.json()["client_id"]
    verifier, state = secrets.token_urlsafe(48), secrets.token_urlsafe(24)
    query = dict(
        client_id=cid,
        redirect_uri="http://127.0.0.1:49231/callback",
        response_type="code",
        code_challenge=challenge(verifier),
        code_challenge_method="S256",
        state=state,
        resource=origin + "/mcp",
        scope="openid profile email",
    )
    r = client.get(origin + "/oauth/authorize", params=query)
    assert r.status_code == 302
    r = client.get(r.headers["location"])
    r.raise_for_status()
    form = Form(r.text)
    assert form.action and "auth.winlab.tw" in form.action, "Keycloak login page not returned"
    form.fields.update(username=user["username"], password=user["password"])
    r = client.post(form.action, data=form.fields)
    assert r.status_code == 302, "Keycloak login failed or required actions remain"
    assert r.headers["location"].startswith(origin + "/oauth/callback")
    r = client.get(r.headers["location"])
    assert r.status_code == 200, "OAuth callback failed"
    consent = Form(r.text)
    assert consent.action == "/oauth/consent"
    r = client.post(
        origin + consent.action, data={**consent.fields, "allow": "yes"}, headers={"Origin": origin}
    )
    assert r.status_code == 302
    result = parse_qs(urlsplit(r.headers["location"]).query)
    assert result["state"] == [state] and result["iss"] == [origin]
    r = client.post(
        origin + "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": cid,
            "redirect_uri": query["redirect_uri"],
            "code": result["code"][0],
            "code_verifier": verifier,
            "resource": origin + "/mcp",
        },
    )
    assert r.status_code == 200, "Token validation or exchange failed: " + r.text[:200]
    tokens = r.json()
    return {"client_id": cid, "username": user["username"], **tokens}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--users", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--origin", default="https://carrel.winlab.tw")
    a = p.parse_args()
    users = json.loads(a.users.read_text())["users"]
    results = []
    for user in users:
        results.append(login(user, a.origin))
        print("OAuth + consent + audience verified:", user["username"], flush=True)
    a.output.write_text(json.dumps(results))
    a.output.chmod(0o600)


if __name__ == "__main__":
    main()

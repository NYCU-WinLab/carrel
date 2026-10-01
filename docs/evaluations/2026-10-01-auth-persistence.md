# Persistent MCP authentication — 0.4.1

Carrel now requests Keycloak offline access so Codex can renew its login after the browser SSO
session ends. Version 0.4.1 is deployed at `https://carrel.winlab.tw/mcp`.

## Cause and change

Previously Carrel requested only `openid profile email`, tying refresh to the ordinary SSO session.
Its local refresh binding also treated Keycloak's `refresh_expires_in=0` as immediately expired,
which would prevent adopting offline tokens. Dynamic registrations expired after a fixed 90 days,
and every upstream token error—including temporary outages—was presented as a permanent auth error.

Discovery and authorization now include `offline_access`. Verified offline grants with a zero refresh
lifetime get an unbounded local binding. Authorized offline client registrations also persist; unused
registrations still expire after 90 days. Online grants retain upstream expiry and renew their
registration on use.
Only refresh-token hashes are stored in Carrel. Binding, code consumption and client renewal are
committed together. Rotated tokens replace the old binding, while an omitted replacement retains it.

Temporary token/JWKS failures return 503 without declaring credentials invalid. Explicit upstream
`invalid_grant` removes the local binding. The advertised `/oauth/revoke` endpoint validates the
client binding, revokes upstream and removes the local binding. PKCE, callback/consent protections,
issuer, audience, authorized party and current membership checks remain enforced.

## Persistence boundary

Access tokens remain five minutes long. Carrel adds no fixed lifetime to an authorized offline
session. Keycloak still controls offline idle limits and revocation; its realm-wide policy was not
changed. The live token has no fixed expiration, but this is not a claim that an indefinitely idle,
revoked or ineligible account can keep access. Membership removal blocks the next renewal; an
already issued access token can remain usable until expiry (with the existing 10-second clock leeway).
Browser SSO logout alone intentionally leaves offline access valid. Users can revoke Carrel from
the WinLab account console. Client logout removes local credentials; remote revocation depends on
client support for the advertised endpoint. Pre-0.4.1 logins need one new authorization.

## Verification

- 133 automated tests pass, including persistent SQLite reopen with advanced local time, client and
  membership boundaries, rotation, omitted scope/replacement, expiry, transient failures and revocation.
  Ruff lint/format, lock consistency, script compilation and whitespace checks pass.
- A disposable member completed real authorization-code/PKCE/consent login. Keycloak returned
  `expires_in=300`, `refresh_expires_in=0` and `offline_access`.
- Real renewal succeeded immediately, after a Carrel restart, after the original access token
  actually expired (the old token was rejected), and after ending the member's SSO sessions.
- A foreign dynamic client could not revoke the token. Removing lab membership blocked renewal.
  Revocation then blocked renewal through both Carrel and Keycloak directly.
- The user's Codex login was renewed. Codex 0.159.3's own app-server MCP discovery loaded Carrel
  0.4.1 and all 40 member tools; a fresh client did so again more than five minutes later.
  No model run or infrastructure mutation was needed for this client test.
- Temporary account, test registrations/bindings and local test credentials were removed. Existing
  resources were untouched. Installed package and service source hashes match the built wheel.

[Sanitized evidence](2026-10-01-auth-persistence.json). Protected rollback archive paths are included;
archive contents remain on the control container. The exact deployed offline idle timeout was not
readable with the existing restricted admin API credential, so no duration is asserted here.

References: [Keycloak offline access](https://www.keycloak.org/docs/latest/server_admin/index.html#_offline-access),
[Codex MCP configuration](https://developers.openai.com/codex/mcp).

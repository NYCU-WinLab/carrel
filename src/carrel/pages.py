"""Self-contained OAuth pages without scripts or third-party assets."""

import base64
import hashlib
import re
from html import escape
from ipaddress import IPv6Address
from urllib.parse import urlsplit

from starlette.responses import HTMLResponse

STYLE = """
:root { color-scheme: light dark; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --bg: #fafaf9; --text: #242422; --muted: #71716b; --line: #deded9; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); }
main { min-height: 100svh; display: grid; place-items: center; padding: 24px; }
section { width: 100%; max-width: 360px; }
h1 { margin: 0; font-size: 24px; font-weight: 600; letter-spacing: -.5px; }
p { margin: 16px 0 28px; color: var(--muted); font-size: 15px; line-height: 1.7; overflow-wrap: anywhere; }
strong { color: var(--text); font-weight: 600; }
.actions { display: flex; justify-content: flex-end; gap: 10px; }
button { min-height: 44px; padding: 10px 24px; border: 1px solid var(--line); border-radius: 8px;
  background: transparent; color: var(--text); font: inherit; font-size: 14px; cursor: pointer; }
button.primary { background: var(--text); border-color: var(--text); color: var(--bg); }
button:hover { opacity: .8; }
button:focus-visible { outline: 2px solid var(--text); outline-offset: 4px; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #191919; --text: #efefeb; --muted: #a4a49d; --line: #42423e; }
}
"""


def callback_origin(redirect_uri):
    """Serialize a registered callback origin without letting URL text alter CSP."""
    destination = urlsplit(redirect_uri)
    host = destination.hostname or ""
    if destination.scheme not in ("http", "https") or destination.username or destination.password:
        raise ValueError("invalid callback origin")
    if ":" in host:
        address = IPv6Address(host)
        if address.scope_id:
            raise ValueError("scoped callback address is not supported")
        host = f"[{address}]"
    elif not re.fullmatch(r"[a-zA-Z0-9.-]+", host):
        raise ValueError("invalid callback hostname")
    port = f":{destination.port}" if destination.port else ""
    return f"{destination.scheme}://{host}{port}"


def consent_page(client_name, redirect_uri, consent):
    name, nonce = (escape(value, quote=True) for value in (client_name, consent))
    return_origin = callback_origin(redirect_uri)
    style_hash = base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
    return HTMLResponse(
        f"""<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>連接 Carrel</title><style>{STYLE}</style></head>
<body><main><section aria-labelledby="title">
<h1 id="title">連接 Carrel</h1>
<p>允許 <strong>{name}</strong> 以你的帳號權限管理 Carrel 資源。</p>
<p>登入會持續保留，關閉瀏覽器後仍可使用。你可以在 WinLab 帳號的應用程式頁面撤銷存取。</p>
<form method="post" action="/oauth/consent">
<input type="hidden" name="consent" value="{nonce}"><div class="actions">
<button name="allow" value="no">取消</button>
<button class="primary" name="allow" value="yes">允許</button>
</div></form></section></main></body></html>""",
        headers={
            "Cache-Control": "no-store",
            # no-referrer makes navigation POSTs carry Origin: null. Keep the
            # origin guard working without disclosing authorization URL queries.
            "Referrer-Policy": "strict-origin",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": (
                f"default-src 'none'; style-src 'sha256-{style_hash}'; "
                # Browsers also check the consent POST's redirect against this
                # policy. Permit only this transaction's registered callback origin.
                f"form-action 'self' {return_origin}; frame-ancestors 'none'; base-uri 'none'"
            ),
        },
    )

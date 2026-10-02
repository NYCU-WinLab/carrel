import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

import jsonschema
import jwt
from mcp.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, TextContent
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import __version__
from .auth import OAuth, Verifier
from .backend import Backend
from .platform import ADMIN_TOOLS, Failure, Platform
from .store import Store
from .tools import BY_NAME, TOOLS


def build(config, backend=None, verifier=None, store=None):
    origin = config["origin"].rstrip("/")
    issuer = config["issuer"].rstrip("/")
    store = store or Store(config["database"])
    verifier = verifier or Verifier(issuer, "carrel-mcp")
    platform = Platform(store, backend or Backend(), {"background_operations": True, **config})
    oauth = OAuth(store, origin, issuer, "carrel-mcp", verifier, config.get("hosted_redirects", []))
    server = Server(
        "carrel",
        version=__version__,
        instructions=(
            "WinLab machines; tools only, no MCP resources. Use whoami when asked about identity or all visible tenants' "
            "used/limit/remaining quotas, service.version and capabilities. These are authoritative; capability questions do not need deployment previews. Use catalog_get for images/sizes, capacity_get "
            "only when asked about shared physical capacity. For a request to create one machine, call machine_create directly with a public key; defaults are Debian 13 VM, 2 vCPU, 2 GiB RAM, 20 GiB disk. No discovery or preview is required. Use deployment_apply to describe "
            "machines, connections (from/to/port), and publications (machine/protocol/port/sub for HTTPS) together. "
            "Use network_access=restricted for destinations that should accept only declared service connections. "
            "The default tenant mode allows all same-tenant traffic; extra networks/NICs are advanced unfiltered L2 experiments. "
            "Creation waits up to 45 seconds for verified readiness and returns a durable operation. Inspect its state/result/error; only use operation_get if still pending. "
            "Queued jobs have not reserved capacity. Use a stable idempotency_key after a lost submission response. "
            "Waiting jobs resume automatically; follow next_action. Completion returns SSH entries and public endpoints. For a local client, merge the returned ssh_config into its SSH configuration when authorized, verify with ssh -G, then present ssh_short. Before setup, use the direct ssh command. The alias needs no DNS change and is scoped by tenant. "
            "Publication verification=routing_configured does not verify an application's external HTTP response. "
            "Follow next_action for failures: operation_retry preserves allocations; revise_request means fix invalid inputs before a new submission. Managed private networks assign IPs automatically. "
            "Machine readiness includes cloud-init completion and requested application checks; SSH alone is insufficient. "
            "Use VMs for Docker, Mininet and databases. memory_mb/swap_mb are MiB; disk_gb is GiB. "
            "Preview when the user asks to plan or compare before creating. Authorized creation can apply directly. Destructive operations still require their confirmation fields. deployment_plan is the complete preview; do not repeat it with deployment_apply(dry_run=true) or manually execute its resources one by one. Previews never reserve or write resources; audit is recorded. "
            "Trust quota_before/delta/quota_after and resource_changes=false; follow-up list/quota/key calls "
            "are unnecessary just to verify a preview. Missing SSH public keys do not block planning; "
            "they are required for actual creation and can be passed inline without saving. "
            "Previews do not test guest boot or commands. Tenant membership is verified on every request; "
            "eligible tenants register automatically after sign-in."
        ),
    )

    @server.list_resources()
    async def list_resources():
        return []

    @server.list_resource_templates()
    async def list_resource_templates():
        return []

    @server.list_tools()
    async def list_tools():
        who = server.request_context.request.scope["carrel.identity"]
        return [t for t in TOOLS if who["admin"] or t.name not in ADMIN_TOOLS]

    @server.call_tool(validate_input=False)
    async def call_tool(name, arguments):
        who = server.request_context.request.scope["carrel.identity"]
        try:
            definition = BY_NAME[name]
            jsonschema.validate(arguments, definition.inputSchema)
            result = await platform.execute(name, arguments, who)
        except jsonschema.ValidationError as error:
            path = ".".join(str(p) for p in error.absolute_path) or "arguments"
            result = {
                "ok": False,
                "error": {
                    "code": "invalid",
                    "message": f"Invalid arguments at {path}: {error.validator}",
                    "argument_path": list(error.absolute_path),
                    "allowed_fields": list(error.schema.get("properties", {})),
                    "required_fields": error.schema.get("required", []),
                },
            }
        except KeyError:
            result = {
                "ok": False,
                "error": {"code": "invalid", "message": "Unknown tool or missing required field"},
            }
        except Exception as e:  # noqa: BLE001 - isolate tool failures and keep reconciliation alive
            print(json.dumps({"event": "tool_failure", "tool": name, "type": type(e).__name__}))
            result = {
                "ok": False,
                "error": {
                    "code": "conflict",
                    "message": "Operation failed; contact an administrator before retrying mutations",
                },
            }
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result))],
            structuredContent=result,
            isError=not result["ok"],
        )

    manager = StreamableHTTPSessionManager(
        server,
        json_response=True,
        stateless=True,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[origin.split("//")[1]],
            allowed_origins=[origin],
        ),
    )

    class McpEndpoint:
        async def __call__(self, scope, receive, send):
            request = Request(scope, receive)
            authorization = request.headers.get("authorization", "")
            try:
                if not authorization.startswith("Bearer "):
                    raise ValueError("missing token")
                scope["carrel.identity"] = await verifier.verify(authorization[7:])
            except jwt.PyJWKClientConnectionError:
                response = JSONResponse({"error": "temporarily_unavailable"}, status_code=503)
                await response(scope, receive, send)
                return
            except (jwt.PyJWTError, ValueError, OSError):
                response = JSONResponse(
                    {"error": "invalid_token"},
                    status_code=401,
                    headers={
                        "WWW-Authenticate": f'Bearer resource_metadata="{origin}/.well-known/oauth-protected-resource/mcp"'
                    },
                )
                await response(scope, receive, send)
                return
            await manager.handle_request(scope, receive, send)

    async def reconcile_loop():
        while True:
            try:
                async with platform.lock:
                    if store.tenants():
                        await platform.expire_grants()
                        await platform.reconcile()
                        await platform.maintain_domains()
                    store.purge_oauth()
            except Exception as e:  # noqa: BLE001 - isolate tool failures and keep reconciliation alive
                print(json.dumps({"event": "reconcile_failed", "type": type(e).__name__}))
            await asyncio.sleep(300)

    @asynccontextmanager
    async def lifespan(app):
        async with manager.run():
            platform.operations.recover()
            task = asyncio.create_task(reconcile_loop())
            yield
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            await platform.operations.close()

    async def health(request):
        return JSONResponse({"status": "ok", "service": "carrel", "version": __version__})

    async def guest_status(request):
        try:
            body = await request.json()
            platform.guest_report(body, request.client.host)
            return JSONResponse({"ok": True})
        except (Failure, ValueError, TypeError, AttributeError):
            return JSONResponse({"ok": False}, status_code=403)

    routes = [
        Route("/healthz", health),
        Route("/mcp", McpEndpoint()),
        Route("/internal/guest-status", guest_status, methods=["POST"]),
    ]
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/oauth/register",
        "/oauth/authorize",
        "/oauth/callback",
        "/oauth/consent",
        "/oauth/token",
        "/oauth/revoke",
    ]:
        routes.append(Route(path, oauth.route, methods=["GET", "POST"]))
    app = Starlette(routes=routes, lifespan=lifespan)

    class Limits:
        def __init__(self, app):
            self.app = app
            self.buckets = {}

        async def __call__(self, scope, receive, send):
            if scope["type"] != "http":
                return await self.app(scope, receive, send)
            req = Request(scope, receive)
            # All public requests arrive through a fixed trusted reverse proxy.
            # Its forwarded identity is not used for authorization.
            internal = scope["path"] == "/internal/guest-status"
            if internal and (not req.client or not req.client.host.startswith("10.200.")):
                return await JSONResponse({"error": "forbidden"}, 403)(scope, receive, send)
            if not internal and req.headers.get("host") != origin.split("//")[1]:
                return await JSONResponse({"error": "invalid_host"}, 400)(scope, receive, send)
            if req.headers.get("origin") and req.headers["origin"] != origin:
                return await JSONResponse({"error": "invalid_origin"}, 403)(scope, receive, send)
            if scope["path"].startswith("/oauth/"):
                now = int(time.time()) // 60
                self.buckets = {k: v for k, v in self.buckets.items() if k >= now}
                self.buckets[now] = self.buckets.get(now, 0) + 1
                if self.buckets[now] > 300:
                    return await JSONResponse({"error": "rate_limited"}, 429)(scope, receive, send)
            count = 0

            async def bounded_receive():
                nonlocal count
                event = await receive()
                count += len(event.get("body", b""))
                if count > 262144:
                    raise ValueError("body too large")
                return event

            try:
                await self.app(scope, bounded_receive, send)
            except ValueError:
                await JSONResponse({"error": "invalid_request"}, 400)(scope, receive, send)

    return Limits(app)


def main():
    import uvicorn

    config = json.loads(Path(os.environ.get("CARREL_CONFIG", "/etc/carrel/config.json")).read_text())
    uvicorn.run(build(config), host="0.0.0.0", port=8080, access_log=False, proxy_headers=False)


if __name__ == "__main__":
    main()

import asyncio
import json


class Backend:
    def __init__(self, ssh_config="/etc/carrel/ssh_config"):
        self.ssh_config = ssh_config

    async def call(self, request, target="carrel-node"):
        proc = await asyncio.create_subprocess_exec(
            "ssh",
            "-F",
            self.ssh_config,
            target,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, _err = await asyncio.wait_for(proc.communicate(json.dumps(request).encode()), 900)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError("node operation timed out; reconcile before retry")
        try:
            result = json.loads(out)
        except ValueError:
            raise RuntimeError("node adapter unavailable") from None
        if proc.returncode or not result.get("ok"):
            # Diagnostics remain in the server journal; no shell/configuration
            # details from the privileged adapter reach a member's MCP response.
            print(json.dumps({"event": "adapter_failure", "op": request["op"], "error": result.get("error")}))
            raise RuntimeError("node operation failed; allocation retained for repair")
        return result["result"]

    async def reconcile(self, state):
        state = {
            **state,
            "machines": [
                {k: v for k, v in m.items() if k not in ("ssh_keys", "runcmd")} for m in state["machines"]
            ],
        }
        node = await self.call(
            {"op": "reconcile", "state": {k: v for k, v in state.items() if k != "certificates"}}
        )
        edge = await self.call(
            {"op": "reconcile", "state": {k: state.get(k, []) for k in ("ports", "domains", "certificates")}},
            "carrel-edge",
        )
        return {"node": node, "edge": edge}

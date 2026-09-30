"""Explicit MCP wire schemas; unknown parameters are rejected before dispatch."""

from mcp.types import Tool

from .platform import MUTATIONS, QUOTA_DIMENSIONS

TEXT = {"type": "string", "minLength": 1, "maxLength": 256}
LABEL = {"type": "string", "pattern": "^[a-z][a-z0-9-]{0,31}$"}
MACHINE = {"type": "string", "minLength": 1, "maxLength": 32}
PORT = {"type": "integer", "minimum": 1, "maximum": 65535}
CPU = {"type": "integer", "minimum": 1, "maximum": 64, "description": "Virtual CPUs (vCPU)."}
MEM = {"type": "integer", "minimum": 512, "maximum": 131072, "description": "RAM in MiB (1024 MiB = 1 GiB)."}
DISK = {"type": "integer", "minimum": 10, "maximum": 1000, "description": "Virtual disk capacity in GiB."}
BOOL = {"type": "boolean"}
KEY = {"type": "string", "minLength": 40, "maxLength": 16000}
DIM = {"type": "string", "enum": list(QUOTA_DIMENSIONS)}
AMOUNT = {"type": "integer", "minimum": 0, "maximum": 1000000}
RESULT = {
    "type": "object",
    "properties": {
        "ok": BOOL,
        "error": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "enum": [
                        "quota_exceeded",
                        "capacity_exhausted",
                        "not_found",
                        "conflict",
                        "forbidden",
                        "invalid",
                        "pending_approval",
                    ],
                },
                "message": TEXT,
            },
            "required": ["code", "message"],
        },
    },
    "required": ["ok"],
    "additionalProperties": True,
}


def tool(name, description, properties=None, required=(), account=False):
    props = dict(properties or {})
    if not account:
        props["tenant"] = LABEL
    mutating = name in MUTATIONS or name in {
        "reconcile_run",
        "quota_set",
        "tenant_suspend",
        "request_approve",
        "request_reject",
    }
    if mutating:
        props["dry_run"] = {
            "type": "boolean",
            "default": False,
            "description": "Preview only: no resource writes or reservations (audit is recorded). Returns quota_before, delta, quota_after, requirements and ready_to_apply. No follow-up list/quota/key checks are needed to prove it made no changes.",
        }
    from mcp.types import ToolAnnotations

    return Tool(
        name=name,
        description=description,
        inputSchema={
            "type": "object",
            "properties": props,
            "required": list(required),
            "additionalProperties": False,
        },
        outputSchema=RESULT,
        annotations=ToolAnnotations(
            readOnlyHint=not mutating and name != "whoami",
            destructiveHint=name in {"machine_delete", "snapshot_rollback", "tenant_suspend"},
            openWorldHint=False,
        ),
    )


TOOLS = [
    tool(
        "whoami",
        "Get identity, default tenant, capabilities and every visible tenant's used/limit/remaining quota in one call. Eligible tenants register automatically. No quota_get needed for this overview.",
        account=True,
    ),
    tool(
        "quota_get",
        "Refresh one tenant's used/limit/remaining quota; whoami already includes all visible tenants.",
    ),
    tool(
        "catalog_get",
        "Get installed images, size presets, MiB/GiB units and supported capabilities together.",
        account=True,
    ),
    tool(
        "capacity_get",
        "Get live aggregate physical CPU/RAM/storage, admission headroom and policy. Shared capacity is separate from tenant quota; no other tenants' guest details. GPU allocation is unsupported, GPU hardware inventory unknown.",
        account=True,
    ),
    tool(
        "images_list",
        "List installed stable images and support dates.",
        {"kind": {"enum": ["vm", "ct"]}},
        account=True,
    ),
    tool("sizes_list", "List machine resource presets.", account=True),
    tool(
        "machine_create",
        "Create one VM/CT; apply returns SSH after probing it. Use VMs for Docker, OVS, Mininet or databases. Dry-run first: checks quota/capacity even without SSH keys, returning requirements instead. Valid public keys are mandatory for apply, can be passed inline and need not be saved. For multiple resources and NICs use deployment_plan.",
        {
            "name": LABEL,
            "kind": {"enum": ["vm", "ct"]},
            "image": {"enum": ["debian-13", "ubuntu-24.04"]},
            "size": {"enum": ["small", "medium", "large"]},
            "cpu": CPU,
            "memory_mb": MEM,
            "disk_gb": DISK,
            "ssh_keys": {"type": "array", "items": KEY, "maxItems": 20},
            "nested_virt": BOOL,
            "swap_mb": {"type": "integer", "minimum": 0, "maximum": 65536, "description": "Swap in MiB."},
            "packages": {
                "type": "array",
                "maxItems": 100,
                "items": {"type": "string", "pattern": "^[a-z0-9][a-z0-9+.-]{0,99}$"},
            },
            "runcmd": {
                "type": "array",
                "maxItems": 100,
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 100,
                    "items": {"type": "string", "maxLength": 4096},
                },
            },
        },
        ["name"],
    ),
    tool("machine_list", "List this tenant's allocated machines."),
    tool(
        "machine_get",
        "Get a machine, hypervisor status and its public SSH entry.",
        {"machine": MACHINE},
        ["machine"],
    ),
    tool(
        "machine_retry",
        "Retry an incomplete allocation after the infrastructure fault is repaired; keeps the same VMID, address and quota reservation.",
        {"machine": MACHINE},
        ["machine"],
    ),
    tool(
        "machine_delete",
        "Delete a machine and its grants permanently; confirm must match its name.",
        {"machine": MACHINE, "confirm": LABEL},
        ["machine", "confirm"],
    ),
    tool(
        "machine_power",
        "Start, stop, gracefully shut down, or reboot; persist the owner's intended onboot state.",
        {"machine": MACHINE, "action": {"enum": ["start", "stop", "shutdown", "reboot"]}},
        ["machine", "action"],
    ),
    tool(
        "machine_resize",
        "Grow CPU, RAM or disk after quota and physical admission checks. Disk cannot shrink.",
        {"machine": MACHINE, "cpu": CPU, "memory_mb": MEM, "disk_gb": DISK},
        ["machine"],
    ),
    tool(
        "machine_metrics", "Read hypervisor RRD metrics for the last hour.", {"machine": MACHINE}, ["machine"]
    ),
    tool(
        "network_create",
        "Create an isolated private L2 network. No gateway, DHCP or assigned IPs; MTU 1450.",
        {"name": LABEL, "cidr": TEXT},
        ["name"],
    ),
    tool("network_list", "List private networks owned by this tenant."),
    tool(
        "network_delete",
        "Delete an empty private network; confirm its name.",
        {"network": TEXT, "confirm": LABEL},
        ["network", "confirm"],
    ),
    tool(
        "machine_nic_attach",
        "Attach a raw private L2 NIC from this tenant; configure addresses inside the guest.",
        {"machine": MACHINE, "network": TEXT},
        ["machine", "network"],
    ),
    tool(
        "machine_nic_detach",
        "Detach a private NIC; primary net0 cannot be detached.",
        {"machine": MACHINE, "nic": {"type": "integer", "minimum": 1, "maximum": 7}},
        ["machine", "nic"],
    ),
    tool("ssh_key_add", "Save a public SSH key for future machines in this tenant.", {"key": KEY}, ["key"]),
    tool("ssh_key_list", "List saved public SSH keys."),
    tool("ssh_key_remove", "Remove a saved key; existing machines are unchanged.", {"id": TEXT}, ["id"]),
    tool(
        "port_open",
        "Publish a TCP/UDP guest port through the external PVE edge, using the tenant's permanent port block.",
        {"machine": MACHINE, "port": PORT, "proto": {"enum": ["tcp", "udp"]}},
        ["machine", "port", "proto"],
    ),
    tool("port_list", "List public port grants."),
    tool("port_close", "Remove a public port grant.", {"id": TEXT}, ["id"]),
    tool(
        "domain_add",
        "Publish HTTPS at <sub>.<tenant>.winlab.tw using a tenant wildcard certificate issued by the control plane.",
        {"machine": MACHINE, "sub": LABEL, "target_port": PORT},
        ["machine", "sub", "target_port"],
    ),
    tool("domain_list", "List your HTTPS routes and certificate queue state."),
    tool(
        "domain_remove",
        "Remove an HTTPS route; delete the owned wildcard DNS record when the final route is removed.",
        {"name": TEXT},
        ["name"],
    ),
    tool(
        "peer_allow",
        "Allow one port on your machine from another tenant or one of its machines. Default cross-tenant traffic is denied.",
        {"machine": MACHINE, "port": PORT, "from_tenant": LABEL, "from_machine": MACHINE},
        ["machine", "port", "from_tenant"],
    ),
    tool("peer_list", "List inbound cross-tenant permissions owned by this tenant."),
    tool("peer_revoke", "Revoke an inbound cross-tenant permission.", {"id": TEXT}, ["id"]),
    tool(
        "snapshot_create",
        "Create a disk snapshot. Reserves a full disk's size against quota.",
        {"machine": MACHINE, "name": LABEL},
        ["machine", "name"],
    ),
    tool("snapshot_list", "List managed snapshots.", {"machine": MACHINE}, ["machine"]),
    tool(
        "snapshot_delete",
        "Delete a managed snapshot.",
        {"machine": MACHINE, "name": LABEL},
        ["machine", "name"],
    ),
    tool(
        "snapshot_rollback",
        "Roll back a snapshot; changes since it was created are lost. Confirm snapshot name.",
        {"machine": MACHINE, "name": LABEL, "confirm": LABEL},
        ["machine", "name", "confirm"],
    ),
    tool(
        "quota_request",
        "Request a new total quota limit, with a reason and optional expiry date.",
        {
            "dimension": DIM,
            "amount": AMOUNT,
            "reason": {"type": "string", "minLength": 5, "maxLength": 2000},
            "until": TEXT,
        },
        ["dimension", "amount", "reason"],
    ),
    tool("request_list", "List your quota requests and decisions."),
    tool(
        "audit_log", "Read your tenant's latest 100 audit entries; secrets and guest commands are redacted."
    ),
    tool("tenant_list", "Admin: list tenant registrations.", account=True),
    tool("node_list", "Admin: inspect site inventory and capacity.", account=True),
    tool("usage_report", "Admin: allocations and quotas for all tenants.", account=True),
    tool(
        "reconcile_run",
        "Admin: regenerate managed network, firewall, DHCP and edge configuration from the database.",
        account=True,
    ),
    tool(
        "quota_set",
        "Admin: set a tenant's total quota limit.",
        {"dimension": DIM, "amount": AMOUNT},
        ["tenant", "dimension", "amount"],
    ),
    tool("tenant_suspend", "Admin: stop tenant machines and prevent mutations.", {}, ["tenant"]),
    tool("request_list_all", "Admin: list all pending and completed requests.", account=True),
    tool("request_approve", "Admin: approve a pending quota request.", {"id": TEXT}, ["id"], account=True),
    tool("request_reject", "Admin: reject a pending quota request.", {"id": TEXT}, ["id"], account=True),
]
BY_NAME = {t.name: t for t in TOOLS}

# Keep callable aliases for existing clients, but do not advertise redundant tools.
TOOLS = [t for t in TOOLS if t.name not in {"images_list", "sizes_list"}]
_machine = {
    k: v
    for k, v in BY_NAME["machine_create"].inputSchema["properties"].items()
    if k not in ("tenant", "dry_run")
}
_network = {"name": LABEL, "cidr": TEXT}


def objects(properties, required, maximum):
    return {
        "type": "array",
        "maxItems": maximum,
        "items": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
    }


plan = tool(
    "deployment_plan",
    "Read-only preview of multiple new machines, private networks and NIC attachments together. Use names as symbolic references to new resources or this tenant's existing names/IDs. Checks aggregate quota, host admission and NIC slots; no reservations or resource writes. Missing public keys become requirements. Apply later with network_create, machine_create, machine_nic_attach; guest configuration is not executed in planning.",
    {
        "machines": objects(_machine, ["name"], 100),
        "networks": objects(_network, ["name"], 99),
        "attachments": objects({"machine": MACHINE, "network": TEXT}, ["machine", "network"], 700),
    },
)
TOOLS.append(plan)
BY_NAME[plan.name] = plan

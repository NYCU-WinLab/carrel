"""Export the legacy Python contract for comparison, never overwrite the live Go contract."""

import ast
import json
from pathlib import Path

from carrel.operations import ASYNC_TOOLS
from carrel.platform import ADMIN_MUTATIONS, ADMIN_TOOLS, CAPABILITIES, IMAGES, MUTATIONS, SIZES
from carrel.tools import BY_NAME, TOOLS

root = Path(__file__).resolve().parents[1]
tree = ast.parse((root / "src/carrel/server.py").read_text())
instructions = next(
    ast.literal_eval(k.value)
    for node in ast.walk(tree)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Server"
    for k in node.keywords
    if k.arg == "instructions"
)
data = {
    "tools": [t.model_dump(by_alias=True, exclude_none=True) for t in BY_NAME.values()],
    "visible": [t.name for t in TOOLS],
    "admin_tools": sorted(ADMIN_TOOLS),
    "mutations": sorted(MUTATIONS | ADMIN_MUTATIONS),
    "async_tools": sorted(ASYNC_TOOLS),
    "images": IMAGES,
    "sizes": SIZES,
    "capabilities": CAPABILITIES,
    "instructions": instructions,
}
dest = root / "internal/carrel/testdata/python-contract.json"
dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_text(json.dumps(data, indent=2) + "\n")

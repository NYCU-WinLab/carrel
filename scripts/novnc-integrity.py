#!/usr/bin/env python3
"""Print the sha384 of every module that noVNC's core/rfb.js imports.

Run it after moving the pinned noVNC commit in internal/carrel/console.go and
paste the output into internal/carrel/console_novnc.go (issue #130).
"""
import base64
import hashlib
import posixpath
import re
import sys
import urllib.request

IMPORT = re.compile(r"""(?:import|export)\s[^'";]*?from\s*['"]([^'"]+)['"]|import\s*['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]""")


def main(base: str) -> None:
    seen: dict[str, str] = {}
    todo = ["/core/rfb.js"]
    while todo:
        path = todo.pop()
        if path in seen:
            continue
        body = urllib.request.urlopen(urllib.request.Request(base + path, headers={"User-Agent": "curl/8"})).read()
        seen[path] = "sha384-" + base64.b64encode(hashlib.sha384(body).digest()).decode()
        for match in IMPORT.finditer(body.decode()):
            spec = next(g for g in match.groups() if g)
            if not spec.startswith("."):
                sys.exit(f"{path}: bare import {spec}")
            todo.append(posixpath.normpath(posixpath.join(posixpath.dirname(path), spec)))
    for path, digest in sorted(seen.items()):
        print(f'\t"{path}": "{digest}",')


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "https://cdn.jsdelivr.net/gh/novnc/noVNC@a8dfd6a3ea3c74244f5ebdaa5a7f1023007a7820")

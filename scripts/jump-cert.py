#!/usr/bin/env python3
"""The SSH jump host's AuthorizedKeysCommand for lab certificates.

sshd runs it as `jump-cert.py %u %t %k` (user, key type, base64 key) for
every key a client offers. For a user certificate offered to the jump user it
prints one authorized_keys line: the lab CA, the certificate's principals
that open a machine, and permitopen for port 22 of every machine that one of
them opens, from the map jump-sync.py keeps (Carrel sends it). One line for
all of them, because sshd uses only the first line that matches. sshd itself
still checks the signature, the validity period and that a principal matches;
this only reads the principals to choose the targets. Anything else prints
nothing, and sshd goes on to the keys file.
"""

import json
import re
import subprocess
import sys

CERTS = "/etc/carrel-jump/certs.json"
TYPE = re.compile(r"(?:ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa)-cert-v01@openssh\.com", re.ASCII)
BLOB = re.compile(r"[A-Za-z0-9+/]{1,16384}={0,2}", re.ASCII)
CA = re.compile(r"(?:ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa) [A-Za-z0-9+/]+={0,2}", re.ASCII)
PRINCIPAL = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}|project:[a-z0-9][a-z0-9-]{0,62}", re.ASCII)
SSH_TARGET = re.compile(r"10\.200\.(?:[1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])\.(?:[1-9]\d|10\d):22", re.ASCII)


def principals(key_type, blob):
    """The principals of a user certificate, as ssh-keygen reads them."""
    p = subprocess.run(["ssh-keygen", "-L", "-f", "-"], input=f"{key_type} {blob}\n",
                       capture_output=True, text=True, timeout=5, check=False)
    if p.returncode or not re.search(r"^\s+Type: \S+ user certificate$", p.stdout, re.M):
        return []
    out, inside = [], False
    for line in p.stdout.splitlines():
        if line.strip() == "Principals:":
            inside = True
        elif inside and line.startswith(" " * 16):
            out.append(line.strip())
        elif inside:
            break
    return out


def line(user, key_type, blob):
    if user != "jump" or not TYPE.fullmatch(key_type) or not BLOB.fullmatch(blob):
        return None
    try:
        with open(CERTS) as f:
            certs = json.load(f)
    except (OSError, ValueError):
        return None
    ca, reach = certs.get("ca"), certs.get("principals")
    if not isinstance(ca, str) or not CA.fullmatch(ca) or not isinstance(reach, dict):
        return None
    names, targets = [], set()
    for name in principals(key_type, blob):
        if PRINCIPAL.fullmatch(name) and isinstance(reach.get(name), list) and name not in names:
            names.append(name)
            targets.update(t for t in reach[name] if isinstance(t, str) and SSH_TARGET.fullmatch(t))
    if not targets:
        return None
    opens = ",".join(f'permitopen="{t}"' for t in sorted(targets))
    return f'cert-authority,principals="{",".join(names)}",restrict,port-forwarding,command="/usr/sbin/nologin",{opens} {ca}'


if __name__ == "__main__":
    try:
        found = line(*sys.argv[1:4]) if len(sys.argv) == 4 else None
    except Exception:  # noqa: BLE001 (a failure admits nothing; sshd reads the keys file)
        found = None
    if found:
        print(found)

#!/bin/sh
# Installs carrel-keys (issue #209). Run by the machine owner over SSH:
#   f=$(mktemp) && curl -fsSL @ORIGIN@/apps/v1/keys/install.sh -o "$f" && sudo sh "$f"; rm -f "$f"
# Every minute the machine pulls the keys saved in its tenant (ssh_key_add)
# and sshd accepts them for the login user, after the key files it reads today.
# Remove with: sudo sh "$f" --remove
set -eu

user=user remove=""
while [ $# -gt 0 ]; do
	case "$1" in
	--user) user="$2"; shift 2 ;;
	--remove) remove=1; shift ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
case "$user" in
root) echo "carrel-keys does not serve root: tenant keys would log in as root" >&2; exit 2 ;;
[a-z_]*) ;;
*) echo "invalid user: $user" >&2; exit 2 ;;
esac
id "$user" >/dev/null 2>&1 || { echo "no such user: $user" >&2; exit 2; }
[ -r /etc/carrel/guest.json ] || { echo "/etc/carrel/guest.json is missing: only Carrel machines can pull keys" >&2; exit 1; }

conf=/etc/ssh/sshd_config.d/40-carrel-keys.conf
dir=/etc/ssh/carrel_authorized_keys

if [ -n "$remove" ]; then
	systemctl disable --now carrel-keys.timer 2>/dev/null || true
	rm -f /etc/systemd/system/carrel-keys.service /etc/systemd/system/carrel-keys.timer /usr/local/sbin/carrel-keys "$conf"
	rm -rf "$dir"
	systemctl daemon-reload
	sshd -t && systemctl reload ssh
	echo "carrel-keys removed"
	exit 0
fi

install -d -m 755 "$dir"
cat > /usr/local/sbin/carrel-keys <<EOF
#!/usr/bin/python3
"""Pull this tenant's saved SSH keys from Carrel (issue #209)."""
import json, os, re, sys, tempfile, urllib.error, urllib.request

USER = "$user"
TARGET = "$dir/" + USER
LINE = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+={0,3} carrel:[A-Za-z0-9._-]{1,64}\$")

config = json.load(open("/etc/carrel/guest.json"))
request = urllib.request.Request("http://10.200.0.3:8080/internal/guest-keys",
                                 data=json.dumps({"vmid": config["vmid"], "token": config["token"]}).encode(),
                                 headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read(1 << 20).decode()
except urllib.error.HTTPError as error:
    if error.code != 403:
        sys.exit("carrel-keys: HTTP %d, keeping the last keys" % error.code)
    body = ""  # The machine or its tenant is gone: no saved key applies.
except OSError as error:
    sys.exit("carrel-keys: %s, keeping the last keys" % error)
lines = [l for l in body.splitlines() if l]
if not all(LINE.match(l) for l in lines):
    sys.exit("carrel-keys: unexpected response, keeping the last keys")
fd, path = tempfile.mkstemp(dir="$dir")
with os.fdopen(fd, "w") as f:
    f.write("".join(l + "\n" for l in lines))
os.chmod(path, 0o644)
os.replace(path, TARGET)
# Only the current user's file stays: a file left by an earlier --user, or
# by a crashed run, would never be updated or revoked again.
for name in os.listdir("$dir"):
    if name != USER:
        os.remove(os.path.join("$dir", name))
EOF
chmod 755 /usr/local/sbin/carrel-keys

cat > /etc/systemd/system/carrel-keys.service <<'EOF'
[Unit]
Description=Pull the tenant's saved SSH keys from Carrel
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/carrel-keys
EOF
cat > /etc/systemd/system/carrel-keys.timer <<'EOF'
[Unit]
Description=Pull the tenant's saved SSH keys every minute
[Timer]
OnBootSec=30s
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
EOF

# Keep every key file sshd reads today and add ours after them. The first
# AuthorizedKeysFile wins, so this file sorts before cloud-init's.
rm -f "$conf"
current=$(sshd -T | awk '$1 == "authorizedkeysfile" { $1 = ""; print substr($0, 2) }')
case "$current" in
"") want=".ssh/authorized_keys .ssh/authorized_keys2 $dir/%u" ;; # sshd defaults
none) want="$dir/%u" ;; # The owner turned key files off: only ours is read.
*) want="$current $dir/%u" ;;
esac
/usr/local/sbin/carrel-keys || echo "warning: the first pull failed; the timer retries every minute" >&2
{ printf 'AuthorizedKeysFile '; printf '%s\n' "$want"; } > "$conf"
if ! sshd -t || [ "$(sshd -T | awk '$1 == "authorizedkeysfile" { $1 = ""; print substr($0, 2) }')" != "$want" ]; then
	rm -f "$conf"
	echo "sshd did not take the key file setting; nothing changed" >&2
	exit 1
fi
systemctl daemon-reload
systemctl enable --now carrel-keys.timer >/dev/null
systemctl reload ssh
echo "carrel-keys installed: $(grep -c . "$dir/$user" 2>/dev/null || true) saved key(s) for $user"

#!/bin/bash
# Build a realistic guest: Python runtime, heavy imports, 50 MB of loaded state, HTTP on port 80.
set -euo pipefail
W=/opt/fnlab; cd $W
PY=$(readlink -f /usr/bin/python3); PYV=$(basename "$PY")

rm -rf pyroot pyrootfs.ext4; mkdir -p pyroot/{bin,proc,sys,dev,tmp,app,usr/bin,usr/lib}
cp /bin/busybox pyroot/bin/busybox
cp "$PY" pyroot/usr/bin/
cp -a "/usr/lib/$PYV" pyroot/usr/lib/
rm -rf "pyroot/usr/lib/$PYV/test" "pyroot/usr/lib/$PYV/idlelib" "pyroot/usr/lib/$PYV/tkinter"
# shared libraries the interpreter and its extension modules need
{ ldd "$PY"; find "/usr/lib/$PYV/lib-dynload" -name '*.so' -exec ldd {} \; ; } 2>/dev/null \
  | grep -oE '/[^ ]+\.so[^ ]*' | sort -u | while read -r lib; do cp -L --parents "$lib" pyroot/; done

cat > pyroot/app/server.py <<'EOF'
import asyncio, decimal, email, hashlib, json, sqlite3, ssl, urllib.request, xml.etree.ElementTree
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(400_000)]  # about 50 MB of loaded data


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"ok": True, "items": len(STATE), "sample": STATE[len(STATE) // 2]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


HTTPServer(("0.0.0.0", 80), H).serve_forever()
EOF
cp pyroot/app/server.py $W/server.py

cat > pyroot/init <<EOF
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sys /sys
/bin/busybox ip addr add 172.16.0.2/30 dev eth0
/bin/busybox ip link set eth0 up
exec /usr/bin/$PYV /app/server.py
EOF
chmod +x pyroot/init
SIZE=$(( $(du -sm pyroot | cut -f1) + 40 ))
truncate -s ${SIZE}M pyrootfs.ext4
/usr/sbin/mkfs.ext4 -q -d pyroot pyrootfs.ext4
echo "$PYV rootfs ${SIZE} MiB"

# Container baseline: same app in Docker
if ! command -v docker >/dev/null; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io >/dev/null
fi
mkdir -p dk && cp server.py dk/ && printf 'FROM python:3.13-slim\nCOPY server.py /app/server.py\nCMD ["python","/app/server.py"]\n' > dk/Dockerfile
sudo docker build -q -t fnlab-py dk

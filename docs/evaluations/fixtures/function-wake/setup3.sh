#!/bin/bash
# Two container images: a Python function with test endpoints, and a headless browser function.
set -euo pipefail
W=/opt/fnlab; cd $W
systemctl start docker

mkdir -p dk2 && cat > dk2/server.py <<'EOF'
import asyncio, decimal, email, hashlib, json, os, random, sqlite3, ssl, time, urllib.request, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(400_000)]  # about 50 MB of loaded data


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/rand":      # what differs between two copies of one snapshot?
            out = {"urandom": os.urandom(8).hex(), "random": random.random(),
                   "uuid4": str(uuid.uuid4()), "time": time.time()}
        elif self.path == "/work":    # a request that touches fresh memory
            tmp = [hashlib.md5(str(i).encode()).hexdigest() for i in range(50_000)]
            out = {"ok": True, "n": len(tmp)}
        else:
            out = {"ok": True, "items": len(STATE)}
        body = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


HTTPServer(("0.0.0.0", 80), H).serve_forever()
EOF
printf 'FROM python:3.13-slim\nCOPY server.py /app/server.py\nCMD ["python","/app/server.py"]\n' > dk2/Dockerfile
docker build -q -t fnlab-py2 dk2

mkdir -p dkb && cat > dkb/server.py <<'EOF'
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from playwright.sync_api import sync_playwright

pw = sync_playwright().start()
browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
page = browser.new_page(viewport={"width": 1280, "height": 720})
page.set_content("<h1>warm</h1>")
N = 0


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        global N
        N += 1
        page.set_content(f"<h1>render {N}</h1>" + "".join(f"<p>row {i}</p>" for i in range(200)))
        png = page.screenshot()
        body = json.dumps({"ok": True, "n": N, "png_bytes": len(png), "title": page.inner_text("h1")}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


HTTPServer(("0.0.0.0", 80), H).serve_forever()
EOF
cat > dkb/Dockerfile <<'EOF'
FROM python:3.13-slim
RUN pip install --no-cache-dir -q playwright \
 && (playwright install --with-deps --only-shell chromium || playwright install --with-deps chromium) \
 && rm -rf /var/lib/apt/lists/*
COPY server.py /app/server.py
CMD ["python","/app/server.py"]
EOF
docker build -q -t fnlab-browser dkb
docker images --format '{{.Repository}} {{.Size}}' | grep fnlab; df -h / | tail -1

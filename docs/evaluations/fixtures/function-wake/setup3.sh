#!/bin/bash
# Two container images: a Python function with test endpoints, and a headless browser function.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=/opt/fnlab; cd $W
systemctl start docker

mkdir -p dk2 && cp "$HERE/server.py" dk2/server.py   # the test function, next to this script
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

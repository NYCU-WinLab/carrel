"""Test function: a Python server with about 50 MB of loaded data and endpoints the checks use."""
import asyncio, decimal, email, hashlib, json, os, random, socket, sqlite3, ssl, time, urllib.parse, urllib.request, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(400_000)]  # about 50 MB of loaded data
PORT = int(os.environ.get("PORT", "80"))


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        query = dict(urllib.parse.parse_qsl(url.query))
        if url.path == "/rand":      # what differs between two copies of one snapshot?
            out = {"urandom": os.urandom(8).hex(), "random": random.random(),
                   "uuid4": str(uuid.uuid4()), "time": time.time()}
        elif url.path == "/write":   # is the root writable, and was it written before?
            seen = os.path.exists("/app/marker")
            open("/app/marker", "w").write("x")
            out = {"wrote": os.path.exists("/app/marker"), "seen_before": seen}
        elif url.path == "/work":    # a request that touches fresh memory
            tmp = [hashlib.md5(str(i).encode()).hexdigest() for i in range(50_000)]
            out = {"ok": True, "n": len(tmp)}
        elif url.path == "/connect":  # can the function open a TCP connection to this address?
            try:
                socket.create_connection((query["host"], int(query["port"])), timeout=2).close()
                out = {"ok": True}
            except OSError as e:
                out = {"ok": False, "error": str(e)}
        elif url.path == "/spoof":    # send one raw TCP packet with a chosen source and flags
            try:
                import struct
                src, dst = socket.inet_aton(query["src"]), socket.inet_aton(query["dst"])
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, socket.IPPROTO_TCP, 0, src, dst)
                tcp = struct.pack("!HHLLBBHHH", 40000, int(query["port"]), 1, 0, 5 << 4, int(query["flags"]), 1024, 0, 0)
                raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                raw.sendto(ip + tcp, (query["dst"], 0))
                raw.close()
                out = {"ok": True}
            except (OSError, KeyError) as e:
                out = {"ok": False, "error": str(e)}
        elif url.path == "/resolve":  # does the function's resolver work?
            try:
                out = {"ok": True, "addr": socket.getaddrinfo(query["name"], 443, socket.AF_INET)[0][4][0]}
            except OSError as e:
                out = {"ok": False, "error": str(e)}
        else:
            out = {"ok": True, "items": len(STATE)}
        body = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


HTTPServer(("0.0.0.0", PORT), H).serve_forever()

"""Test function: a Python server with about 50 MB of loaded data and endpoints the checks use."""
import asyncio, decimal, email, hashlib, json, os, random, socket, sqlite3, ssl, time, urllib.parse, urllib.request, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(400_000)]  # about 50 MB of loaded data
PORT = int(os.environ.get("PORT", "80"))


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/big?"):  # a large answer: is the way back to the router limited too?
            size = int(dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))["mib"]) << 20
            self.send_response(200)
            self.send_header("Content-Length", str(size))
            self.end_headers()
            chunk = b"b" * (1 << 20)
            for _ in range(size >> 20):
                self.wfile.write(chunk)
            return
        try:
            out = self.answer()
        except Exception as e:  # the checks read the reason, not a closed connection
            out = {"error": repr(e)}
        body = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def answer(self):
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
        elif url.path == "/print":    # write MiB to stdout: does the function's log stay small?
            import sys
            for _ in range(int(query.get("mib", "1"))):
                sys.stdout.write(("p" * 1023 + "\n") * 1024)
            sys.stdout.flush()
            out = {"ok": True}
        elif url.path == "/download":  # how fast does the function receive from the internet?
            start, size = time.time(), 0
            req = urllib.request.Request(query["url"], headers={"User-Agent": "carrel-fn-check"})
            with urllib.request.urlopen(req, timeout=60) as r:
                while chunk := r.read(1 << 16):
                    size += len(chunk)
            out = {"bytes": size, "seconds": time.time() - start}
        elif url.path == "/upload":    # how fast does the function send to the internet?
            body = b"u" * int(query["bytes"])
            start = time.time()
            req = urllib.request.Request(query["url"], data=body, method="POST", headers={"User-Agent": "carrel-fn-check"})
            with urllib.request.urlopen(req, timeout=60) as r:
                r.read()
            out = {"bytes": len(body), "seconds": time.time() - start}
        elif url.path == "/conns":     # how many TCP connections can the function hold at once?
            import concurrent.futures
            def one(_):
                try:
                    return socket.create_connection((query["host"], int(query["port"])), timeout=5)
                except OSError:
                    return None
            with concurrent.futures.ThreadPoolExecutor(64) as pool:
                held = [s for s in pool.map(one, range(int(query["n"]))) if s]
            out = {"held": len(held)}
            for s in held:
                s.close()
        elif url.path == "/churn":     # open and close n connections one after another
            start, made = time.time(), 0
            for _ in range(int(query["n"])):
                try:
                    socket.create_connection((query["host"], int(query["port"])), timeout=2).close()
                    made += 1
                except OSError:
                    pass
            out = {"made": made, "seconds": time.time() - start}
        elif url.path == "/udp":       # send n datagrams on one socket as fast as it can
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            start = time.time()
            for _ in range(int(query["n"])):
                sock.sendto(b"x" * 64, (query["host"], int(query["port"])))
            sock.close()
            out = {"sent": int(query["n"]), "seconds": time.time() - start}
        elif url.path == "/resolve":  # does the function's resolver work?
            try:
                out = {"ok": True, "addr": socket.getaddrinfo(query["name"], 443, socket.AF_INET)[0][4][0]}
            except OSError as e:
                out = {"ok": False, "error": str(e)}
        else:
            out = {"ok": True, "items": len(STATE)}
        return out

    def log_message(self, *a):
        pass


HTTPServer(("0.0.0.0", PORT), H).serve_forever()

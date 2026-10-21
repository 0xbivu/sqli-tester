# Deliberately vulnerable test server for sqli.py self-check (localhost only).
import http.server, urllib.parse as up, time, re
ROWS = {"1": "Alice", "2": "Bob"}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = up.urlsplit(self.path); q = dict(up.parse_qsl(u.query))
        raw = q.get("id", "")
        # simulate: SELECT name FROM users WHERE id='<raw>'
        if "SLEEP" in raw.upper():
            m = re.search(r"SLEEP\((\d+)\)", raw.upper()); time.sleep(int(m.group(1)))
        body = ""
        if "'" in raw and "AND '1'='1" not in raw and "AND '1'='2" not in raw and "SLEEP" not in raw.upper():
            body = "check the manual that corresponds to your MySQL server version"  # error-based
        elif "AND '1'='1" in raw:
            body = "User: " + ROWS.get(raw.split("'")[0], "unknown")  # true: full
        elif "AND '1'='2" in raw:
            body = "User: unknown-no-such-row"  # false: different row
        else:
            body = "User: " + ROWS.get(raw, "unknown")
        self.send_response(200); self.end_headers(); self.wfile.write(body.encode())
http.server.HTTPServer(("127.0.0.1", 8766), H).serve_forever()

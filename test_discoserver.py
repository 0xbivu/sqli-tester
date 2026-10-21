# Vulnerable test server for sqli.py discovery self-check (localhost only).
# - baseline is stable
# - hidden param "debug": value is REFLECTED into the page
# - hidden param "secret_id": presence changes the page (BEHAVIORAL), and it's SQLi-vulnerable (error+time)
# - every other param is ignored
import http.server, urllib.parse as up, time, re
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        q = dict(up.parse_qsl(up.urlsplit(self.path).query))
        body = "<html>Welcome to the shop. Browse our items.</html>"
        if "debug" in q:
            body += "\n<!-- debug=" + q["debug"] + " -->"          # reflection
        if "secret_id" in q:
            raw = q["secret_id"]
            if "SLEEP" in raw.upper():
                m = re.search(r"SLEEP\((\d+)\)", raw.upper()); time.sleep(int(m.group(1)))
            elif "'" in raw and "AND" not in raw.upper():
                body += "\ncheck the manual that corresponds to your MySQL server version"  # error
            else:
                body += "\n<div>record " + raw + " loaded with extra detail block here</div>"  # behavioral change
        self.send_response(200); self.end_headers(); self.wfile.write(body.encode())
http.server.HTTPServer(("127.0.0.1", 8767), H).serve_forever()

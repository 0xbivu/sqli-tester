# sqli-tester

SQL injection parameter tester — error-based, boolean-blind, time-blind.

**Authorized testing only.** Your own apps, in-scope bug-bounty targets, or engagements with written permission.

```
./sqli.py "https://site/item?id=1&cat=books"
./sqli.py "https://site/login" -d "user=admin&pass=x"
```

Self-check: run `python3 test_vulnserver.py &` then `./sqli.py "http://127.0.0.1:8766/?id=1"` — expect all three classes.

Fuzz common param names when a URL has none of its own:
```
./sqli.py "https://site/page" -f              # names from params.txt
./sqli.py "https://site/page" -f mywords.txt   # your own list
```

## Param discovery (`--discover`)

Mines hidden params the industrial way — reflection + stable-factor behavioral diffing, sent in buckets and bisected to isolate each reacting name, then each hit is re-tested alone to drop false positives.

```
./sqli.py "https://site/item" --discover            # GET
./sqli.py "https://api/v1/user" -m json --discover   # JSON body
./sqli.py "https://site/x" --discover --delay 0.3    # rate-limit friendly
```

On fully dynamic pages (no stable length/word/line/status) it falls back to reflection-only and says so under `-v`. Headers/cookies/path segments are not mined.

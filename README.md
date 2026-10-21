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

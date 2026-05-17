# Regular Expression Denial of Service (ReDoS)

> Some regex engines (NFA-based: Python, JS, .NET, Java pre-21, PCRE) can take exponential time on crafted inputs against vulnerable patterns. A single request can pin a CPU for minutes.

## Summary

- [Vulnerable Patterns](#vulnerable-patterns)
- [Classic Payloads](#classic-payloads)
- [Discovery](#discovery)
- [Real-World CVE Patterns](#real-world-cve-patterns)
- [Mitigation](#mitigation)
- [References](#references)

## Vulnerable Patterns

Look for **nested quantifiers** with overlapping alternatives:

```
(a+)+
(a|a)+
(a|aa)+
(a*)*
([a-zA-Z]+)*
(\w+)*$
(\d+\.)+\d+
^(([a-z])+.)+[A-Z]([a-z])+$       <- Java ReDoS CVE-2017-7657
^(a+)+$
^([a-z0-9]+)*$
```

## Classic Payloads

For pattern `(a+)+$`:

```
aaaaaaaaaaaaaaaaaaaaaaaaaaX
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX
```

Each extra `a` roughly doubles processing time. 30-40 a's is usually fatal.

For pattern `(.*a){25}`:

```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

For email validation `^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@)`:

```
aaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

## Discovery

### Static analysis

- [regexploit](https://github.com/doyensec/regexploit) — finds ReDoS-prone regex patterns:

```bash
regexploit < patterns.txt
regexploit-py file.py
regexploit-js bundle.js
```

- [safe-regex](https://github.com/davisjam/safe-regex) — Node.js linter.

### Dynamic

Submit progressively longer inputs to fields with regex validation; time each request. Linear → safe. Exponential → ReDoS.

Fields to probe:

- Email
- URL
- Phone number
- Username
- Date
- File path

### Catastrophic backtracking signature

```
n=10  → 1 ms
n=20  → 100 ms
n=25  → 3 s
n=30  → 90 s
```

That's a 2× per character — classic catastrophic backtracking.

## Real-World CVE Patterns

| Library | Pattern (simplified) | CVE |
|---------|----------------------|-----|
| `marked` | nested links / tables | CVE-2022-21680 |
| `moment` | preprocessRFC2822 | CVE-2022-31129 |
| `validator.js` | `isEmail` historically | various |
| `ua-parser-js` | UA pattern | CVE-2022-25927 |
| Cloudflare WAF | rule regex | 2019 incident |
| Stack Overflow | search regex | 2016 outage |

## Mitigation

- **Use a linear-time regex engine** (RE2 in Go, `re2-wasm` in Node, `Hyperscan`, .NET 7+ `NonBacktracking`, Python 3.11+ `re` is still NFA — use `re2` package).
- **Avoid nested quantifiers** and overlapping alternatives. Refactor `^(a+)+$` to `^a+$`.
- **Set a timeout** on regex execution (`java.util.regex.Pattern.matcher(...).useAnchoringBounds(...)` + watchdog thread, Python's `regex` module with `timeout=`).
- **Bound input length** before matching. Reject input over a few KB.
- **Pre-validate** with a coarse, safe check (e.g. length + char class) before applying the complex regex.

## References

- [OWASP — ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [Doyensec — regexploit](https://github.com/doyensec/regexploit)
- [Cloudflare — Details of the Cloudflare outage on July 2, 2019](https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/)

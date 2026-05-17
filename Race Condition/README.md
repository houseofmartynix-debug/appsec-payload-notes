# Race Condition

> Race conditions exploit a window between a check and an action (TOCTOU) or between two concurrent state changes.

## Summary

- [Common Targets](#common-targets)
- [Single-Endpoint Race](#single-endpoint-race)
- [Multi-Endpoint Race](#multi-endpoint-race)
- [Tools](#tools)
- [Single-Packet Attack](#single-packet-attack)
- [Worked Examples](#worked-examples)
- [Mitigation](#mitigation)
- [References](#references)

## Common Targets

- Coupon / gift-card redemption
- Voting / liking / rating
- Withdraw / transfer of money
- 2FA setup races
- Limited inventory purchase
- Friend-request / follow toggles
- Account creation with same email
- Password reset token usage

## Single-Endpoint Race

Fire 20+ identical requests at the same endpoint, in parallel, faster than the server can serialize.

Example — gift-card redeem (only valid once):

```bash
seq 30 | xargs -P30 -I{} curl -s -X POST https://target.tld/api/redeem \
  -H "Authorization: Bearer $T" -d '{"code":"GIFT123"}'
```

## Multi-Endpoint Race

A check on endpoint A, an action on endpoint B — flood both interleaved.

Example — withdraw vs balance check:

```
POST /api/balance/check     <- (server caches yes)
POST /api/withdraw          <- 10 parallel
```

## Tools

- [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder) (Burp extension)
- [race-the-web](https://github.com/insp3ctre/race-the-web)
- Custom Go / Python with `goroutines` / `asyncio`
- `wrk` / `hey` for raw throughput

## Single-Packet Attack

James Kettle's technique: send the **final byte** of each parallel request in a single TCP packet so they all arrive at the application layer simultaneously, regardless of network jitter.

Turbo Intruder template:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    engine.queue(target.req, gate='race1')
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

Sends all 30 requests' final byte at once.

## Worked Examples

### Coupon abuse

1. Generate 20 sessions with the same user.
2. From each, redeem the same `GIFT123` simultaneously.
3. Server checks `coupon.used == false` 20× before any commits → grants 20× the value.

### MFA bypass on activation

- Endpoint A: `POST /mfa/enable` (writes secret)
- Endpoint B: `POST /mfa/disable` (deletes secret)
- Race them; the final state can be inconsistent (account enabled MFA with attacker-known secret).

### Concurrent password reset

- Token consumed only after successful change.
- Race two `POST /reset` with the same token: both pass, both set passwords — depending on DB, one wins; sometimes you can set password for a *different* account by swapping the email in body.

### Account creation duplicate

- Many systems normalize emails (`a+b@x.com → a@x.com`).
- Two simultaneous signups with `victim@x.com` and `victim+anything@x.com` race past the uniqueness check.

## Mitigation

- Use **atomic database operations** with proper isolation (`SELECT ... FOR UPDATE`, `UPDATE ... WHERE used = false RETURNING ...`).
- Use **unique constraints** + retry logic at the DB layer.
- For idempotent operations, require an **idempotency key**.
- Apply **distributed locks** (Redis SETNX, ZooKeeper) for cross-service races.
- Implement **rate-limiting** but understand it's not sufficient against single-packet attacks.

## References

- [PortSwigger — Race Conditions](https://portswigger.net/web-security/race-conditions)
- [James Kettle — Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine)
- [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder)

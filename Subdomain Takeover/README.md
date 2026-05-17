# Subdomain Takeover

> A subdomain takeover happens when a DNS record points to a third-party service (S3, Azure, Heroku, GitHub Pages, etc.) that no longer exists. An attacker who claims that resource controls the subdomain.

## Summary

- [Workflow](#workflow)
- [Common Service Fingerprints](#common-service-fingerprints)
- [Tools](#tools)
- [Impact](#impact)
- [Reporting Tips](#reporting-tips)
- [Mitigation](#mitigation)
- [References](#references)

## Workflow

1. Enumerate subdomains:
   - `amass`, `subfinder`, `assetfinder`, `findomain`
   - `crt.sh`, `chaos.projectdiscovery.io`
   - DNS bruteforce with `dnsx` and large wordlists
2. Resolve and probe HTTP/HTTPS with `httpx`.
3. For each response, look for **takeover fingerprints** (404 / error pages from known providers).
4. Confirm the DNS record points to a service-controlled name (`CNAME`, `ALIAS`).
5. Claim the resource on that service and host content under the victim subdomain.

## Common Service Fingerprints

| Service | DNS pointer | Fingerprint |
|---------|-------------|-------------|
| AWS S3 | `*.s3.amazonaws.com` / `*.s3-website-*` | `NoSuchBucket` / `The specified bucket does not exist` |
| AWS Cloudfront | `*.cloudfront.net` | `Bad request: ERROR: The request could not be satisfied` (verify ownership) |
| GitHub Pages | `*.github.io` | `There isn't a GitHub Pages site here.` |
| Heroku | `*.herokuapp.com` / `*.herokussl.com` | `No such app` |
| Azure | `*.azurewebsites.net`, `*.cloudapp.net`, `*.trafficmanager.net`, `*.blob.core.windows.net` | `404 Web Site not found`, error pages |
| Shopify | `*.myshopify.com` | `Sorry, this shop is currently unavailable.` |
| Tumblr | `*.tumblr.com` | `Whatever you were looking for doesn't currently exist` |
| Fastly | `*.fastly.net` | `Fastly error: unknown domain` |
| Pantheon | `*.pantheonsite.io` | `The gods are wise, but do not know of the site which you seek.` |
| Surge.sh | `*.surge.sh` | `project not found` |
| Bitbucket | `*.bitbucket.io` | `Repository not found` |
| Ghost | `*.ghost.io` | `The thing you were looking for is no longer here, or never was` |
| Squarespace | `*.squarespace.com` | `No Such Account` |
| Webflow | `*.webflow.io` | `The page you are looking for doesn't exist or has been moved` |
| Cargo Collective | `*.cargocollective.com` | `404 Not Found` (verify ownership) |
| Help Scout | `*.helpscoutdocs.com` | `No settings were found for this company:` |
| Tilda | `*.tilda.ws` | `Please renew your subscription` |
| Unbounce | `*.unbouncepages.com` | `The requested URL was not found on this server.` |
| Worksites.net | `*.worksites.net` | `Hello! Sorry, but the webpage you requested could not be found.` |
| Strikingly | `*.s.strikinglydns.com` | `PAGE NOT FOUND.` |

The full curated list: [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz).

## Tools

- [subjack](https://github.com/haccer/subjack)
- [Subzy](https://github.com/PentestPad/subzy)
- [nuclei](https://github.com/projectdiscovery/nuclei) with the `takeovers` templates:
  ```bash
  nuclei -l hosts.txt -t http/takeovers/
  ```
- [SubOver](https://github.com/Ice3man543/SubOver)

## Impact

- **Phishing under the victim's brand.**
- **Cookie scope abuse**: if cookies are set on `.target.tld`, the attacker's subdomain receives them in cross-subdomain requests.
- **CORS subdomain allow-list bypass**: many apps trust `*.target.tld`.
- **OAuth `redirect_uri` allow-list bypass** when wildcard subdomain is registered.
- **Mixed-content / SSO assumptions** that internal subdomains are trusted.

## Reporting Tips

- Prove ownership without hosting malicious content. Publish a benign verification file (e.g. a clear `bugbounty.txt`).
- Document the cookie / CORS / OAuth chain that elevates impact beyond "I parked a page".
- Hand-back: dispose of the resource once the report is acknowledged so the org can take over again.

## Mitigation

- DNS records pointing at third-party services should be **deprovisioned alongside the resource**.
- Periodically audit `CNAME` records vs live resources.
- Use `_acme-challenge` etc. carefully — orphaned validation records can also lead to issuance attacks.
- For Bug Bounty programs: maintain a clear policy that ownership-proof must be benign.

## References

- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
- [HackerOne — Subdomain Takeovers](https://www.hackerone.com/application-security/guide-subdomain-takeovers)
- [Detectify Labs — Hostile Subdomain Takeover](https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/)

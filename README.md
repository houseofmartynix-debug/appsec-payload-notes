<h1 align="center">Payloads All The Things</h1>

<p align="center">
  A list of useful payloads and bypasses for Web Application Security.<br>
  Feel free to improve with your payloads and techniques.
</p>

<p align="center">
  <b>Author:</b> Marco Selva<br>
  <b>License:</b> MIT
</p>

---

> **DISCLAIMER**
> This repository is intended for **educational purposes**, **authorized penetration testing**, **CTF challenges**, and **defensive security research** only.
> Do **NOT** use these techniques against systems you do not own or have explicit written permission to test.
> The author assumes no liability and is not responsible for any misuse or damage caused by the use of this material.

---

## Table of Contents

| # | Category | Description |
|---|----------|-------------|
| 01 | [SQL Injection](./SQL%20Injection/) | Manipulating SQL queries to extract or modify data |
| 02 | [XSS Injection](./XSS%20Injection/) | Cross-site scripting payloads and bypasses |
| 03 | [Command Injection](./Command%20Injection/) | Operating system command execution |
| 04 | [XXE Injection](./XXE%20Injection/) | XML External Entity attacks |
| 05 | [SSRF](./SSRF/) | Server-Side Request Forgery |
| 06 | [CSRF Injection](./CSRF%20Injection/) | Cross-Site Request Forgery |
| 07 | [File Inclusion](./File%20Inclusion/) | Local and Remote File Inclusion (LFI / RFI) |
| 08 | [Directory Traversal](./Directory%20Traversal/) | Path traversal payloads |
| 09 | [Open Redirect](./Open%20Redirect/) | URL redirection vulnerabilities |
| 10 | [CRLF Injection](./CRLF%20Injection/) | Carriage Return Line Feed injection |
| 11 | [LDAP Injection](./LDAP%20Injection/) | LDAP query manipulation |
| 12 | [NoSQL Injection](./NoSQL%20Injection/) | MongoDB and other NoSQL DB injections |
| 13 | [Server Side Template Injection](./Server%20Side%20Template%20Injection/) | SSTI in Jinja2, Twig, Freemarker, etc. |
| 14 | [Insecure Deserialization](./Insecure%20Deserialization/) | PHP, Java, Python, .NET deserialization |
| 15 | [JWT](./JWT/) | JSON Web Token attacks |
| 16 | [OAuth Misconfiguration](./OAuth%20Misconfiguration/) | OAuth 2.0 / OIDC abuse |
| 17 | [GraphQL Injection](./GraphQL%20Injection/) | GraphQL introspection and abuse |
| 18 | [Prototype Pollution](./Prototype%20Pollution/) | JavaScript prototype chain attacks |
| 19 | [Race Condition](./Race%20Condition/) | TOCTOU and concurrency bugs |
| 20 | [Web Cache Deception](./Web%20Cache%20Deception/) | Cache poisoning and deception |
| 21 | [HTTP Request Smuggling](./HTTP%20Request%20Smuggling/) | CL.TE, TE.CL, TE.TE |
| 22 | [Upload Insecure Files](./Upload%20Insecure%20Files/) | Malicious file upload bypasses |
| 23 | [Authentication](./Authentication/) | Auth bypass, default creds, brute force |
| 24 | [API](./API/) | REST/SOAP API hacking |
| 25 | [CORS Misconfiguration](./CORS%20Misconfiguration/) | Cross-Origin abuse |
| 26 | [Account Takeover](./Account%20Takeover/) | ATO techniques |
| 27 | [Subdomain Takeover](./Subdomain%20Takeover/) | Dangling DNS records |
| 28 | [XPATH Injection](./XPATH%20Injection/) | XPath query injection |
| 29 | [Regular Expression DoS](./Regular%20Expression%20DoS/) | ReDoS payloads |
| 30 | [Methodology and Resources](./Methodology%20and%20Resources/) | Pentest methodology and references |

---

## Repository Structure

Each folder contains:

- `README.md` — Description, exploitation steps, payloads, bypasses, and references.
- Optional `Files/` — Proof-of-concept files, exploit scripts, wordlists.
- Optional `Intruder/` — Wordlists for use with Burp Intruder, ffuf, wfuzz, etc.

---

## How to Use This Repository

1. Identify the vulnerability class you are testing.
2. Browse to the related folder and read the `README.md`.
3. Start with **basic payloads**, then move to **bypass / filter evasion** sections.
4. Always validate impact before reporting.
5. Reference the **Methodology and Resources** folder for end-to-end pentest workflows.

---

## Contributing

Contributions are welcome! Read [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.
The goal is to keep payloads concise, categorized, and free of malicious intent.

---

## Tools Referenced Throughout

| Tool | Purpose |
|------|---------|
| Burp Suite | Web proxy and intruder |
| OWASP ZAP | Open-source web proxy |
| sqlmap | Automated SQL injection |
| ffuf / wfuzz / gobuster | Fuzzing and directory brute force |
| nmap | Network reconnaissance |
| nuclei | Templated vulnerability scanner |
| Amass / Subfinder | Subdomain enumeration |
| httpx | HTTP probing |
| dnsx | DNS resolver |
| jwt_tool | JWT auditing |
| graphw00f / clairvoyance | GraphQL fingerprinting |

---

## References and Inspiration

- OWASP Web Security Testing Guide (WSTG)
- OWASP Top 10
- PortSwigger Web Security Academy
- HackTricks
- Bug Bounty Reports from HackerOne / Bugcrowd
- CTF Writeups (DEF CON, HTB, THM)

---

<p align="center">
  Made with discipline by <b>Marco Selva</b> · <a href="./LICENSE">MIT License</a>
</p>

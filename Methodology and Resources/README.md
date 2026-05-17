# Methodology and Resources

> End-to-end pentest workflows, reusable command snippets, and a curated reading list. Use this folder as a "north star" for engagements.

## Summary

- [Engagement Lifecycle](#engagement-lifecycle)
- [Recon](#recon)
- [Active Scanning](#active-scanning)
- [Web Application Testing](#web-application-testing)
- [Network / Internal](#network--internal)
- [Linux Privilege Escalation](#linux-privilege-escalation)
- [Windows Privilege Escalation](#windows-privilege-escalation)
- [Active Directory](#active-directory)
- [Container & Cloud](#container--cloud)
- [Mobile](#mobile)
- [Reporting](#reporting)
- [Reading List](#reading-list)
- [Wordlists](#wordlists)

## Engagement Lifecycle

1. **Scoping** — sign Statement of Work, agree on targets, dates, escalation contacts.
2. **Authorization** — written approval, IPs whitelisted, out-of-scope explicitly listed.
3. **Recon** — passive then active.
4. **Threat modeling** — identify high-value assets.
5. **Vulnerability discovery** — manual + automated.
6. **Exploitation** — minimum-viable proof, no data exfil beyond what's needed.
7. **Post-exploitation** — lateral movement only if in scope.
8. **Reporting** — exec summary, technical details, reproduction, fix.
9. **Retest** — verify fixes.

## Recon

### Passive

```bash
amass enum -passive -d target.tld
subfinder -d target.tld -all
assetfinder --subs-only target.tld
chaos -d target.tld
findomain -t target.tld
curl -s "https://crt.sh/?q=%25.target.tld&output=json" | jq -r '.[].name_value' | sort -u
```

### Active

```bash
amass enum -active -d target.tld
dnsx -d target.tld -w wordlist.txt -resp
puredns bruteforce wordlist.txt target.tld
```

### Probing live hosts

```bash
httpx -l hosts.txt -title -status-code -tech-detect -screenshot
nuclei -l hosts.txt -t exposures/ -t cves/ -severity high,critical
```

### OSINT

- [github-search](https://github.com/gwen001/github-search) — leaked secrets in code.
- `trufflehog` — entropy / regex-based secret scanning.
- LinkedIn / Hunter.io for emails.
- Wayback Machine: `waybackurls target.tld | sort -u`.

## Active Scanning

```bash
nmap -sC -sV -oA scan target.tld
nmap -p- --min-rate 5000 -oA full target.tld
nmap -sU -F target.tld
naabu -host target.tld -p -
```

## Web Application Testing

### Crawl & wordlist

```bash
gospider -s https://target.tld -d 3 -o gospider/
katana -u https://target.tld -d 3 -o katana.txt
ffuf -u https://target.tld/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403
```

### Vulnerability scanning

```bash
nuclei -u https://target.tld -severity high,critical
nikto -h https://target.tld
testssl.sh https://target.tld
```

### Manual checklist

Use OWASP WSTG as the spine:

- Information gathering
- Configuration & deployment management
- Identity management
- Authentication
- Authorization
- Session management
- Input validation (SQLi, XSS, etc. — see sibling folders)
- Error handling
- Cryptography
- Business logic
- Client-side
- API

## Network / Internal

```bash
nmap -sC -sV -p- -oA full 10.0.0.0/24
crackmapexec smb 10.0.0.0/24
responder -I eth0
ntpdate target           # check time skew for Kerberos
enum4linux-ng -A 10.0.0.5
```

## Linux Privilege Escalation

### Enumeration

- [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)

### Key checks

```bash
id
sudo -l
find / -perm -4000 2>/dev/null            # SUID binaries
getcap -r / 2>/dev/null                    # capabilities
cat /etc/crontab; ls -la /etc/cron.*
mount; cat /etc/fstab
ps auxf
ss -tulpn
uname -a
```

### Exploit references

- [GTFOBins](https://gtfobins.github.io/) — abusable binaries.
- Kernel CVEs via `uname -a` + `searchsploit`.

## Windows Privilege Escalation

### Enumeration

- [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)
- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)

### Key checks

```powershell
whoami /priv
whoami /groups
systeminfo
Get-WmiObject Win32_Service | ? {$_.StartMode -eq "Auto"} | Select Name,PathName,State
Get-ScheduledTask | ? State -eq Ready
icacls "C:\Path\To\Service\binary.exe"
reg query HKLM\SYSTEM\CurrentControlSet\Services\<svc> /v ImagePath
```

### Common vectors

- Unquoted service paths
- AlwaysInstallElevated
- Token impersonation (`SeImpersonatePrivilege` → [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) / [GodPotato](https://github.com/BeichenDream/GodPotato))
- DLL hijacking
- Kernel exploits via `systeminfo`

## Active Directory

### Recon

```bash
bloodhound-python -d target.local -u user -p pass -ns 10.0.0.5 -c All
ldapsearch -x -H ldap://10.0.0.5 -D 'user@target.local' -w pass -b 'DC=target,DC=local'
crackmapexec ldap 10.0.0.5 -u user -p pass --users
```

### Attack paths

- **Kerberoasting**: dump SPN tickets → offline crack.
- **AS-REP roast**: users with `DONT_REQ_PREAUTH`.
- **Unconstrained delegation**: capture TGTs of any authenticator.
- **DCSync**: replicate AD secrets with `Replicating Directory Changes`.
- **ADCS misconfig**: ESC1–ESC15 (Certify, Certipy).
- **LAPS / GPO** read access.

### Tools

- [Impacket](https://github.com/fortra/impacket) — `secretsdump.py`, `GetUserSPNs.py`, `GetNPUsers.py`, `psexec.py`.
- [BloodHound](https://github.com/SpecterOps/BloodHound) — graph attack paths.
- [Certipy](https://github.com/ly4k/Certipy) — ADCS abuse.

## Container & Cloud

### Docker

```bash
docker ps; docker images
docker run --rm -it -v /:/host alpine     # if you can run docker as user
```

Check `cap_add`, `--privileged`, `/var/run/docker.sock` mounts.

### Kubernetes

```bash
kubectl auth can-i --list
kubectl get pods,svc,sa --all-namespaces
kubectl get secrets --all-namespaces
```

Look for: cluster-admin bindings, exposed dashboards, secrets in env vars, hostPath mounts.

### Cloud

- AWS: `aws sts get-caller-identity; aws iam list-attached-user-policies`; tools: [Pacu](https://github.com/RhinoSecurityLabs/pacu), [ScoutSuite](https://github.com/nccgroup/ScoutSuite), [CloudFox](https://github.com/BishopFox/cloudfox).
- Azure: `az account show; az role assignment list`; tools: [ROADtools](https://github.com/dirkjanm/ROADtools), [AzureHound](https://github.com/SpecterOps/AzureHound).
- GCP: `gcloud auth list; gcloud projects list`; tools: [GCP IAM Privilege Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation).

## Mobile

### Android

- Decompile APK: `jadx -d out app.apk`.
- Inspect: `AndroidManifest.xml` for exported components.
- Patch SSL pinning: `objection`, `Frida`.
- Static: `MobSF`.

### iOS

- Extract IPA, inspect `Info.plist`, ATS exceptions.
- Dump keychain via `objection`.

## Reporting

A good report has:

- **Executive summary** — risk language, no jargon.
- **Findings** — one per vuln, sorted by severity.
  - Title
  - Severity (CVSS or qualitative)
  - Affected URL / parameter / asset
  - Description
  - Impact (what an attacker gets)
  - Reproduction steps (numbered, deterministic)
  - Recommendation
  - References (CWE, OWASP, vendor advisories)
- **Methodology** — what you tested and how.
- **Appendices** — tool output, screenshots.

## Reading List

- [The Web Application Hacker's Handbook](https://www.amazon.com/Web-Application-Hackers-Handbook-Exploiting/dp/1118026470) — Stuttard & Pinto
- [Real-World Bug Hunting](https://nostarch.com/bughunting) — Peter Yaworski
- [The Hacker Playbook 3](https://www.amazon.com/Hacker-Playbook-Practical-Penetration-Testing/dp/1980901759)
- [Bug Bounty Bootcamp](https://nostarch.com/bug-bounty-bootcamp) — Vickie Li
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz)
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

## Wordlists

- [SecLists](https://github.com/danielmiessler/SecLists) — the indispensable collection.
- [Assetnote wordlists](https://wordlists.assetnote.io/) — high-quality, content-discovery focused.
- [jhaddix/all.txt](https://gist.github.com/jhaddix/) — subdomain bruteforce classic.
- [PayloadBox](https://github.com/payloadbox) — payload-specific lists.
- [fuzzdb](https://github.com/fuzzdb-project/fuzzdb) — attack patterns and vulnerability inputs.

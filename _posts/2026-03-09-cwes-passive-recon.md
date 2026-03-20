---
title: "CWES Cheatsheet — Passive Recon"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, recon, osint, passive-recon]
---

passive recon is all about gathering info without touching the target directly. no packets sent to them, no noise, just public sources and smart googling. the goal is to build a picture of the target before you ever send a single request.

---

## Passive Reconnaissance

passive reconnaissance involves gathering information about the target **without directly interacting** with it. this relies on analysing publicly available information and resources.

| Technique | Description | Example | Tools | Risk of Detection |
|---|---|---|---|---|
| `Search Engine Queries` | using search engines to uncover info about the target — websites, social media profiles, news articles | searching Google for "`[Target Name] employees`" | Google, DuckDuckGo, Bing, Shodan | Very Low |
| `WHOIS Lookups` | querying WHOIS databases for domain registration details | performing a WHOIS lookup to find registrant name, contact info, name servers | whois, online WHOIS services | Very Low |
| `DNS` | analysing DNS records to identify subdomains, mail servers, and other infrastructure | using `dig` to enumerate subdomains | dig, nslookup, host, dnsenum, fierce, dnsrecon | Very Low |
| `Web Archive Analysis` | examining historical snapshots to identify changes, vulnerabilities, or hidden info | using the Wayback Machine to view past versions of a target website | Wayback Machine | Very Low |
| `Social Media Analysis` | gathering info from LinkedIn, Twitter, Facebook | searching LinkedIn for employees to learn about roles and potential SE targets | LinkedIn, Twitter, Facebook, OSINT tools | Very Low |
| `Code Repositories` | analysing public repos for exposed credentials or vulnerabilities | searching GitHub for code related to the target that might contain secrets | GitHub, GitLab | Very Low |

---

## WHOIS

| Command | Description |
|---|---|
| `export TARGET="domain.tld"` | assign target to an environment variable |
| `whois $TARGET` | WHOIS lookup for the target |

```bash
whois inlanefreight.com

[...]
Domain Name: inlanefreight.com
Registry Domain ID: 2420436757_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrar.amazon
Registrar URL: https://registrar.amazon.com
Updated Date: 2023-07-03T01:11:15Z
Creation Date: 2019-08-05T22:43:09Z
[...]
```

each WHOIS record typically contains:

- `Domain Name` — the domain name itself (e.g., example.com)
- `Registrar` — the company where the domain was registered (e.g., GoDaddy, Namecheap)
- `Registrant Contact` — the person or organization that registered the domain
- `Administrative Contact` — the person responsible for managing the domain
- `Technical Contact` — the person handling technical issues related to the domain
- `Creation and Expiration Dates` — when it was registered and when it expires
- `Name Servers` — servers that translate the domain name into an IP address

for historical WHOIS data (ownership changes over time), use [WhoisFreaks](https://whoisfreaks.com/).

---

## Passive Subdomain Enumeration

this relies on external sources to discover subdomains without directly querying the target's DNS servers.

**Certificate Transparency (CT) logs** — public repositories of SSL/TLS certificates. these certificates often include a list of associated subdomains in their Subject Alternative Name (SAN) field.

**search engines** — using operators like `site:` to filter results and find subdomains.

**online databases** — various tools aggregate DNS data from multiple sources.

| Resource/Command | Description |
|---|---|
| `VirusTotal` | <https://www.virustotal.com/gui/home/url> |
| `Censys` | <https://censys.io/> |
| `Crt.sh` | <https://crt.sh/> |
| `curl -s https://sonar.omnisint.io/subdomains/{domain} \| jq -r '.[]' \| sort -u` | all subdomains for a given domain |
| `curl -s https://sonar.omnisint.io/tlds/{domain} \| jq -r '.[]' \| sort -u` | all TLDs found for a given domain |
| `curl -s https://sonar.omnisint.io/all/{domain} \| jq -r '.[]' \| sort -u` | all results across all TLDs for a given domain |
| `curl -s https://sonar.omnisint.io/reverse/{ip} \| jq -r '.[]' \| sort -u` | reverse DNS lookup on IP address |
| `curl -s https://sonar.omnisint.io/reverse/{ip}/{mask} \| jq -r '.[]' \| sort -u` | reverse DNS lookup of a CIDR range |
| `curl -s "https://crt.sh/?q=${TARGET}&output=json" \| jq -r '.[] \| "\(.name_value)\n\(.common_name)"' \| sort -u` | certificate transparency |
| `cat sources.txt \| while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}-${TARGET}"; done` | searching for subdomains on the sources provided in sources.txt |

### sources.txt

```
baidu
bufferoverun
crtsh
hackertarget
otx
projecdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
```

---

## Searching CT Logs

there are two popular options for searching CT logs:

| Tool | Key Features | Use Cases | Pros | Cons |
|---|---|---|---|---|
| [crt.sh](https://crt.sh/) | user-friendly web interface, simple search by domain, displays certificate details, SAN entries | quick and easy searches, identifying subdomains, checking certificate issuance history | free, easy to use, no registration required | limited filtering and analysis options |
| [Censys](https://search.censys.io/) | powerful search engine for internet-connected devices, advanced filtering by domain, IP, certificate attributes | in-depth analysis of certificates, identifying misconfigurations, finding related certificates and hosts | extensive data and filtering options, API access | requires registration (free tier available) |

```bash
# crt.sh — fetch JSON output and filter for dev subdomains
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u
```

---

## Passive Infrastructure Identification

| Resource/Command | Description |
|---|---|
| `Netcraft` | <https://www.netcraft.com/> |
| `WayBackMachine` | <http://web.archive.org/> |
| `WayBackURLs` | <https://github.com/tomnomnom/waybackurls> |
| `waybackurls -dates https://$TARGET > waybackurls.txt` | crawling URLs from a domain with the date it was obtained |

---

## Fingerprinting Techniques

there are several techniques used for web server and technology fingerprinting:

- **`Banner Grabbing`** — examining banners returned by web servers or services to identify software names, version numbers, and service details
- **`Analysing HTTP Headers`** — reviewing HTTP request and response headers for info disclosure. headers such as `Server` and `X-Powered-By` often expose web server software, frameworks, or scripting languages
- **`Probing for Specific Responses`** — sending crafted or malformed requests to trigger distinctive responses or error messages characteristic of specific web servers
- **`Analysing Page Content`** — inspecting the structure of web pages, source code, scripts, comments, and metadata for indicators like framework-specific files or copyright notices

| Tool | Description | Features |
|---|---|---|
| `Wappalyzer` | browser extension and online service for website technology profiling | identifies a wide range of web technologies — CMSs, frameworks, analytics tools, and more |
| `BuiltWith` | web technology profiler that provides detailed reports on a website's tech stack | offers both free and paid plans with varying levels of detail |
| `WhatWeb` | command-line tool for website fingerprinting | uses a vast database of signatures to identify various web technologies |
| `Nmap` | versatile network scanner for various recon tasks, including service and OS fingerprinting | can be used with scripts (NSE) for more specialised fingerprinting |
| `Netcraft` | web security services including website fingerprinting and security reporting | detailed reports on technology, hosting provider, and security posture |
| `wafw00f` | command-line tool specifically designed for identifying Web Application Firewalls (WAFs) | helps determine if a WAF is present and, if so, its type and configuration |

```bash
# nikto — only running the fingerprinting modules
nikto -h inlanefreight.com -Tuning b
# -h specifies the target host
# -Tuning b tells Nikto to only run the Software Identification modules
```

---

## Check Robots.txt

`www.example.com/robots.txt`

the robots.txt file lives in the root directory of a website. each set of instructions ("record") is separated by a blank line:

1. `User-agent` — which crawler or bot the rules apply to. a wildcard (`*`) means all bots
2. `Directives` — specific instructions to the identified user-agent

| Directive | Description | Example |
|---|---|---|
| `Disallow` | paths the bot should not crawl | `Disallow: /admin/` |
| `Allow` | explicitly permits crawling specific paths, even if they fall under a broader `Disallow` rule | `Allow: /public/` |
| `Crawl-delay` | delay (in seconds) between successive requests from the bot | `Crawl-delay: 10` |
| `Sitemap` | URL to an XML sitemap for more efficient crawling | `Sitemap: https://www.example.com/sitemap.xml` |

---

## Google Dorking

> refer to the [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)
{: .prompt-tip }

**useful combos to try:**

- finding login pages: `site:example.com inurl:login` or `site:example.com (inurl:login OR inurl:admin)`
- identifying exposed files: `site:example.com filetype:pdf` or `site:example.com (filetype:xls OR filetype:docx)`
- uncovering config files: `site:example.com inurl:config.php` or `site:example.com (ext:conf OR ext:cnf)`
- locating database backups: `site:example.com inurl:backup` or `site:example.com filetype:sql`

| Operator | Description | Example |
|---|---|---|
| `site:` | limits results to a specific website or domain | `site:example.com` |
| `inurl:` | finds pages with a specific term in the URL | `inurl:login` |
| `filetype:` | searches for files of a particular type | `filetype:pdf` |
| `intitle:` | finds pages with a specific term in the title | `intitle:"confidential report"` |
| `intext:` / `inbody:` | searches for a term within the body text of pages | `intext:"password reset"` |
| `cache:` | displays the cached version of a webpage | `cache:example.com` |
| `link:` | finds pages that link to a specific webpage | `link:example.com` |
| `related:` | finds websites related to a specific webpage | `related:example.com` |
| `info:` | provides a summary of information about a webpage | `info:example.com` |
| `define:` | provides definitions of a word or phrase | `define:phishing` |
| `numrange:` | searches for numbers within a specific range | `site:example.com numrange:1000-2000` |
| `allintext:` | finds pages containing all specified words in the body text | `allintext:admin password reset` |
| `allinurl:` | finds pages containing all specified words in the URL | `allinurl:admin panel` |
| `allintitle:` | finds pages containing all specified words in the title | `allintitle:confidential report 2023` |
| `AND` | narrows results by requiring all terms to be present | `site:example.com AND (inurl:admin OR inurl:login)` |
| `OR` | broadens results by including pages with any of the terms | `"linux" OR "ubuntu" OR "debian"` |
| `NOT` | excludes results containing the specified term | `site:bank.com NOT inurl:login` |
| `*` (wildcard) | represents any character or word | `site:socialnetwork.com filetype:pdf user* manual` |
| `..` (range search) | finds results within a specified numerical range | `site:ecommerce.com "price" 100..500` |
| `" "` (quotation marks) | searches for exact phrases | `"information security policy"` |
| `-` (minus sign) | excludes terms from the search results | `site:news.com -inurl:sports` |

---

## Wayback Machine

<https://web.archive.org/>

```bash
# waybackurls tool — find all archived URLs
# can reveal old endpoints, params, subdomains
waybackurls target.com
```

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)

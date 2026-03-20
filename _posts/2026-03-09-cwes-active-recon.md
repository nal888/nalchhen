---
title: "CWES Cheatsheet — Active Recon"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, recon, dns, active-recon]
---

active recon means you're actually touching the target — sending queries, probing responses. noisier than passive, but you get way more detail. this is where you start building the real attack surface map.

---

## Active Reconnaissance

in active reconnaissance, the attacker **directly interacts with the target system** to gather information.

| Technique | Description | Example | Tools | Risk of Detection |
|---|---|---|---|---|
| `Port Scanning` | identifying open ports and services running on the target | using Nmap to scan for open ports like 80 (HTTP) and 443 (HTTPS) | Nmap, Masscan, Unicornscan | High |
| `Vulnerability Scanning` | probing the target for known vulnerabilities like outdated software or misconfigurations | running Nessus against a web app to check for SQLi or XSS | Nessus, OpenVAS, Nikto | High |
| `Network Mapping` | mapping the target's network topology, connected devices and their relationships | using traceroute to determine the path packets take to the target | Traceroute, Nmap | Medium to High |
| `Banner Grabbing` | retrieving info from banners displayed by services on the target | connecting to port 80 and examining the HTTP banner to identify web server software and version | Netcat, curl | Low |
| `OS Fingerprinting` | identifying the operating system running on the target | using Nmap's OS detection (`-O`) to determine if the target runs Windows, Linux, or another OS | Nmap, Xprobe2 | Low |
| `Service Enumeration` | determining the specific versions of services running on open ports | using Nmap's `-sV` to determine if a web server is running Apache 2.4.50 or Nginx 1.18.0 | Nmap | Low |
| `Web Spidering` | crawling the target website to identify pages, directories, and files | running Burp Suite Spider or ZAP Spider to map out the structure of a website | Burp Suite Spider, ZAP Spider, Scrapy | Low to Medium |

---

## wafw00f

```bash
wafw00f inlanefreight.com

                ______
               /      \
              (  W00f! )
               \  ____/
               ,,    __            404 Hack Not Found
           |`-.__   / /                      __     __
           /"  _/  /_/                       \ \   / /
          *===*    /                          \ \_/ /  405 Not Allowed
         /     )__//                           \   /
    /|  /     /---`                        403 Forbidden
    \\/`   \ |                                 / _ \
    `\    /_\\_              502 Bad Gateway  / / \ \  500 Internal Error
      `_____``-`                             /_/   \_\

                        ~ WAFW00F : v2.2.0 ~
        The Web Application Firewall Fingerprinting Toolkit

[*] Checking https://inlanefreight.com
[+] The site https://inlanefreight.com is behind Wordfence (Defiant) WAF.
[~] Number of requests: 2
```

---

## WHOIS

| Command | Description |
|---|---|
| `export TARGET="domain.tld"` | assign target to an environment variable |
| `whois $TARGET` | WHOIS lookup for the target |

---

## DNS Record Types

| Record Type | Full Name | Description | Zone File Example |
|---|---|---|---|
| `A` | Address Record | maps a hostname to its IPv4 address | `www.example.com.` IN A `192.0.2.1` |
| `AAAA` | IPv6 Address Record | maps a hostname to its IPv6 address | `www.example.com.` IN AAAA `2001:db8:85a3::8a2e:370:7334` |
| `CNAME` | Canonical Name Record | creates an alias for a hostname, pointing it to another hostname | `blog.example.com.` IN CNAME `webserver.example.net.` |
| `MX` | Mail Exchange Record | specifies the mail server(s) responsible for handling email for the domain | `example.com.` IN MX 10 `mail.example.com.` |
| `NS` | Name Server Record | delegates a DNS zone to a specific authoritative name server | `example.com.` IN NS `ns1.example.com.` |
| `TXT` | Text Record | stores arbitrary text info, often used for domain verification or security policies | `example.com.` IN TXT `"v=spf1 mx -all"` |
| `SOA` | Start of Authority Record | specifies admin info about a DNS zone — primary name server, responsible person's email, and other params | `example.com.` IN SOA `ns1.example.com. admin.example.com. 2024060301 10800 3600 604800 86400` |
| `SRV` | Service Record | defines the hostname and port number for specific services | `_sip._udp.example.com.` IN SRV 10 5 5060 `sipserver.example.com.` |
| `PTR` | Pointer Record | used for reverse DNS lookups, mapping an IP address to a hostname | `1.2.0.192.in-addr.arpa.` IN PTR `www.example.com.` |

---

## DNS Enumeration

| Command | Description |
|---|---|
| `nslookup $TARGET` | identify the `A` record for the target domain |
| `nslookup -query=A $TARGET` | identify the `A` record for the target domain |
| `dig $TARGET @<nameserver/IP>` | identify the `A` record for the target domain |
| `dig a $TARGET @<nameserver/IP>` | identify the `A` record for the target domain |
| `nslookup -query=PTR <IP>` | identify the `PTR` record for the target IP address |
| `dig -x <IP> @<nameserver/IP>` | identify the `PTR` record for the target IP address |
| `nslookup -query=ANY $TARGET` | identify `ANY` records for the target domain |
| `dig any $TARGET @<nameserver/IP>` | identify `ANY` records for the target domain |
| `nslookup -query=TXT $TARGET` | identify the `TXT` records for the target domain |
| `dig txt $TARGET @<nameserver/IP>` | identify the `TXT` records for the target domain |
| `nslookup -query=MX $TARGET` | identify the `MX` records for the target domain |
| `dig mx $TARGET @<nameserver/IP>` | identify the `MX` records for the target domain |

### dig

the `dig` command (`Domain Information Groper`) is a versatile and powerful utility for querying DNS servers and retrieving various types of DNS records.

| Command | Description |
|---|---|
| `dig domain.com` | performs a default A record lookup for the domain |
| `dig domain.com A` | retrieves the IPv4 address (A record) |
| `dig domain.com AAAA` | retrieves the IPv6 address (AAAA record) |
| `dig domain.com MX` | finds the mail servers (MX records) |
| `dig domain.com NS` | identifies the authoritative name servers |
| `dig domain.com TXT` | retrieves any TXT records |
| `dig domain.com CNAME` | retrieves the canonical name (CNAME) record |
| `dig domain.com SOA` | retrieves the start of authority (SOA) record |
| `dig @1.1.1.1 domain.com` | specifies a specific name server to query |
| `dig +trace domain.com` | shows the full path of DNS resolution |
| `dig -x 192.168.1.1` | performs a reverse lookup on the IP address to find the associated hostname |
| `dig +short domain.com` | provides a short, concise answer to the query |
| `dig +noall +answer domain.com` | displays only the answer section of the query output |
| `dig domain.com ANY` | retrieves all available DNS records (note: many DNS servers ignore `ANY` queries per [RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482)) |

> some servers can detect and block excessive DNS queries. use caution and respect rate limits.
{: .prompt-warning }

---

## Zone Transfers

a zone transfer dumps the **entire DNS zone** — every subdomain, IP, and record. if it works, you basically get the full map handed to you on a plate. rarely works on properly configured servers, but always worth trying.

```bash
# dig — attempt zone transfer
dig axfr @nsztm1.digi.ninja zonetransfer.me
dig axfr @8.8.8.8 zonetransfer.me    # Google DNS

# nslookup
nslookup -type=any -query=AXFR $TARGET nameserver.target.domain

# fierce — auto-tries zone transfer + brute force as fallback
fierce --domain target.com
```

---

## Active Infrastructure Identification

**Fingerprinting Techniques:**

- **`Banner Grabbing`** — examining banners returned by web servers or services to identify software names, version numbers, and service details
- **`Analysing HTTP Headers`** — reviewing HTTP headers for info disclosure. `Server` and `X-Powered-By` often expose web server software, frameworks, or scripting languages
- **`Probing for Specific Responses`** — sending crafted or malformed requests to trigger distinctive responses or error messages
- **`Analysing Page Content`** — inspecting page structure, source code, scripts, comments, and metadata for framework-specific indicators

```bash
# nikto — only running the fingerprinting modules
nikto -h inlanefreight.com -Tuning b
# -h specifies the target host
# -Tuning b tells Nikto to only run the Software Identification modules
```

| Resource/Command | Description |
|---|---|
| `curl -I "http://${TARGET}"` | display HTTP headers of the target webserver |
| `whatweb -a https://www.facebook.com -v` | technology identification |
| `Wappalyzer` | <https://www.wappalyzer.com/> |
| `wafw00f -v https://$TARGET` | WAF fingerprinting |
| `Aquatone` | <https://github.com/michenriksen/aquatone> |
| `cat subdomain.list \| aquatone -out ./aquatone -screenshot-timeout 1000` | makes screenshots of all subdomains in the subdomain.list |

---

## Active Subdomain Enumeration

| Resource/Command | Description |
|---|---|
| `HackerTarget` | <https://hackertarget.com/zone-transfer/> |
| `SecLists` | <https://github.com/danielmiessler/SecLists> |
| `nslookup -type=any -query=AXFR $TARGET nameserver.target.domain` | zone transfer using nslookup |
| `gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"` | bruteforcing subdomains |

```bash
# dnsenum — all-in-one
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# dnsrecon brute force
dnsrecon -d target.com -t brt \
  -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# fierce — brute with custom wordlist
fierce --domain target.com \
  --subdomain-file /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt
```

**note:** this is **DNS-based** subdomain fuzzing. it queries public DNS servers. if the subdomain isn't in DNS (internal/vhost only), you need **VHost fuzzing** instead.

there are several tools available for brute-force enumeration:

| Tool | Description |
|---|---|
| [dnsenum](https://github.com/fwaeytens/dnsenum) | comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains |
| [fierce](https://github.com/mschwager/fierce) | user-friendly tool for recursive subdomain discovery, featuring wildcard detection |
| [dnsrecon](https://github.com/darkoperator/dnsrecon) | versatile tool that combines multiple DNS recon techniques and offers customisable output formats |
| [amass](https://github.com/owasp-amass/amass) | actively maintained tool focused on subdomain discovery, known for integration with other tools and extensive data sources |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans |
| [puredns](https://github.com/d3mondev/puredns) | powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively |

### DNSEnum

`dnsenum` is a comprehensive toolkit for DNS reconnaissance written in Perl. key functions:

- `DNS Record Enumeration` — retrieves A, AAAA, NS, MX, and TXT records
- `Zone Transfer Attempts` — automatically attempts zone transfers from discovered name servers
- `Subdomain Brute-Forcing` — supports brute-force enumeration using a wordlist
- `Google Scraping` — scrapes Google search results to find additional subdomains
- `Reverse Lookup` — performs reverse DNS lookups to identify domains associated with a given IP
- `WHOIS Lookups` — performs WHOIS queries for domain ownership and registration details

---

## Virtual Hosts

virtual hosts allow multiple websites to run on the **same IP** — differentiated by the `Host:` header. these don't show up in DNS, so you can't find them with standard subdomain tools.

the key difference between `VHosts` and `subdomains`:

- `Subdomains` — extensions of a main domain (e.g., `blog.example.com`). typically have their own DNS records
- `Virtual Hosts (VHosts)` — configurations within a web server that allow multiple websites on a single server. can be associated with top-level domains or subdomains

if a virtual host does not have a DNS record, you can still access it by modifying the `hosts` file on your local machine.

### Types of Virtual Hosting

| Type | How it works |
|---|---|
| `Name-Based` | same IP, different `Host` header → different site. most common and flexible. doesn't require multiple IPs |
| `IP-Based` | each site gets its own IP. doesn't rely on the `Host` header, better isolation. requires multiple IPs (expensive) |
| `Port-Based` | same IP, different port → different site. can be used when IPs are limited, but not as user-friendly |

### Example Apache VHost Config

```apacheconf
# Example of name-based virtual host configuration in Apache
<VirtualHost *:80>
    ServerName www.example1.com
    DocumentRoot /var/www/example1
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example2.org
    DocumentRoot /var/www/example2
</VirtualHost>

<VirtualHost *:80>
    ServerName www.another-example.net
    DocumentRoot /var/www/another-example
</VirtualHost>
```

### VHost Fuzzing

| Resource/Command | Description |
|---|---|
| `curl -s http://192.168.10.10 -H "Host: randomtarget.com"` | changing the HOST HTTP header to request a specific domain |
| `cat ./vhosts.list \| while read vhost; do echo "\n********\nFUZZING: ${vhost}\n********"; curl -s -I http://<IP> -H "HOST: ${vhost}.target.domain" \| grep "Content-Length: "; done` | bruteforcing for possible virtual hosts |
| `ffuf -w ./vhosts -u http://<IP> -H "HOST: FUZZ.target.domain" -fs 612` | bruteforcing virtual hosts using `ffuf` |

```bash
# ffuf VHost fuzzing — modify Host header
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://<target>/ \
  -H "Host: FUZZ.target.com" \
  -fs <default_size>

# gobuster vhost
gobuster vhost -u http://target.com/ \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain
```

**when to use VHost vs DNS fuzzing:**
- domain in **public DNS** → DNS subdomain fuzzing
- domain in **`/etc/hosts`** or internal → VHost fuzzing

### Virtual Host Discovery Tools

| Tool | Description | Features |
|---|---|---|
| [gobuster](https://github.com/OJ/gobuster) | multi-purpose tool often used for directory/file brute-forcing, but also effective for vhost discovery | fast, supports multiple HTTP methods, can use custom wordlists |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | similar to Gobuster, but with a Rust-based implementation | supports recursion, wildcard discovery, and various filters |
| [ffuf](https://github.com/ffuf/ffuf) | fast web fuzzer that can be used for vhost discovery by fuzzing the `Host` header | customizable wordlist input and filtering options |

**gobuster tips:**
- use the `-t` flag to increase threads for faster scanning
- the `-k` flag can ignore SSL/TLS certificate errors
- use the `-o` flag to save output to a file

---

## Crawling

crawling follows links across the site to map out the structure automatically.

| Resource/Command | Description |
|---|---|
| `ZAP` | <https://www.zaproxy.org/> |
| `ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt` | discovering files and folders that cannot be spotted by browsing the website |
| `ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://www.target.domain/FOLDERS/WORDLISTEXTENSIONS` | mutated bruteforcing against the target web server |

---

## Spider Recon

```bash
# install scrapy
pip3 install scrapy

# install reconspider
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip

# run reconspider
python3 ReconSpider.py http://inlanefreight.com
```

output from `result.json`:

```json
{
    "emails": [
        "lily.floid@inlanefreight.com",
        "cvs@inlanefreight.com"
    ],
    "links": [
        "https://www.themeansar.com",
        "https://www.inlanefreight.com/index.php/offices/"
    ],
    "external_files": [
        "https://www.inlanefreight.com/wp-content/uploads/2020/09/goals.pdf"
    ]
}
```

| JSON Key | Description |
|---|---|
| `emails` | lists email addresses found on the domain |
| `links` | lists URLs of links found within the domain |
| `external_files` | lists URLs of external files such as PDFs |
| `js_files` | lists URLs of JavaScript files used by the website |
| `form_fields` | lists form fields found on the domain |
| `images` | lists URLs of images found on the domain |
| `videos` | lists URLs of videos found on the domain |
| `audio` | lists URLs of audio files found on the domain |
| `comments` | lists HTML comments found in the source code |

---

## Auto Recon Tools

### FinalRecon

```bash
# install
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py

# usage
./finalrecon.py --help
./finalrecon.py --headers --whois --url http://inlanefreight.com
./finalrecon.py --full target.com
./finalrecon.py --headers target.com     # server headers
./finalrecon.py --sslinfo target.com     # SSL cert details
./finalrecon.py --crawl target.com       # crawl for links
```

### Reconnaissance Frameworks

| Framework | Description |
|---|---|
| [FinalRecon](https://github.com/thewhiteh4t/FinalRecon) | Python-based recon tool offering modules for SSL certificate checking, Whois, header analysis, and crawling |
| [Recon-ng](https://github.com/lanmaster53/recon-ng) | powerful framework with modules for DNS enumeration, subdomain discovery, port scanning, web crawling, and exploit discovery |
| [theHarvester](https://github.com/laramies/theHarvester) | designed for gathering email addresses, subdomains, hosts, employee names, open ports from public sources |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | OSINT automation tool that integrates with various data sources to collect IPs, domains, emails, social media profiles |
| [OSINT Framework](https://osintframework.com/) | collection of various tools and resources for open-source intelligence gathering |

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)

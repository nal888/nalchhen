---
title: "CWES Cheatsheet"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, web-exploitation, htb]
pin: true
toc: false
---

this is my personal cheatsheet collection for the **Certified Web Exploitation Specialist (CWES)** cert. i'm sharing the structure and tools i used while studying, not to hand you answers, but hopefully to inspire you to build your own.

go through the topics, pick up the tools, and make your own notes. that's how it actually sticks.

---

## Topics

| Attack Vector | Tools / Commands | Key Topics |
|---|---|---|
| <a href="/posts/cwes-passive-recon/" target="_blank">Passive Recon</a> | host, wafw00f, whois, google dork, wayback | Public info, subdomain recon, infrastructure ID |
| <a href="/posts/cwes-active-recon/" target="_blank">Active Recon</a> | nslookup, dnsrecon, dnsenum, dig, fierce | Subdomain enum, VHOST, zone transfers, DNS |
| <a href="/posts/cwes-fuzzing/" target="_blank">Fuzzing</a> | ffuf, Gobuster, Wenum, Feroxbuster | Dir/page/extension/param/API fuzzing |
| <a href="/posts/cwes-xss/" target="_blank">XSS</a> | XSStrike, Brute XSS, XSSer | Stored, Reflected, DOM-based |
| <a href="/posts/cwes-sql-injection/" target="_blank">SQL Injection</a> | SQLMap, manual SQL | SQLi fundamentals, SQLMap essentials |
| <a href="/posts/cwes-command-injection/" target="_blank">Command Injection</a> | Blacklist filters | Filter bypass techniques |
| <a href="/posts/cwes-file-upload/" target="_blank">File Upload</a> | Client-side/blacklist/whitelist/content-type bypass | Upload filter bypasses |
| <a href="/posts/cwes-file-inclusion/" target="_blank">File Inclusion</a> | LFI, PHPWrapper | LFI, PHP wrappers |
| <a href="/posts/cwes-server-side-attacks/" target="_blank">Server-Side Attacks</a> | SSRF, SSTI, SSI, XSLT | Server-side injection techniques |
| <a href="/posts/cwes-login-brute-forcing/" target="_blank">Login Brute Forcing</a> | Hydra, hashcat | Brute force, password cracking |
| <a href="/posts/cwes-broken-authentication/" target="_blank">Broken Authentication</a> | — | Auth bypass techniques |
| <a href="/posts/cwes-web-attacks/" target="_blank">Web Attacks</a> | HTTP Verb Tamper, IDOR, XXE | Verb tampering, IDOR, XXE |
| <a href="/posts/cwes-graphql/" target="_blank">Attacking GraphQL</a> | GraphQL | Enumeration, exploitation |
| <a href="/posts/cwes-api-attacks/" target="_blank">API Attacks</a> | REST | REST API attack techniques |
| <a href="/posts/cwes-common-applications/" target="_blank">Attacking Common Applications</a> | — | Common app exploitation |
| <a href="/posts/cwes-javascript-deobfuscation/" target="_blank">JavaScript Deobfuscation</a> | — | JS deobfuscation techniques |

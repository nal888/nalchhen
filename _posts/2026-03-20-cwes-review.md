---
title: "HTB CWES — Exam Review, Tips & Practice Machines"
date: 2026-03-20
categories: [Certifications, CWES]
tags: [cwes, review, htb, exam, web-exploitation]
pin: true
image:
  path: /assets/img/htb/cwes-certificate.jpg
  alt: HTB Certified Web Exploitation Specialist
---

so, i did a thing.

i'm a 2nd-year cyber security student and this is my first ever hacking certification. i spent my entire holiday break grinding through the htb academy modules, taking insane amounts of notes, and practising. then with exactly one week left before uni started back up, i just said screw it and hit "start exam".

three days in, i had enough flags to hit the passing score of 80%. the remaining four days i spent almost entirely on polishing my report — more on that later.

here's what the experience was actually like and what i'd tell anyone about to take it.

---

## the experience

you get **7 days** to compromise **5 different web applications** and write a **commercial-grade penetration test report**.

the exam is straightforward in the sense that there's nothing unfair or out of scope, but it's definitely not simple. you can't just throw payloads at a login form and expect a shell. the apps feel like real web apps, not ctf challenges, and you have to get creative with how you chain vulnerabilities together to get from zero to admin.

i got stuck for hours on two of the apps. both times the vulnerability turned out to be something simple — i was just so tunnel-focused on one approach that i couldn't see it. both times, i stepped away, took a break, came back with a fresh idea, tried it, and it worked. that pattern kept repeating.

this was my first real hacking cert and honestly it taught me a lot about how to look at web applications differently from a security standpoint. before this i'd look at a web app and just see a website. now i look at it and start thinking about what's happening behind every request, every parameter, every redirect. that shift in perspective alone was worth the grind.

---

## the report

htb's report grading is **strict**. like, really strict. they want a proper commercial-quality penetration test report — executive summary, detailed findings with evidence, risk ratings, remediation recommendations, the whole thing.

this is why i spent 4 out of my 7 days on the report even after hitting my passing score. i wasn't taking any chances. my workflow:

- set up [SysReptor](https://docs.sysreptor.com/) with the CWES template **before** starting the exam
- every time i found a vulnerability or got a flag, i wrote it up immediately with screenshots
- after i had all my flags, i went back and made sure every finding was clear, well-evidenced, and had proper remediation advice
- last day was proofreading, formatting, and making sure the executive summary actually made sense

> set up your report template before you even connect to the vpn. do not leave report writing until the end — your brain will be fried and you'll hate yourself.
{: .prompt-tip }

---

## tips

### 1. document as you go

seriously. i wrote up findings the moment i confirmed them. if i had left all of that for day 6 or 7, i would've been cooked. screenshots get messy, you forget exact steps, and the quality drops.

### 2. move on when you're stuck

i wasted so many hours tunnelling on two apps. both times the answer was something i would've seen earlier if i'd just stepped away and looked at a different target first. when you come back with fresh eyes, things that were invisible before suddenly become obvious.

### 3. take insane notes during your study

i went through every academy module and wrote my own notes for each one — commands, techniques, examples, all of it. during the exam i was constantly referencing my own cheatsheet. writing things out in your own words is what makes it stick.

### 4. practise black-box web testing

the skill assessments at the end of each module aren't really black-box — you already know what vulnerability you're looking for. the exam is different. you have zero idea what vulns are present, so you need to test everything.

grind through some HTB machines (see the list below) to build that mindset. since the cwes exam is purely web-based, you only need to focus on the **initial web access** — skip the priv esc, that's not what you're training for here.

---

## my cwes cheatsheet

i compiled all of my study notes into a master cheatsheet that i used heavily during both my prep and the exam itself. it covers every vulnerability class from passive recon to server-side attacks with full command references.

sharing it not as a shortcut to pass, but hopefully to give you a starting point for building your own.

> **[CWES Cheatsheet](/posts/cwes-cheatsheet/)**

---

## htb machines for practice

these are boxes i'd recommend for building black-box web testing confidence. focus on the **web exploitation foothold only** — once you've popped the initial access, that's the skill you're training for cwes.

> don't feel like you need to do all of these. do enough until you're comfortable finding web vulns without being told what to look for, then go sit the exam.
{: .prompt-info }

| # | Machine | OS | Key Focus |
|---|---|---|---|
| 1 | Bashed | Linux | Web shell, directory discovery |
| 2 | BountyHunter | Linux | XXE, Python exploitation |
| 3 | Friendzone | Linux | DNS, LFI |
| 4 | Bastion | Windows | SMB, VHD mounting |
| 5 | Return | Windows | Printer abuse, service exploitation |
| 6 | Heist | Windows | Password cracking, RID cycling |
| 7 | Cronos | Linux | DNS zone transfer, command injection |
| 8 | Shibboleth | Linux | IPMI, Zabbix exploitation |
| 9 | Bastard | Windows | Drupal exploitation |
| 10 | Sniper | Windows | LFI, RFI |
| 11 | Alert | Linux | Web enumeration |
| 12 | Cap | Linux | PCAP analysis, IDOR |
| 13 | GoodGames | Linux | SQLi, SSTI |
| 14 | TwoMillion | Linux | API exploitation |
| 15 | Headless | Linux | XSS, command injection |
| 16 | Usage | Linux | SQLi, file upload |
| 17 | OpenSource | Linux | Source code review, Git |
| 18 | Editorial | Linux | SSRF, API enumeration |
| 19 | Nineveh | Linux | Brute force, LFI |
| 20 | Enterprise | Linux | WordPress, SQLi |
| 21 | Forge | Linux | SSRF |
| 22 | RedCross | Linux | XSS, SQLi |
| 23 | Timing | Linux | LFI, mass assignment |
| 24 | Node | Linux | API exploitation, deserialization |

---

if you're studying for this, especially while balancing uni — just go for it. it's stressful, but it's the kind of stress that actually teaches you something.

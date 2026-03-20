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

as a 2nd-year cyber security student, this certification means a whole lot to me. i spent my entire holiday break grinding through the modules, taking insane amounts of notes, and practicing. then, with exactly one week left before the new university semester started, i decided to just yolo it and hit the "start exam" button.

somehow, through a mix of tryhard mentality, caffeine, and trusting my methodology, **i passed.**

here is my honest review of the hack the box **certified web exploitation specialist (CWES)** exam, what the experience was actually like, and a few tips that saved my life during that 7-day sprint.

---

## the experience: what is the cwes actually like?

a lot of people compare this to other certs, but htb is just built different. you get **7 days** to compromise **5 different web applications** (going from zero access to full admin) and write a **commercial-grade report**.

the biggest shock for me was how real it felt. these aren't just little ctf challenges built specifically to be hackable — they feel like actual web apps you'd see in a real-world audit. you really have to **chain vulnerabilities together**. you might find something small in one place that gives you the context you need to exploit a completely different app. it's exhausting, but honestly? it's damn cool when everything finally clicks.

because i started it a week before uni, i had to treat it like a full-time job. i put in some massive hours those first few days, but the feeling of submitting that final report before my first day of class was unmatched.

> the exam environment was very stable and felt realistic. these apps are built for actual users, not just built to be "hackable". finding the exploitation steps required deep understanding of the modules and how techniques from one module apply to another.
{: .prompt-info }

---

## my top tips for passing

if you are a student or just someone gearing up for this exam, here is what actually worked for me:

### 1. document while you hack, not after

do not leave the report until the end. set up your template (a lot of people use [SysReptor](https://docs.sysreptor.com/)) before you even connect to the vpn. every time you get a flag or find a vulnerability, write it up immediately. htb grading is strict, and scrambling to write a professional report on day 7 when your brain is fried is a terrible idea.

> download the CWES SysReptor template and examine it **before** starting the exam. plan out your report writing strategy in advance — don't figure it out during the exam itself.
{: .prompt-tip }

my report workflow looked something like this:

- **start of engagement** — fill in meta info, scope, and engagement details
- **during engagement** — write up each finding immediately when discovered. log every flag in the appendix as soon as you get it
- **end of engagement** — write the executive summary, assessment overview, and recommendations. then tidy up: grammar, proofreading, styling

### 2. don't get tunnel vision

if you are stuck on a target for hours, **step away**. go look at one of the other web apps. it happened to me more than once where looking at a different target gave me a fresh idea for the one i was stuck on.

> this is genuinely the most common advice from everyone who's passed this cert, and it's common because it works. context-switching resets your brain.
{: .prompt-tip }

### 3. take borderline insane notes

you can't rely on memory for this. i copied important academy concepts, step-by-step writeups for the skills assessments, and made a cheat sheet for every vulnerability class. writing it out in your own words is what builds your muscle memory.

### 4. practise black-box testing before the exam

the skill assessments at the end of each module aren't really black-box — you already know what vulnerability class you're looking for. in the real exam, you come in with **zero knowledge** of what vulnerabilities the application might have. that's a completely different mindset.

to bridge that gap, grind through some HTB machines (see the practice list below). since the cwes exam is purely web-based, you only need to focus on the **initial web access** — no need for privilege escalation. the goal is to build your own black-box methodology for web apps.

---

## my personal cwes cheatsheet

speaking of taking insane notes, i actually compiled all of my study materials, tools, and methodologies into a master cheatsheet.

i used this heavily during my holiday prep and during the exam itself. it covers everything from passive recon to server-side attacks, with full command references, tables, and examples for every vulnerability class. i'm sharing it here not to give you a magic key to pass, but to give you a structure to **inspire your own notes**.

> **check out my [CWES Cheatsheet here](/posts/cwes-cheatsheet/)**

---

## htb machines for practice

these are machines i'd recommend for building black-box web testing confidence before the exam. since cwes is purely web-focused, **you only need to practise the initial access / web exploitation foothold** — no need to bother with privilege escalation. once you've popped the web vuln and gotten in, that's the skill you're training.

> don't feel compelled to complete every single machine. do enough until you feel confident with your black-box web methodology, then go sit the exam.
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

## final thoughts

the cwes is genuinely one of the best web security certifications out there. the training material is thorough, the exam is challenging but fair, and the report writing requirement forces you to think like a real consultant — not just a flag hunter.

to anyone else studying for this, especially if you're balancing it with school: drink water, trust your notes, and don't be afraid to just go for it.

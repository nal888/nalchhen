---
title: "CWES Cheatsheet — JavaScript Deobfuscation"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, javascript, deobfuscation, js]
---

obfuscated JavaScript is common in CTFs and real-world recon. learning to read and deobfuscate it helps you find hidden endpoints, credentials, and logic that devs didn't want you to see.

---

## Code Obfuscation Basics

Obfuscation makes code harder to read without changing its behavior.

**Common Obfuscation Techniques**

| Technique | Description |
|---|---|
| Variable renaming | `username` → `_0x3a1f` |
| String encoding | Strings split, hex/base64 encoded |
| Dead code injection | Irrelevant code added to confuse |
| Control flow flattening | `if/else` replaced with switch/state machine |
| Packer | Code compressed + wrapped in eval/decoding stub |
| Array shuffling | Strings stored in shuffled array, referenced by index |
| `eval()` wrappers | Entire code passed to `eval()` at runtime |

**Spotting Obfuscated JS**

```javascript
// Signs to look for:
eval(function(p,a,c,k,e,d){...})   // packer pattern
var _0xabc1=['\x68\x65\x6c\x6c\x6f'];  // hex-encoded strings
String.fromCharCode(72,101,108,108,111)  // charcode array
atob('aGVsbG8=')                    // base64 inline
```

---

## Deobfuscation Techniques

**Tools:** beautifier.io, de4js, browser devtools

**Step 1: Beautify first**

```bash
# Online tools
# https://beautifier.io
# https://de4js.kshift.me
# https://prettier.io/playground

# Local with Node.js
npm install -g js-beautify
js-beautify obfuscated.js -o clean.js
```

**Step 2: Identify the encoding scheme**

```javascript
// Hex strings
'\x68\x65\x6c\x6c\x6f'   // decode in console: "\x68\x65\x6c\x6c\x6f"

// Unicode escapes
'\u0068\u0065\u006c\u006c\u006f'

// Base64
atob('aGVsbG8=')           // → "hello"

// Char codes
String.fromCharCode(72,101,108)  // run in console
```

**Step 3: Use browser DevTools**

```
1. Open DevTools → Sources tab
2. Paste obfuscated code in console (read-only, don't execute untrusted code)
3. Use "Pretty print" button ({}) to format minified code
4. Set breakpoints to inspect variable values at runtime
```

---

## Minified vs Obfuscated

| | Minified | Obfuscated |
|---|---|---|
| Goal | Reduce file size | Hide logic |
| Reversible | Yes — beautify | Partially — depends on technique |
| Variable names | Shortened but readable | Replaced with `_0x...` junk |
| Strings | Readable | Encoded (hex, base64, charcode) |
| Tool | beautifier.io | de4js, manual analysis |

---

## Decoding Encoded Strings

**Tools:** CyberChef, atob(), manual

```javascript
// Base64 — decode in browser console
atob('aGVsbG8gd29ybGQ=')         // → "hello world"
btoa('hello world')               // encode

// Hex string
'\x68\x65\x6c\x6c\x6f'          // paste in console → "hello"

// Char code array
String.fromCharCode(104,101,108,108,111)  // → "hello"

// URL-encoded
decodeURIComponent('%68%65%6c%6c%6f')    // → "hello"
```

**CyberChef Recipes**

```
From Base64 → output
From Hex → output
From Charcode → output
URL Decode → output
Magic (auto-detect) → often works for simple encoding
```

---

## Analysing Deobfuscated Code

After cleaning up the code, look for:

```javascript
// API endpoints hidden in strings
fetch('/api/v1/secret-endpoint')
XMLHttpRequest.open('POST', '/internal/admin')

// Hardcoded credentials or tokens
var apiKey = 'sk-xxxxxxxxxxxxxxxx'
var password = 'sup3r_s3cr3t'

// Hidden parameters
var hiddenParam = 'debug=true&admin=1'

// Conditional logic that reveals bypass paths
if (user.role === 'admin') { /* skip auth */ }
```

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)

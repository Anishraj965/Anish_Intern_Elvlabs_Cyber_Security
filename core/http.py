"""
core/http.py
=============
HttpClient  — shared requests.Session wrapper with DVWA auto-login.
Crawler     — recursive HTML link + form crawler.
Both live here so the rest of the project only needs one HTTP import.
"""

from __future__ import annotations

import random
import re
import time
from typing import Callable, Dict, List, Optional, Set
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
]
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "DNT": "1",
}
WAF_INDICATORS = [
    "cloudflare", "incapsula", "akamai", "imperva", "barracuda",
    "modsecurity", "webknight", "sucuri", "sitelock", "comodo",
    "access denied", "request blocked", "web application firewall",
    "security violation", "403 forbidden",
]
DVWA_SAFE_KEYWORDS = [
    "login", "csrf", "token", "dvwa", "security", "captcha",
    "phpids", "help", "about", "instructions", "setup", "logout",
]
SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".map",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".mp4", ".mp3",
)

LogFn = Optional[Callable[[str], None]]


# ─────────────────────────── HTTP CLIENT ───────────────────────────
class HttpClient:
    def __init__(self, timeout: int = 10, delay: float = 0.5,
                 use_cookies: bool = True, logger: LogFn = None):
        self.session = requests.Session()
        self.timeout = timeout
        self.delay = delay
        self.logger = logger
        self.request_count = 0
        if not use_cookies:
            self.session.cookies.clear()

    def _log(self, msg: str) -> None:
        if self.logger:
            self.logger(msg)

    # ── Core HTTP methods ──────────────────────────────────────────
    def get(self, url: str, allow_redirects: bool = True,
            timeout: Optional[int] = None) -> Optional[requests.Response]:
        time.sleep(self.delay)
        headers = DEFAULT_HEADERS.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)
        try:
            r = self.session.get(url, headers=headers,
                                  timeout=timeout or self.timeout,
                                  allow_redirects=allow_redirects)
            self.request_count += 1
            return r
        except requests.exceptions.HTTPError as e:
            if e.response and e.response.status_code == 403:
                self._log(f"[HTTP] 403 Forbidden: {url}")
            else:
                self._log(f"[HTTP] Error: {e} — {url}")
        except requests.exceptions.Timeout:
            self._log(f"[HTTP] Timeout: {url}")
        except RequestException as e:
            self._log(f"[HTTP] Request failed: {url} ({e})")
        return None

    def post(self, url: str, data: Optional[Dict] = None,
             json: Optional[Dict] = None,
             extra_headers: Optional[Dict] = None,
             timeout: Optional[int] = None) -> Optional[requests.Response]:
        time.sleep(self.delay)
        headers = DEFAULT_HEADERS.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)
        if extra_headers:
            headers.update(extra_headers)
        try:
            r = self.session.post(url, data=data, json=json,
                                   headers=headers,
                                   timeout=timeout or self.timeout,
                                   allow_redirects=True)
            self.request_count += 1
            return r
        except RequestException as e:
            self._log(f"[HTTP] POST failed: {url} ({e})")
        return None

    def timed_get(self, url: str,
                  timeout: Optional[int] = None) -> tuple[Optional[requests.Response], float]:
        """GET that also returns elapsed wall-clock time (used for time-based SQLi)."""
        time.sleep(self.delay)
        headers = DEFAULT_HEADERS.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)
        start = time.time()
        try:
            r = self.session.get(url, headers=headers,
                                  timeout=timeout or self.timeout,
                                  allow_redirects=True)
            self.request_count += 1
            return r, time.time() - start
        except requests.exceptions.Timeout:
            return None, time.time() - start
        except RequestException:
            return None, time.time() - start

    def options(self, url: str) -> Optional[requests.Response]:
        try:
            r = self.session.options(url, timeout=self.timeout)
            self.request_count += 1
            return r
        except RequestException:
            return None

    # ── WAF detection ─────────────────────────────────────────────
    def is_waf_blocked(self, html: Optional[str]) -> bool:
        if not html:
            return False
        low = html.lower()
        dvwa_ok = any(kw in low for kw in DVWA_SAFE_KEYWORDS)
        blocked = any(ind in low for ind in WAF_INDICATORS)
        return blocked and not dvwa_ok

    # ── Set-Cookie header extraction ───────────────────────────────
    @staticmethod
    def set_cookie_headers(resp: requests.Response) -> List[str]:
        try:
            hdrs = resp.raw.headers.get_all("Set-Cookie")
            if hdrs:
                return list(hdrs)
        except AttributeError:
            pass
        single = resp.headers.get("Set-Cookie")
        return [single] if single else []

    # ── DVWA login ─────────────────────────────────────────────────
    def login_dvwa(self, base_url: str, username: str = "admin",
                   password: str = "password", security: str = "low") -> bool:
        """
        Exactly mirrors test2.py HttpClient.login_dvwa():
        1. GET /login.php  →  extract user_token CSRF
        2. POST credentials
        3. GET /security.php  →  extract token  →  POST security level
        """
        base = base_url.rstrip("/")
        login_url    = f"{base}/login.php"
        security_url = f"{base}/security.php"

        # Step 1 — get login page and extract CSRF token
        resp = self.get(login_url)
        if resp is None:
            self._log("[DVWA] Could not fetch login page")
            return False
        token_m = re.search(r"name=['\"]user_token['\"] value=['\"]([^'\"]+)['\"]", resp.text)
        user_token = token_m.group(1) if token_m else ""

        # Step 2 — POST credentials
        data = {"username": username, "password": password,
                "Login": "Login", "user_token": user_token}
        resp = self.post(login_url, data=data)
        if resp is None:
            self._log("[DVWA] Login POST failed")
            return False
        if "login.php" in resp.url.lower():
            self._log("[DVWA] Login failed — wrong credentials or CSRF token mismatch")
            return False

        # Step 3 — set security level
        resp2 = self.get(security_url)
        if resp2:
            token_m = re.search(r"name=['\"]user_token['\"] value=['\"]([^'\"]+)['\"]", resp2.text)
            sec_token = token_m.group(1) if token_m else ""
            self.post(security_url, data={"security": security,
                                           "seclev_submit": "Submit",
                                           "user_token": sec_token})
        self._log(f"[DVWA] Login successful. Security level = {security}")
        return True

    # ── Form submission helper (used by XSS / CSRF modules) ───────
    def submit_form(self, form, overrides: Dict[str, str]) -> Optional[requests.Response]:
        from core.models import WebForm
        data = {}
        for inp in form.inputs:
            data[inp.name] = overrides.get(inp.name, inp.value)
        if form.method.upper() == "POST":
            return self.post(form.action, data=data)
        return self.get(form.action)


# ─────────────────────────── CRAWLER ───────────────────────────────
class Crawler:
    def __init__(self, base_url: str, cfg, client: HttpClient,
                 on_page: LogFn = None):
        self.base_url = base_url
        self.cfg = cfg
        self.client = client
        self.on_page = on_page
        self.visited: Set[str] = set()
        self.pages_crawled = 0
        # endpoint dict: normalized_url -> {"params": [...], "forms": [...]}
        self._eps: Dict[str, dict] = {}

    def run(self):
        from core.models import Endpoint
        self._crawl(self.base_url, self.cfg.max_depth)
        results = []
        for url, data in self._eps.items():
            ep = Endpoint(url=url, params=data["params"], forms=data["forms"])
            results.append(ep)
        return results

    def _same_scope(self, url: str) -> bool:
        pa, pb = urlparse(url), urlparse(self.base_url)
        if pa.netloc == pb.netloc:
            return True
        if getattr(self.cfg, "follow_subdomains", False) and pa.netloc and pb.netloc:
            def root(n): parts = n.split("@")[-1].split(":")[0].split("."); return ".".join(parts[-2:])
            return root(pa.netloc) == root(pb.netloc)
        return False

    def _norm(self, url: str) -> str:
        from urllib.parse import urlencode, urlunparse
        pr = urlparse(url)
        qs = parse_qs(pr.query, keep_blank_values=True)
        sq = urlencode({k: v[0] if v else "" for k, v in sorted(qs.items())})
        return urlunparse((pr.scheme, pr.netloc, pr.path or "/", pr.params, sq, ""))

    def _crawl(self, url: str, depth: int) -> None:
        if depth < 0 or self.pages_crawled >= self.cfg.max_pages:
            return
        norm = self._norm(url)
        if norm in self.visited:
            return
        path = urlparse(norm).path.lower()
        if path.endswith(SKIP_EXTENSIONS):
            return
        self.visited.add(norm)

        resp = self.client.get(url)
        if resp is None:
            return
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "text/html" not in ctype and "application/xhtml" not in ctype and ctype:
            return

        self.pages_crawled += 1
        if self.on_page:
            self.on_page(url)

        soup = BeautifulSoup(resp.text or "", "html.parser")

        # — collect query params —
        ep = self._eps.setdefault(norm, {"params": [], "forms": []})
        pr = urlparse(norm)
        if pr.query:
            for p in parse_qs(pr.query, keep_blank_values=True):
                if p not in ep["params"]:
                    ep["params"].append(p)

        # — collect forms —
        if getattr(self.cfg, "crawl_forms", True):
            for ftag in soup.find_all("form"):
                form = self._parse_form(ftag, url)
                if form:
                    ep["forms"].append(form)

        # — follow links —
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            nxt = urljoin(url, href)
            if nxt.startswith(("http://", "https://")) and self._same_scope(nxt):
                self._crawl(nxt, depth - 1)

    @staticmethod
    def _parse_form(ftag, page_url: str):
        from core.models import FormField, WebForm
        action = urljoin(page_url, ftag.get("action") or page_url)
        method = (ftag.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"
        inputs = []
        for tag in ftag.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue
            if tag.name == "textarea":
                ftype, value = "textarea", tag.text or ""
            elif tag.name == "select":
                ftype = "select"
                opt = tag.find("option", selected=True) or tag.find("option")
                value = (opt.get("value") or opt.text or "") if opt else ""
            else:
                ftype = (tag.get("type") or "text").lower()
                value = tag.get("value", "")
            inputs.append(FormField(name=name, type=ftype, value=value or ""))
        if not inputs:
            return None
        return WebForm(action=action, method=method, inputs=inputs, source_url=page_url)

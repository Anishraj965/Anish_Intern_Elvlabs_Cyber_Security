"""
core/utils.py
==============
Stateless helpers (URL manipulation, similarity, tokens) +
InjectionPoint abstraction — unified payload delivery for
SQLi, XSS and CSRF modules regardless of whether the target
is a URL query param or an HTML form field.
"""

from __future__ import annotations

import difflib
import random
import re
import string
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse, unquote_plus

import requests


# ─────────────────────────── URL HELPERS ───────────────────────────
def normalize_url(u: str) -> str:
    pr = urlparse(u)
    qs = parse_qs(pr.query, keep_blank_values=True)
    sq = urlencode({k: v[0] if v else "" for k, v in sorted(qs.items())})
    return urlunparse((pr.scheme, pr.netloc, pr.path or "/", pr.params, sq, ""))


def pretty_url(u: str) -> str:
    return unquote_plus(u)


def same_scope(a: str, b: str, follow_subdomains: bool = False) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    if pa.netloc == pb.netloc:
        return True
    if follow_subdomains and pa.netloc and pb.netloc:
        def root(n): parts = n.split("@")[-1].split(":")[0].split("."); return ".".join(parts[-2:])
        return root(pa.netloc) == root(pb.netloc)
    return False


def apply_payload_to_url(url: str, param: str, payload: str,
                          append: bool = True, replace: bool = False) -> str:
    """Return URL with `payload` applied to `param`.
    append=True  → appends to existing value (classic SQLi).
    replace=True → overwrites value entirely (XSS / SSRF style).
    """
    pr = urlparse(url)
    qs = parse_qs(pr.query, keep_blank_values=True)
    cur = (qs.get(param, [""])[0]) if param in qs else ""
    if replace:
        qs[param] = [payload]
    elif append:
        qs[param] = [cur + payload]
    else:
        qs[param] = [payload + cur]
    nq = urlencode({k: v[0] if v else "" for k, v in qs.items()})
    return urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, nq, ""))


def get_param_value(url: str, param: str) -> str:
    qs = parse_qs(urlparse(url).query, keep_blank_values=True)
    return (qs.get(param, [""])[0] or "").strip()


def is_numeric_like(value: str) -> bool:
    return re.fullmatch(r"-?\d+(\.\d+)?", value or "") is not None


def truncate(text: str, length: int = 600) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[:length] + " … [truncated]" if len(text) > length else text


# ─────────────────────────── MISC HELPERS ──────────────────────────
def random_token(n: int = 8, prefix: str = "ZZ", suffix: str = "ZZ") -> str:
    body = "".join(random.choices(string.ascii_uppercase + string.digits, k=n))
    return f"{prefix}{body}{suffix}"


def rand_token(n: int = 8) -> str:
    """test2.py style token: X<random>X"""
    return "X" + "".join(random.choices(string.ascii_uppercase + string.digits, k=n)) + "X"


def similarity_ratio(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


# ─────────────────────────── FORM HELPERS ──────────────────────────
FORM_FIELD_DEFAULTS: Dict[str, str] = {
    "email": "tester@example.com", "number": "1", "range": "1",
    "tel": "1234567890", "password": "Test@1234",
    "url": "https://example.com", "date": "2024-01-01",
    "color": "#ff0000", "search": "test", "text": "test",
    "textarea": "test value", "hidden": "", "checkbox": "on",
    "radio": "on", "select": "",
}
NON_INJECTABLE_TYPES = {"submit", "button", "image", "reset", "file", "hidden", "checkbox", "radio"}


def default_field_value(f) -> str:
    return f.value if f.value else FORM_FIELD_DEFAULTS.get(f.type, "test")


def baseline_form_data(form) -> Dict[str, str]:
    return {f.name: default_field_value(f) for f in form.inputs}


def injectable_fields(form) -> list:
    return [f for f in form.inputs if f.name and f.type.lower() not in NON_INJECTABLE_TYPES]


# ─────────────────────────── INJECTION POINT ───────────────────────
@dataclass
class InjectionPoint:
    """One injectable (parameter, request-shape) pair ready to receive payloads."""
    param: str
    method: str
    url: str
    original_value: str
    baseline_resp: Optional[requests.Response]
    _send: Callable
    _timed_send: Callable
    source: str = "url"
    form: object = None

    @property
    def baseline_text(self) -> str:
        return self.baseline_resp.text if self.baseline_resp else ""

    @property
    def baseline_status(self) -> int:
        return self.baseline_resp.status_code if self.baseline_resp else 0

    def send(self, payload: str, replace: bool = False) -> Tuple[str, Optional[requests.Response]]:
        return self._send(payload, replace)

    def timed_send(self, payload: str) -> Tuple[Optional[requests.Response], float]:
        return self._timed_send(payload)


def for_url_param(client, url: str, param: str) -> InjectionPoint:
    baseline = client.get(url)

    def send(payload: str, replace: bool = False):
        target = apply_payload_to_url(url, param, payload, append=not replace, replace=replace)
        return target, client.get(target)

    def timed_send(payload: str):
        target = apply_payload_to_url(url, param, payload, append=True)
        return client.timed_get(target)

    return InjectionPoint(
        param=param, method="GET", url=url,
        original_value=get_param_value(url, param),
        baseline_resp=baseline, _send=send, _timed_send=timed_send, source="url",
    )


def for_form_field(client, form, target_field, base_data: Dict[str, str],
                   baseline_resp: Optional[requests.Response]) -> InjectionPoint:
    def send(payload: str, replace: bool = False):
        data = dict(base_data)
        base_val = base_data.get(target_field.name, "")
        data[target_field.name] = payload if replace else (base_val + payload)
        resp = client.submit_form(form, data)
        display = f"{form.action}[{form.method}] {target_field.name}={data[target_field.name]!r}"
        return display, resp

    def timed_send(payload: str):
        data = dict(base_data)
        data[target_field.name] = base_data.get(target_field.name, "") + payload
        start = time.time()
        resp = client.submit_form(form, data)
        return resp, time.time() - start

    return InjectionPoint(
        param=target_field.name, method=form.method, url=form.action,
        original_value=base_data.get(target_field.name, ""),
        baseline_resp=baseline_resp, _send=send, _timed_send=timed_send,
        source="form", form=form,
    )

"""config.py — Global paths and scan configuration."""
from __future__ import annotations
import logging
import os
from dataclasses import dataclass, field, fields
from typing import Dict, List, Optional

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DATA_DIR     = os.path.join(BASE_DIR, "data")
REPORTS_DIR  = os.path.join(BASE_DIR, "reports")
SCANS_DIR    = os.path.join(BASE_DIR, "scans")      # subprocess output landing zone
SCANNERS_DIR = os.path.join(BASE_DIR, "scanners")   # standalone scanner scripts
DB_PATH      = os.path.join(DATA_DIR, "scanner.db")

for _d in (DATA_DIR, REPORTS_DIR, SCANS_DIR):
    os.makedirs(_d, exist_ok=True)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

# ── Per-field numeric bounds enforced in from_form() ───────────────────────
# Format: field_name -> (min_value, max_value)
_FIELD_BOUNDS: Dict[str, tuple] = {
    "max_depth": (1, 10),
    "max_pages": (1, 500),
    "timeout":   (1, 300),    # HTTP request timeout in seconds
    "delay":     (0.0, 30.0), # inter-request delay in seconds
    "sqli_thread_char_extract": (1, 20),
}

# Valid values for the DVWA security level dropdown
_VALID_DVWA_SECURITY = {"low", "medium", "high"}


@dataclass
class ScanConfig:
    target: str = ""
    # Crawler
    max_depth: int  = 2
    max_pages: int  = 60
    # HTTP
    timeout: int   = 10
    delay: float   = 0.3
    # DVWA login
    login_dvwa: bool       = False
    dvwa_username: str     = "admin"
    dvwa_password: str     = "password"
    dvwa_security: str     = "low"
    # Module toggles
    enable_sqli:  bool = False
    enable_xss:   bool = False
    enable_csrf:  bool = False
    enable_owasp: bool = False
    # SQLi extras
    sqli_thread_char_extract: Optional[int] = None
    # CSRF extras
    csrf_test_active: bool = False
    csrf_aggressive:  bool = False
    # XSS extras
    xss_scan_types: str = "reflected,stored,dom"
    # OWASP sub-checks (True = enabled)
    enable_owasp_a01: bool = True
    enable_owasp_a02: bool = True
    enable_owasp_a03_extra: bool = True
    enable_owasp_a04: bool = True
    enable_owasp_a05: bool = True
    enable_owasp_a06: bool = True
    enable_owasp_a07: bool = True
    enable_owasp_a08: bool = True
    enable_owasp_a09: bool = True
    enable_owasp_a10: bool = True

    @classmethod
    def from_form(cls, form: Dict) -> "ScanConfig":
        valid = {f.name: f for f in fields(cls)}
        kwargs: Dict = {}
        for key, fld in valid.items():
            type_str = str(fld.type)
            if "bool" in type_str:
                kwargs[key] = key in form and str(form.get(key, "")).lower() in ("1", "true", "on", "yes")
            elif key in form:
                raw = form.get(key)
                try:
                    if "float" in type_str:
                        val = float(raw)
                        lo, hi = _FIELD_BOUNDS.get(key, (None, None))
                        if lo is not None:
                            val = max(float(lo), min(float(hi), val))
                        kwargs[key] = val
                    elif "int" in type_str:
                        if raw not in (None, ""):
                            val = int(raw)
                            lo, hi = _FIELD_BOUNDS.get(key, (None, None))
                            if lo is not None:
                                val = max(int(lo), min(int(hi), val))
                            kwargs[key] = val
                    elif type_str == "str":
                        kwargs[key] = raw
                except (ValueError, TypeError) as exc:
                    logging.warning(
                        "ScanConfig.from_form: ignoring unparseable field %s=%r — %s",
                        key, raw, exc,
                    )

        # Validate dvwa_security is a known value
        if "dvwa_security" in kwargs:
            if kwargs["dvwa_security"] not in _VALID_DVWA_SECURITY:
                logging.warning(
                    "ScanConfig.from_form: invalid dvwa_security=%r, defaulting to 'low'",
                    kwargs["dvwa_security"],
                )
                kwargs["dvwa_security"] = "low"

        return cls(**kwargs)

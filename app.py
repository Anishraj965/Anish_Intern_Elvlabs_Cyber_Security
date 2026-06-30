"""
app.py — Flask web app.
Runs each of the 4 standalone scanners as independent subprocesses in parallel threads.
"""
from __future__ import annotations

import json, os, re, secrets, shutil, subprocess, sys, threading, traceback, uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, url_for

from config import DB_PATH, REPORTS_DIR, SCANS_DIR, SCANNERS_DIR, ScanConfig
from core import database as db
from core.models import Finding, Severity, ScanProgress
from core.reports import generate_all, build_context
from core.owasp_mapping import OWASP_TOP_10_2021

db.init_db()

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")

# ── Secret key ─────────────────────────────────────────────────────────────
# Use a persistent key from the environment. If absent, generate a random one
# so the app still starts, but warn clearly that sessions won't survive restarts.
_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    _secret_key = secrets.token_hex(32)
    import warnings
    warnings.warn(
        "SECRET_KEY environment variable is not set. A random key has been generated — "
        "all sessions will be invalidated on restart. "
        "Set SECRET_KEY=<random-hex-string> in your environment for persistent sessions.",
        stacklevel=1,
    )
app.secret_key = _secret_key

# ── In-memory progress registry ────────────────────────────────────────────
REGISTRY: Dict[str, ScanProgress] = {}
_LOCK = threading.Lock()

def _reg(p: ScanProgress) -> None:
    with _LOCK: REGISTRY[p.scan_id] = p

def get_prog(sid: str) -> Optional[ScanProgress]:
    with _LOCK: return REGISTRY.get(sid)

# ── Resource limits ─────────────────────────────────────────────────────────
# Hard timeout for each scanner subprocess (seconds). The watchdog kills the
# process if it runs longer than this.
SCANNER_TIMEOUT: int = 30 * 60        # 30 minutes per module

# ev.wait() ceiling — slightly longer than SCANNER_TIMEOUT so the watchdog
# always fires before the orchestrator gives up.
MODULE_WAIT_TIMEOUT: int = SCANNER_TIMEOUT + 5 * 60

# Maximum number of scan orchestrations that may run concurrently. Requests
# beyond this limit are rejected with a 429-style error.
MAX_CONCURRENT_SCANS: int = 3
_SCAN_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)

# ── Scanner definitions ────────────────────────────────────────────────────
SCANNER_DEFS: Dict[str, Dict] = {
    "sqli": {
        "file":      "evil_sqli.py",
        "label":     "SQL Injection",
        "icon":      "💉",
        "json_file": "scan_result.json",
        "has_mode":  True,
        "has_threads": False,
    },
    "xss": {
        "file":      "evil_xss.py",
        "label":     "Cross-Site Scripting",
        "icon":      "🔥",
        "json_file": "scan_result.json",
        "has_mode":  True,
        "has_threads": True,
    },
    "csrf": {
        "file":      "evil_csrf.py",
        "label":     "CSRF",
        "icon":      "🎯",
        "json_file": "csrf_scan_result.json",
        "has_mode":  True,
        "has_threads": True,
    },
    "owasp": {
        "file":      "evil_owasp.py",
        "label":     "OWASP Top 10",
        "icon":      "🛡",
        "json_file": "owasp_scan_result.json",
        "has_mode":  False,
        "has_threads": True,
    },
}

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHFJAB]")

def _strip(s: str) -> str:
    return ANSI_RE.sub("", s)

# ── OWASP ID normalisation ─────────────────────────────────────────────────
_OWASP_SHORT = {f"A{i:02d}": f"A{i:02d}:2021" for i in range(1, 11)}

def _norm_owasp(raw: str) -> str:
    raw = (raw or "A05:2021").strip()
    if ":" in raw:
        return raw if raw in OWASP_TOP_10_2021 else "A05:2021"
    return _OWASP_SHORT.get(raw, "A05:2021")


# ── Domain-based report folder helper ─────────────────────────────────────
def _domain_slug(target: str) -> str:
    """Convert URL to a filesystem-safe domain slug for folder naming."""
    url = target.split("//")[-1]
    domain = url.split("/")[0].split(":")[0]
    slug = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)
    return slug[:40] if slug else "unknown"

def _report_dir(scan_id: str) -> str:
    """Get domain/scan_id-based report directory."""
    scan = db.get_scan(scan_id)
    if scan and scan.get("target"):
        domain = _domain_slug(scan["target"])
        return os.path.join(REPORTS_DIR, domain, scan_id[:8])
    return os.path.join(REPORTS_DIR, scan_id)

def _rpath(sid: str, fmt: str) -> str:
    return os.path.join(_report_dir(sid), f"report.{fmt}")

def _reports_ready(sid: str) -> Dict[str, bool]:
    return {f: os.path.exists(_rpath(sid, f)) for f in ("html", "pdf", "json", "txt")}


# ── CLI arg builder ────────────────────────────────────────────────────────
def _build_args(key: str, cfg: ScanConfig, out_dir: str) -> List[str]:
    """Return CLI arg list for one scanner subprocess."""
    args = [
        "-u", cfg.target,
        "--output", out_dir,
        "--delay",   str(cfg.delay),
        "--timeout", str(cfg.timeout),
    ]
    args += ["--depth", str(cfg.max_depth)]

    sdef = SCANNER_DEFS[key]
    if sdef["has_mode"]:
        args += ["--mode", "scan"]
    if sdef["has_threads"]:
        args += ["--threads", "5"]

    if cfg.login_dvwa:
        args.append("--dvwa-login")

    if key == "sqli" and cfg.sqli_thread_char_extract:
        args += ["--threadCharExtract", str(cfg.sqli_thread_char_extract)]

    if key == "csrf":
        if cfg.csrf_test_active:
            args.append("--test")
        if cfg.csrf_aggressive:
            args.append("--aggressive")

    if key == "xss":
        types = cfg.xss_scan_types or "reflected,stored,dom"
        args += ["--types", types]

    if key == "owasp":
        owasp_map = {
            "enable_owasp_a01":      "--disable-a01",
            "enable_owasp_a02":      "--disable-a02",
            "enable_owasp_a03_extra":"--disable-a03-extra",
            "enable_owasp_a04":      "--disable-a04",
            "enable_owasp_a05":      "--disable-a05",
            "enable_owasp_a06":      "--disable-a06",
            "enable_owasp_a07":      "--disable-a07",
            "enable_owasp_a08":      "--disable-a08",
            "enable_owasp_a09":      "--disable-a09",
            "enable_owasp_a10":      "--disable-a10",
        }
        for attr, flag in owasp_map.items():
            if not getattr(cfg, attr, True):
                args.append(flag)

    return args


# ── Subprocess runner ──────────────────────────────────────────────────────
def _run_subprocess(key: str, cfg: ScanConfig, scan_id: str,
                    prog: ScanProgress, out_dir: str) -> int:
    sfile = os.path.join(SCANNERS_DIR, SCANNER_DEFS[key]["file"])
    cli   = _build_args(key, cfg, out_dir)
    cmd   = [sys.executable, sfile] + cli

    prog.log(key, f"[*] Starting {SCANNER_DEFS[key]['label']} scanner")
    prog.log(key, f"[*] Target : {cfg.target}")
    prog.module_status[key] = "running"

    proc: Optional[subprocess.Popen] = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, bufsize=1,
            encoding="utf-8", errors="replace",
        )

        # Watchdog thread: kill the subprocess if it exceeds SCANNER_TIMEOUT.
        # When proc.kill() is called the stdout iterator below terminates
        # naturally, so no extra joining is needed.
        def _watchdog() -> None:
            prog.log(key, f"[!] Scanner exceeded timeout ({SCANNER_TIMEOUT}s). Terminating process.")
            prog.module_status[key] = "error"
            try:
                proc.kill()
            except OSError:
                pass

        timer = threading.Timer(SCANNER_TIMEOUT, _watchdog)
        timer.daemon = True
        timer.start()
        try:
            for raw in proc.stdout:
                clean = _strip(raw.rstrip())
                if clean:
                    prog.log(key, clean)
            proc.wait()
        finally:
            timer.cancel()  # disarm watchdog if scanner finished normally

        rc = proc.returncode
    except Exception as exc:
        prog.log(key, f"[-] Subprocess error: {exc}")
        prog.log(key, traceback.format_exc())
        prog.module_status[key] = "error"
        if proc is not None:
            try:
                proc.kill()
            except OSError:
                pass
        return -1

    if rc == 0:
        prog.module_status[key] = "done"
        prog.log(key, f"[+] {SCANNER_DEFS[key]['label']} scanner finished.")
    else:
        prog.module_status[key] = "error"
        prog.log(key, f"[-] Scanner exited with code {rc}")
    return rc


# ── Severity helper ────────────────────────────────────────────────────────
def _sev(raw) -> Severity:
    if isinstance(raw, int):
        try:    return Severity(raw)
        except ValueError: return Severity.INFO
    return Severity.from_str(str(raw))


# ── Finding severity: auto-escalate confirmed SQL injections ───────────────
def _sqli_severity(f: dict) -> Severity:
    """
    SQL Injection severity rules (CVSS-aligned):
    - Confirmed data extraction (version, current_user, columns) → CRITICAL
    - Error-Based or Union-Based technique confirmed             → CRITICAL
    - Time-Based / Boolean Blind confirmed                       → HIGH
    - Otherwise fall back to scanner-reported severity
    """
    technique = (f.get("technique") or "").lower()
    has_extraction = any([f.get("version"), f.get("current_user"),
                          f.get("columns"), f.get("databases"), f.get("tables")])
    if has_extraction:
        return Severity.CRITICAL
    if "error" in technique or "union" in technique:
        return Severity.CRITICAL
    if "time" in technique or "boolean" in technique or "blind" in technique:
        return Severity.HIGH
    return _sev(f.get("severity", "High"))


# ── Finding progress updater ───────────────────────────────────────────────
def _update_prog(prog: ScanProgress, key: str, sev: Severity) -> None:
    sl = sev.label
    prog.findings_count += 1
    prog.severity_counts[sl] = prog.severity_counts.get(sl, 0) + 1
    prog.module_findings[key]  = prog.module_findings.get(key, 0) + 1
    prog.module_severity[key][sl] = prog.module_severity[key].get(sl, 0) + 1


# ── Finding importers ──────────────────────────────────────────────────────
def _import_sqli(scan_id: str, json_path: str, prog: ScanProgress) -> int:
    if not os.path.exists(json_path): return 0
    try:
        with open(json_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception: return 0
    count = 0
    for f in data.get("findings", []):
        sev  = _sqli_severity(f)          # ← auto-escalate to Critical when confirmed
        dbms = f.get("dbms") or ""
        finding = Finding(
            scan_id=scan_id,
            category="SQL Injection",
            subtype=f.get("technique", "Error-Based"),
            owasp_id="A03:2021",
            owasp_name="Injection",
            severity=sev,
            confidence=float(f.get("confidence", 0.90)),
            url=f.get("url", ""),
            parameter=f.get("param"),
            method="GET",
            payload=f.get("payload"),
            evidence=(
                f"DBMS: {dbms}. "
                f"DB Version: {f.get('version','')}. "
                f"Current User: {f.get('current_user','')}. "
                f"Columns: {f.get('columns','')}"
            ).strip(". "),
            description=(
                f"SQL Injection ({f.get('technique','')}) confirmed in parameter "
                f"'{f.get('param','')}' on {f.get('url','')}"
                + (f". DBMS: {dbms}" if dbms else "") + "."
            ),
            remediation=(
                "Use parameterized queries / prepared statements. "
                "Never concatenate user input into SQL strings. "
                "Apply strict input validation and least-privilege DB accounts."
            ),
            cwe="CWE-89",
            extra={k: f.get(k) for k in ("version","current_user","columns","dbms") if f.get(k)},
        )
        db.save_finding(finding)
        _update_prog(prog, "sqli", sev)
        prog.owasp_radar["A03:2021"] = prog.owasp_radar.get("A03:2021", 0) + 1
        count += 1
    return count


def _import_xss(scan_id: str, json_path: str, prog: ScanProgress) -> int:
    if not os.path.exists(json_path): return 0
    try:
        with open(json_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception: return 0
    count = 0
    for f in data.get("findings", []):
        technique = f.get("technique", "Reflected")
        sev = _sev(f.get("severity", "Medium"))
        finding = Finding(
            scan_id=scan_id,
            category="XSS",
            subtype=technique,
            owasp_id="A03:2021",
            owasp_name="Injection",
            severity=sev,
            confidence=float(f.get("confidence", 0.90)),
            url=f.get("url", ""),
            parameter=f.get("param"),
            method="GET",
            payload=f.get("payload"),
            evidence=f"Payload reflected / executed: {f.get('payload','')}",
            description=(
                f"{technique} XSS in parameter '{f.get('param','')}' "
                f"on {f.get('url','')}."
            ),
            remediation=(
                "Sanitize and encode all user-supplied output. "
                "Implement Content-Security-Policy headers. "
                "Use modern frameworks that auto-escape output."
            ),
            cwe="CWE-79",
        )
        db.save_finding(finding)
        _update_prog(prog, "xss", sev)
        prog.owasp_radar["A03:2021"] = prog.owasp_radar.get("A03:2021", 0) + 1
        count += 1
    return count


def _import_csrf(scan_id: str, json_path: str, prog: ScanProgress) -> int:
    if not os.path.exists(json_path): return 0
    try:
        with open(json_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception: return 0
    count = 0
    for f in data.get("findings", []):
        sev = _sev(f.get("severity", "High"))
        finding = Finding(
            scan_id=scan_id,
            category="CSRF",
            subtype=f.get("csrf_type", "POST"),
            owasp_id="A01:2021",
            owasp_name="Broken Access Control",
            severity=sev,
            confidence=float(f.get("confidence", 0.85)),
            url=f.get("url", ""),
            parameter=None,
            method=f.get("method", "POST"),
            payload=None,
            evidence=(
                f"Form action: {f.get('form_action','')} | "
                f"Token present: {f.get('token_present', False)} | "
                f"Token fields: {', '.join(f.get('token_fields',[]) or [])} | "
                f"Test result: {f.get('test_result','N/A')}"
            ),
            description=(
                f"CSRF vulnerability ({f.get('csrf_type','Unknown')} type) on "
                f"{f.get('form_action', f.get('url',''))}. "
                f"CSRF token {'present but not validated' if f.get('token_present') else 'missing'}."
            ),
            remediation=(
                "Implement synchronizer anti-CSRF tokens on all state-changing forms. "
                "Set SameSite=Strict on session cookies. "
                "Validate Origin and Referer request headers."
            ),
            cwe="CWE-352",
        )
        db.save_finding(finding)
        _update_prog(prog, "csrf", sev)
        prog.owasp_radar["A01:2021"] = prog.owasp_radar.get("A01:2021", 0) + 1
        count += 1
    return count


def _import_owasp(scan_id: str, json_path: str, prog: ScanProgress) -> int:
    if not os.path.exists(json_path): return 0
    try:
        with open(json_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception: return 0
    count = 0
    for f in data.get("findings", []):
        sev = _sev(f.get("severity", "Info"))
        owasp_id = _norm_owasp(f.get("owasp_id", "A05:2021"))
        owasp_info = OWASP_TOP_10_2021.get(owasp_id, {})
        # Auto-escalate confirmed SSTI to Critical
        subtype = (f.get("subtype") or "").lower()
        if "ssti" in subtype or "template injection" in subtype:
            evidence = (f.get("evidence") or "").lower()
            if "49" in evidence or "evaluated" in evidence or "confirmed" in evidence:
                sev = Severity.CRITICAL
        finding = Finding(
            scan_id=scan_id,
            category=f.get("category", "OWASP"),
            subtype=f.get("subtype", "Unknown"),
            owasp_id=owasp_id,
            owasp_name=f.get("owasp_name") or owasp_info.get("name", "Unknown"),
            severity=sev,
            confidence=float(f.get("confidence", 0.75)),
            url=f.get("url", ""),
            parameter=f.get("parameter"),
            method=f.get("method", "GET"),
            payload=f.get("payload"),
            evidence=f.get("evidence", ""),
            description=f.get("description", ""),
            remediation=f.get("remediation", ""),
            cwe=f.get("cwe"),
            extra=f.get("extra", {}),
        )
        db.save_finding(finding)
        _update_prog(prog, "owasp", sev)
        prog.owasp_radar[owasp_id] = prog.owasp_radar.get(owasp_id, 0) + 1
        count += 1
    return count


IMPORTERS = {
    "sqli":  (_import_sqli,  "scan_result.json"),
    "xss":   (_import_xss,   "scan_result.json"),
    "csrf":  (_import_csrf,  "csrf_scan_result.json"),
    "owasp": (_import_owasp, "owasp_scan_result.json"),
}


# ── Per-module thread wrapper ──────────────────────────────────────────────
def _module_thread(key: str, cfg: ScanConfig, scan_id: str,
                   prog: ScanProgress, done_event: threading.Event) -> None:
    out_dir = os.path.join(SCANS_DIR, scan_id, key)
    os.makedirs(out_dir, exist_ok=True)
    try:
        _run_subprocess(key, cfg, scan_id, prog, out_dir)
        importer_fn, json_name = IMPORTERS[key]
        json_path = os.path.join(out_dir, json_name)
        n = importer_fn(scan_id, json_path, prog)
        prog.log(key, f"[+] Imported {n} finding(s) into report database.")
    except Exception:
        prog.log(key, f"[-] Module error:\n{traceback.format_exc()}")
        prog.module_status[key] = "error"
    finally:
        done_event.set()


# ── Main scan orchestrator ─────────────────────────────────────────────────
def _run_scan(scan_id: str, cfg: ScanConfig, prog: ScanProgress) -> None:
    enabled = {k for k in ("sqli", "xss", "csrf", "owasp")
               if getattr(cfg, f"enable_{k}", False)}

    if not enabled:
        prog.log("global", "[-] No modules enabled. Enable at least one scanner.")
        prog.status = "failed"
        db.update_scan(scan_id, status="failed",
                       finished_at=datetime.now(timezone.utc).isoformat(),
                       error="No modules selected")
        return

    for k in ("sqli", "xss", "csrf", "owasp"):
        if k not in enabled:
            prog.module_status[k] = "skipped"

    prog.status = "scanning"
    db.update_scan(scan_id, status="scanning")
    prog.log("global", f"[*] Scan started: {cfg.target}")
    prog.log("global", f"[*] Active modules: {', '.join(enabled)}")

    events: Dict[str, threading.Event] = {}
    for key in enabled:
        ev = threading.Event()
        events[key] = ev
        t = threading.Thread(
            target=_module_thread,
            args=(key, cfg, scan_id, prog, ev),
            daemon=True,
        )
        t.start()
        prog.log("global", f"[*] Launched {SCANNER_DEFS[key]['label']} ...")

    for key, ev in events.items():
        finished = ev.wait(timeout=MODULE_WAIT_TIMEOUT)
        if finished:
            prog.log("global", f"[+] {SCANNER_DEFS[key]['label']} complete.")
        else:
            prog.log("global",
                     f"[!] {SCANNER_DEFS[key]['label']} did not finish within "
                     f"{MODULE_WAIT_TIMEOUT}s — results may be partial.")

    prog.status = "reporting"
    prog.current_module = "Reports"
    db.update_scan(scan_id, status="reporting")
    prog.log("global", "[*] Generating reports ...")
    try:
        paths = generate_all(scan_id)
        for fmt, p in paths.items():
            prog.log("global", f"[+] {fmt.upper()} report: {p}")
    except Exception:
        prog.log("global", f"[-] Report error:\n{traceback.format_exc()}")

    finished = datetime.now(timezone.utc).isoformat()
    db.update_scan(scan_id, status="completed", finished_at=finished)
    prog.status = "completed"
    prog.finished_at = finished
    prog.current_module = ""
    prog.log("global", f"[+] Scan complete — {prog.findings_count} finding(s).")


def start_scan(cfg: ScanConfig) -> str:
    # Non-blocking acquire; raises immediately if all slots are taken.
    if not _SCAN_SEMAPHORE.acquire(blocking=False):
        raise RuntimeError(
            f"Maximum concurrent scans ({MAX_CONCURRENT_SCANS}) are already running. "
            "Please wait for a scan to finish before starting a new one."
        )
    sid  = uuid.uuid4().hex[:16]
    prog = ScanProgress(scan_id=sid, target=cfg.target)
    _reg(prog)
    db.create_scan(sid, cfg.target, vars(cfg))

    def _run_and_release() -> None:
        try:
            _run_scan(sid, cfg, prog)
        finally:
            _SCAN_SEMAPHORE.release()   # always free the slot, even on crash

    threading.Thread(target=_run_and_release, daemon=True).start()
    return sid


# ── Chart data helper ──────────────────────────────────────────────────────
def _compute_chart_data(findings: list) -> dict:
    """Compute chart-ready data from findings list for the findings page."""
    # Category × Severity matrix for stacked bar
    cat_by_sev: Dict[str, Dict[str, int]] = {}
    confidence_buckets = [0] * 10  # 0-10%, 10-20%, ..., 90-100%
    tech_counts: Dict[str, int] = {}
    url_severity: Dict[str, str] = {}  # url → highest severity

    sev_order = ["Critical", "High", "Medium", "Low", "Info"]

    for f in findings:
        cat = f.get("category", "Unknown")
        sev = f.get("severity", "Info")
        if cat not in cat_by_sev:
            cat_by_sev[cat] = {s: 0 for s in sev_order}
        cat_by_sev[cat][sev] = cat_by_sev[cat].get(sev, 0) + 1

        # Confidence histogram
        conf = float(f.get("confidence") or 0)
        bucket = min(int(conf * 10), 9)
        confidence_buckets[bucket] += 1

        # Technique/subtype counts
        sub = f.get("subtype", "Unknown")
        tech_counts[sub] = tech_counts.get(sub, 0) + 1

        # URL risk
        url = f.get("url", "")
        if url:
            cur = url_severity.get(url, "Info")
            if sev_order.index(sev) > sev_order.index(cur):
                url_severity[url] = sev

    # Top 10 URLs by severity
    top_urls = sorted(url_severity.items(),
                      key=lambda x: sev_order.index(x[1]), reverse=True)[:10]

    return {
        "cat_by_sev": cat_by_sev,
        "confidence_buckets": confidence_buckets,
        "tech_counts": tech_counts,
        "top_urls": [{"url": u[:55], "severity": s} for u, s in top_urls],
    }


# ── Routes ─────────────────────────────────────────────────────────────────
@app.route("/")
def dashboard():
    scans = db.list_scans(50)
    for s in scans:
        p = get_prog(s["scan_id"])
        if p and s["status"] not in ("completed", "failed", "stopped"):
            s["live_progress"] = p.to_dict()
    # Timeline data: findings count per scan date (last 20 completed scans)
    timeline = []
    for s in reversed(scans[-20:]):
        if s.get("status") == "completed":
            date_str = (s.get("started_at") or "")[:10]
            if date_str:
                sv = s.get("severity_counts") or {}
                timeline.append({
                    "date": date_str,
                    "total": s.get("findings_count", 0),
                    "critical": sv.get("Critical", 0),
                    "high": sv.get("High", 0),
                })
    return render_template("index.html", page="dashboard", scans=scans, timeline=timeline)


@app.route("/scan/new")
def new_scan():
    return render_template("index.html", page="new_scan", defaults=ScanConfig())


@app.route("/scan/start", methods=["POST"])
def scan_start():
    target = (request.form.get("target") or "").strip()
    if not target:
        return redirect(url_for("new_scan"))
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    # ── Target URL validation ───────────────────────────────────────────────
    if len(target) > 2048:
        return render_template("index.html", page="new_scan", defaults=ScanConfig(),
                               error="Target URL is too long (max 2,048 characters)."), 400
    if any(c in target for c in ("\n", "\r", "\x00")):
        return render_template("index.html", page="new_scan", defaults=ScanConfig(),
                               error="Target URL contains invalid characters."), 400

    cfg = ScanConfig.from_form(dict(request.form))
    cfg.target = target

    try:
        sid = start_scan(cfg)
    except RuntimeError as exc:
        return render_template("index.html", page="new_scan", defaults=ScanConfig(),
                               error=str(exc)), 429

    return redirect(url_for("scan_view", scan_id=sid))


@app.route("/scan/<scan_id>")
def scan_view(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan: abort(404)
    prog = get_prog(scan_id)
    return render_template("index.html", page="scan_progress",
                           scan=scan, prog=prog,
                           reports=_reports_ready(scan_id),
                           owasp_ids=list(OWASP_TOP_10_2021.keys()),
                           owasp_info=OWASP_TOP_10_2021,
                           scanner_defs=SCANNER_DEFS)


@app.route("/scan/<scan_id>/progress")
def scan_progress_api(scan_id: str):
    prog = get_prog(scan_id)
    scan = db.get_scan(scan_id)
    if not prog and not scan:
        return jsonify({"error": "not found"}), 404
    status  = prog.status if prog else scan.get("status", "unknown")
    sev     = db.severity_counts(scan_id) if scan else {}
    return jsonify({
        "status":           status,
        "current_module":   prog.current_module if prog else "",
        "pages_crawled":    prog.pages_crawled  if prog else scan.get("pages_crawled", 0),
        "findings_count":   prog.findings_count if prog else sum(sev.values()),
        "severity_counts":  prog.severity_counts if prog else sev,
        "module_logs":      {k: v[-300:] for k, v in prog.module_logs.items()} if prog else {},
        "module_status":    prog.module_status  if prog else {},
        "module_findings":  prog.module_findings if prog else {},
        "module_severity":  prog.module_severity if prog else {},
        "owasp_radar":      prog.owasp_radar     if prog else {},
        "global_log":       prog.global_log[-150:] if prog else [],
        "reports":          _reports_ready(scan_id),
        "done":             status in ("completed", "failed", "stopped"),
    })


@app.route("/scan/<scan_id>/stop", methods=["POST"])
def scan_stop(scan_id: str):
    prog = get_prog(scan_id)
    if prog: prog.status = "stopped"
    db.update_scan(scan_id, status="stopped",
                   finished_at=datetime.now(timezone.utc).isoformat())
    return redirect(url_for("scan_view", scan_id=scan_id))


@app.route("/scan/<scan_id>/findings")
def scan_findings(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan: abort(404)
    sev_f = request.args.get("severity")
    cat_f = request.args.get("category")
    owa_f = request.args.get("owasp")
    findings = db.get_findings(scan_id, category=cat_f, severity=sev_f, owasp_id=owa_f)
    all_findings = db.get_findings(scan_id)  # unfiltered for chart data
    chart_data = _compute_chart_data(all_findings)
    return render_template("index.html", page="findings",
                           scan=scan, findings=findings,
                           sev_counts=db.severity_counts(scan_id),
                           cat_counts=db.category_counts(scan_id),
                           owasp_counts=db.owasp_counts(scan_id),
                           chart_data=chart_data,
                           severity_filter=sev_f, category_filter=cat_f, owasp_filter=owa_f,
                           severity_order=["Critical","High","Medium","Low","Info"],
                           sev_colors={"Critical":"#ff003c","High":"#ff6600","Medium":"#ffe600",
                                       "Low":"#00e5ff","Info":"#5a6e82"},
                           owasp_ids=list(OWASP_TOP_10_2021.keys()),
                           owasp_info=OWASP_TOP_10_2021,
                           reports=_reports_ready(scan_id))


@app.route("/scan/<scan_id>/finding/<int:fid>")
def finding_detail(scan_id: str, fid: int):
    scan    = db.get_scan(scan_id)
    finding = db.get_finding(fid)
    if not scan or not finding or finding["scan_id"] != scan_id: abort(404)
    return render_template("index.html", page="finding_detail",
                           scan=scan, finding=finding,
                           owasp_info=OWASP_TOP_10_2021)


@app.route("/scan/<scan_id>/report/<fmt>")
def download_report(scan_id: str, fmt: str):
    if fmt not in ("html", "pdf", "json", "txt"): abort(400)
    path = _rpath(scan_id, fmt)
    if not os.path.exists(path):
        ctx = build_context(scan_id)
        if not ctx: abort(404)
        from core.reports import generate_html, generate_pdf, generate_json, generate_txt
        os.makedirs(os.path.dirname(path), exist_ok=True)
        {"html": generate_html, "pdf": generate_pdf,
         "json": generate_json, "txt":  generate_txt}[fmt](ctx, path)
    if not os.path.exists(path): abort(404)
    mime  = {"html":"text/html","pdf":"application/pdf",
             "json":"application/json","txt":"text/plain"}
    scan  = db.get_scan(scan_id)
    slug  = _domain_slug(scan.get("target","") or scan_id)
    fname = f"vuln_{slug}_{scan_id[:8]}.{fmt}"
    return send_file(path, mimetype=mime[fmt],
                     as_attachment=(fmt != "html"), download_name=fname)


@app.route("/scan/<scan_id>/delete", methods=["POST"])
def delete_scan(scan_id: str):
    rdir = _report_dir(scan_id)
    db.delete_scan(scan_id)
    for d in (rdir, os.path.join(SCANS_DIR, scan_id)):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
    REGISTRY.pop(scan_id, None)
    return redirect(url_for("dashboard"))


@app.route("/health")
def health():
    return jsonify({"status": "ok", "db": os.path.exists(DB_PATH)})


if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  ☠  EVIL WEB REAPER — Web Application Vulnerability Scanner   ║
║  ⚠  AUTHORISED TESTING AND EDUCATIONAL USE ONLY              ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)

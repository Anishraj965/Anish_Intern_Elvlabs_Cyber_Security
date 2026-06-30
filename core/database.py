"""
core/database.py
==================
SQLite persistence layer. Every finding from every module (SQLi, XSS, CSRF,
OWASP A01-A10) is written through :func:`save_finding`, so the dashboard,
history view and all four report formats read from one consistent source.

A fresh connection is opened per call (sqlite3 connections are cheap) so the
module is safe to use from the Flask request thread and the background scan
thread at the same time.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Dict, List, Optional

from config import DB_PATH
from core.models import Finding, Severity


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    pages_crawled INTEGER DEFAULT 0,
    endpoints_tested INTEGER DEFAULT 0,
    requests_sent INTEGER DEFAULT 0,
    config_json TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    category TEXT NOT NULL,
    subtype TEXT NOT NULL,
    owasp_id TEXT NOT NULL,
    owasp_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    url TEXT NOT NULL,
    parameter TEXT,
    method TEXT NOT NULL DEFAULT 'GET',
    payload TEXT,
    evidence TEXT,
    description TEXT,
    remediation TEXT,
    cwe TEXT,
    extra_json TEXT,
    found_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings (category);
CREATE INDEX IF NOT EXISTS idx_findings_owasp ON findings (owasp_id);
"""

_SEVERITY_ORDER_SQL = (
    "CASE severity "
    "WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 "
    "WHEN 'Low' THEN 3 ELSE 4 END"
)


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------
def create_scan(scan_id: str, target: str, config_dict: Dict) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scans (scan_id, target, status, started_at, config_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (scan_id, target, "queued", datetime.now(timezone.utc).isoformat(), json.dumps(config_dict)),
        )


def update_scan(scan_id: str, **fields) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [scan_id]
    with get_conn() as conn:
        conn.execute(f"UPDATE scans SET {cols} WHERE scan_id = ?", values)


def get_scan(scan_id: str) -> Optional[Dict]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def list_scans(limit: int = 50) -> List[Dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["severity_counts"] = severity_counts(d["scan_id"])
        d["findings_count"] = sum(d["severity_counts"].values())
        out.append(d)
    return out


def delete_scan(scan_id: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
def save_finding(finding: Finding) -> int:
    # Defensive serialisation: extra may be a dict or already-serialised JSON string.
    extra = finding.extra
    if isinstance(extra, dict):
        extra_json = json.dumps(extra, default=str)
    elif isinstance(extra, str):
        extra_json = extra
    else:
        extra_json = "{}"

    # cwe should always be a string like "CWE-89"; coerce defensively.
    cwe = str(finding.cwe) if finding.cwe is not None and not isinstance(finding.cwe, str) else finding.cwe

    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO findings
               (scan_id, category, subtype, owasp_id, owasp_name, severity, confidence,
                url, parameter, method, payload, evidence, description, remediation, cwe,
                extra_json, found_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                finding.scan_id, finding.category, finding.subtype, finding.owasp_id,
                finding.owasp_name, finding.severity.label, float(finding.confidence),
                finding.url, finding.parameter, finding.method,
                finding.payload, finding.evidence, finding.description,
                finding.remediation, cwe, extra_json, finding.found_at,
            ),
        )
        return cur.lastrowid


def _enrich(row: Dict) -> Dict:
    row["extra"] = json.loads(row.pop("extra_json") or "{}")
    sev = Severity.from_str(row["severity"])
    row["severity_color"] = sev.color
    row["severity_score"] = int(sev)
    return row


def get_findings(scan_id: str, category: Optional[str] = None,
                  severity: Optional[str] = None, owasp_id: Optional[str] = None) -> List[Dict]:
    query = "SELECT * FROM findings WHERE scan_id = ?"
    params: List = [scan_id]
    if category:
        query += " AND category = ?"
        params.append(category)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if owasp_id:
        query += " AND owasp_id = ?"
        params.append(owasp_id)
    query += f" ORDER BY {_SEVERITY_ORDER_SQL}, id"
    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_enrich(dict(r)) for r in rows]


def get_finding(finding_id: int) -> Optional[Dict]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    return _enrich(dict(row)) if row else None


def severity_counts(scan_id: str) -> Dict[str, int]:
    counts = {s.label: 0 for s in Severity}
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS c FROM findings WHERE scan_id = ? GROUP BY severity",
            (scan_id,),
        ).fetchall()
    for r in rows:
        counts[r["severity"]] = r["c"]
    return counts


def category_counts(scan_id: str) -> Dict[str, int]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT category, COUNT(*) AS c FROM findings WHERE scan_id = ? GROUP BY category",
            (scan_id,),
        ).fetchall()
    return {r["category"]: r["c"] for r in rows}


def owasp_counts(scan_id: str) -> Dict[str, Dict[str, int]]:
    """Returns ``{owasp_id: {severity_label: count}}`` for the Top-10 coverage matrix."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT owasp_id, severity, COUNT(*) AS c FROM findings "
            "WHERE scan_id = ? GROUP BY owasp_id, severity",
            (scan_id,),
        ).fetchall()
    out: Dict[str, Dict[str, int]] = {}
    for r in rows:
        out.setdefault(r["owasp_id"], {})[r["severity"]] = r["c"]
    return out


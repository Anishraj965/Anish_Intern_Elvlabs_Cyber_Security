"""core/models.py — shared data structures for all modules."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Dict, List, Optional


class Severity(IntEnum):
    INFO = 0; LOW = 1; MEDIUM = 2; HIGH = 3; CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @property
    def color(self) -> str:
        return {0:"#5a6e82",1:"#00e5ff",2:"#ffe600",3:"#ff6600",4:"#ff003c"}[self.value]

    @classmethod
    def from_str(cls, name: str) -> "Severity":
        try:    return cls[name.strip().upper()]
        except: return cls.INFO


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
    parameter: Optional[str] = None
    method: str = "GET"
    payload: Optional[str] = None
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cwe: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["severity_score"] = int(self.severity)
        d["severity_color"] = self.severity.color
        return d


@dataclass
class FormField:
    name: str
    type: str = "text"
    value: str = ""


@dataclass
class WebForm:
    action: str
    method: str = "GET"
    inputs: List[FormField] = field(default_factory=list)
    source_url: str = ""

    def fillable_inputs(self) -> List[FormField]:
        skip = {"submit","button","image","reset","file"}
        return [i for i in self.inputs if i.type.lower() not in skip and i.name]


@dataclass
class Endpoint:
    url: str
    params: List[str] = field(default_factory=list)
    forms: List[WebForm] = field(default_factory=list)


@dataclass
class ScanProgress:
    scan_id: str
    target: str
    status: str = "queued"
    current_module: str = ""
    pages_crawled: int = 0
    findings_count: int = 0
    severity_counts: Dict[str,int] = field(default_factory=lambda:
        {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0})
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str] = None
    error: Optional[str] = None
    # Per-module tracking for 4-tab UI
    module_logs: Dict[str,List[str]] = field(default_factory=lambda:
        {"sqli":[],"xss":[],"csrf":[],"owasp":[]})
    module_status: Dict[str,str] = field(default_factory=lambda:
        {"sqli":"pending","xss":"pending","csrf":"pending","owasp":"pending"})
    module_findings: Dict[str,int] = field(default_factory=lambda:
        {"sqli":0,"xss":0,"csrf":0,"owasp":0})
    module_severity: Dict[str,Dict[str,int]] = field(default_factory=lambda: {
        k:{"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
        for k in ("sqli","xss","csrf","owasp")})
    owasp_radar: Dict[str,int] = field(default_factory=dict)
    global_log: List[str] = field(default_factory=list)

    def log(self, module: str, msg: str, max_lines: int = 500) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry = f"[{ts}] {msg}"
        buf = self.module_logs.get(module, self.global_log)
        buf.append(entry)
        if len(buf) > max_lines:
            buf[:] = buf[-max_lines:]
        self.global_log.append(entry)
        if len(self.global_log) > 800:
            self.global_log[:] = self.global_log[-800:]

    def to_dict(self) -> Dict[str,Any]:
        return {
            "scan_id": self.scan_id, "target": self.target,
            "status": self.status, "current_module": self.current_module,
            "pages_crawled": self.pages_crawled,
            "findings_count": self.findings_count,
            "severity_counts": self.severity_counts,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "error": self.error,
            "module_logs": {k: v[-200:] for k,v in self.module_logs.items()},
            "module_status": self.module_status,
            "module_findings": self.module_findings,
            "module_severity": self.module_severity,
            "owasp_radar": self.owasp_radar,
            "global_log": self.global_log[-150:],
        }

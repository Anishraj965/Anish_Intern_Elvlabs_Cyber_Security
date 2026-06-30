"""
core/owasp_mapping.py
======================
Reference data for the OWASP Top 10 (2021) used to annotate every finding
with an OWASP category, a short plain-English description and general
remediation guidance. This lets the report generators show a consistent
"OWASP Top 10 Coverage" matrix regardless of which module produced a finding.

Descriptions below are written independently for this project (not copied
from any OWASP document) and are intentionally short -- they exist to give
a capstone reader quick context, not to replace the official OWASP project
documentation, which should always be cited as the canonical reference.
"""

from __future__ import annotations

from typing import Dict, List, TypedDict


class OwaspCategory(TypedDict):
    id: str
    name: str
    summary: str
    remediation: List[str]


OWASP_TOP_10_2021: Dict[str, OwaspCategory] = {
    "A01:2021": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "summary": (
            "Restrictions on what authenticated or anonymous users are allowed "
            "to do are not properly enforced, allowing access to data or "
            "functions outside the user's intended permissions (e.g. viewing "
            "another user's records, reaching admin pages, or bypassing "
            "CSRF protections)."
        ),
        "remediation": [
            "Deny access by default and require explicit grants for every route and resource.",
            "Enforce ownership checks server-side for every object reference (avoid IDOR).",
            "Use anti-CSRF tokens on all state-changing requests and verify the Origin/Referer header.",
            "Disable directory listing and remove or protect administrative paths.",
            "Log and alert on repeated access-control failures.",
        ],
    },
    "A02:2021": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "summary": (
            "Sensitive data (credentials, session tokens, personal data) is "
            "transmitted or stored without adequate protection -- for example "
            "over plain HTTP, without HSTS, or in cookies missing the Secure flag."
        ),
        "remediation": [
            "Serve the entire site over TLS and redirect all HTTP traffic to HTTPS.",
            "Send the Strict-Transport-Security (HSTS) header with a long max-age.",
            "Mark session and authentication cookies as Secure and HttpOnly.",
            "Never place secrets, tokens or PII in URLs or GET parameters.",
            "Use strong, up-to-date, well-reviewed cryptographic algorithms only.",
        ],
    },
    "A03:2021": {
        "id": "A03:2021",
        "name": "Injection",
        "summary": (
            "Untrusted input is concatenated into a query, command or template "
            "without proper validation, escaping or parameterization, allowing "
            "an attacker to alter the intended logic. Covers SQL injection, "
            "cross-site scripting (XSS), OS command injection and template injection."
        ),
        "remediation": [
            "Use parameterized queries / prepared statements for all database access -- never string-concatenate input into SQL.",
            "Apply context-aware output encoding for all user-controlled data rendered in HTML, JS, attributes or URLs.",
            "Validate input against an allow-list of expected formats server-side.",
            "Avoid passing user input to shell commands, eval(), or template engines; use safe APIs and sandboxed/autoescaping templates.",
            "Adopt a strict Content-Security-Policy as defense-in-depth against XSS.",
        ],
    },
    "A04:2021": {
        "id": "A04:2021",
        "name": "Insecure Design",
        "summary": (
            "Security weaknesses that stem from the application's design "
            "rather than an implementation bug -- missing rate limiting, "
            "predictable resource identifiers, or business logic that can "
            "be abused regardless of how cleanly the code is written."
        ),
        "remediation": [
            "Apply rate limiting and account lockout / backoff on authentication and other sensitive endpoints.",
            "Thread-model abuse cases (not just happy paths) during design and review.",
            "Avoid exposing predictable identifiers for sensitive resources.",
            "Use centralized, well-tested security controls (auth, validation) rather than reinventing them per-feature.",
            "Limit the data returned by APIs to what the client actually needs.",
        ],
    },
    "A05:2021": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "summary": (
            "The application, server or framework is deployed with insecure "
            "defaults, unnecessary features enabled, overly verbose error "
            "messages, missing security headers, or exposed configuration "
            "and backup files."
        ),
        "remediation": [
            "Harden default configurations: disable unused features, sample apps, default accounts and verbose error pages.",
            "Set security headers: Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy.",
            "Disable directory listing and remove backup, config and version-control files (.git, .env, .bak) from web roots.",
            "Restrict HTTP methods (disable TRACE/TRACK, restrict OPTIONS) at the server/framework level.",
            "Automate configuration review as part of the deployment pipeline.",
        ],
    },
    "A06:2021": {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "summary": (
            "The application uses libraries, frameworks, CMS platforms or "
            "server software with known vulnerabilities, or versions that "
            "are end-of-life and no longer receive security patches."
        ),
        "remediation": [
            "Maintain an inventory of client- and server-side components and their versions.",
            "Subscribe to vulnerability advisories for all direct and transitive dependencies.",
            "Patch or upgrade components on a regular, monitored cadence.",
            "Remove unused dependencies, features, files and documentation.",
            "Avoid exposing version numbers via headers, comments or default file paths where practical.",
        ],
    },
    "A07:2021": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "summary": (
            "Weaknesses in how the application confirms a user's identity or "
            "manages sessions -- weak password policies, predictable session "
            "identifiers, missing multi-factor authentication, or responses "
            "that let an attacker enumerate valid usernames."
        ),
        "remediation": [
            "Implement multi-factor authentication for sensitive accounts.",
            "Return identical, generic error messages for 'unknown user' and 'wrong password'.",
            "Use long, random, securely-generated session identifiers and rotate them on login/privilege change.",
            "Enforce strong password policies and check new passwords against breach lists.",
            "Apply rate limiting / lockout on authentication endpoints.",
        ],
    },
    "A08:2021": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "summary": (
            "The application relies on plugins, libraries, CDNs, CI/CD "
            "pipelines or auto-update mechanisms without verifying their "
            "integrity, allowing tampered code or data to be trusted and executed."
        ),
        "remediation": [
            "Use Subresource Integrity (SRI) hashes for any third-party scripts and stylesheets.",
            "Verify digital signatures / checksums for software updates and dependencies.",
            "Ensure CI/CD pipelines and configuration files (.git, .github, .travis.yml, Jenkinsfile) are not publicly accessible.",
            "Avoid sending unsigned or unencrypted serialized data to untrusted clients.",
        ],
    },
    "A09:2021": {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "summary": (
            "Insufficient logging, monitoring and alerting means breaches and "
            "active attacks (e.g. repeated failed logins, injection attempts) "
            "go undetected. Externally this often correlates with verbose "
            "error pages and an absence of any anti-automation controls."
        ),
        "remediation": [
            "Log authentication, access-control and validation failures with enough detail to investigate incidents.",
            "Ensure logs are protected from tampering and monitored / alerted on in near real time.",
            "Return generic error pages to users while logging full details server-side.",
            "Establish an incident response plan and test it periodically.",
        ],
    },
    "A10:2021": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "summary": (
            "The application fetches a remote resource using a URL supplied "
            "by the user without validating the destination, allowing an "
            "attacker to make the server issue requests to internal services, "
            "cloud metadata endpoints, or other unintended destinations."
        ),
        "remediation": [
            "Validate and allow-list destination hosts/schemes for any server-side fetch driven by user input.",
            "Disable HTTP redirects when fetching user-supplied URLs, or re-validate after each redirect.",
            "Apply network segmentation so the application server cannot reach internal-only services or cloud metadata endpoints.",
            "Return generic errors for fetch failures rather than echoing internal responses.",
        ],
    },
}


# ---------------------------------------------------------------------------
# Maps the `category` string produced by detection modules to an OWASP
# Top 10 (2021) category. Used by every module so findings can be grouped
# and the "Top 10 coverage matrix" can be rendered consistently.
# ---------------------------------------------------------------------------
CATEGORY_OWASP_MAP: Dict[str, str] = {
    # Primary objectives
    "SQL Injection": "A03:2021",
    "Cross-Site Scripting": "A03:2021",
    "Cross-Site Request Forgery": "A01:2021",
    "Command Injection": "A03:2021",
    "Template Injection": "A03:2021",
    "XML External Entity": "A03:2021",
    # OWASP checklist modules
    "Broken Access Control": "A01:2021",
    "Cryptographic Failures": "A02:2021",
    "Insecure Design": "A04:2021",
    "Security Misconfiguration": "A05:2021",
    "Vulnerable and Outdated Components": "A06:2021",
    "Identification and Authentication Failures": "A07:2021",
    "Software and Data Integrity Failures": "A08:2021",
    "Security Logging and Monitoring Failures": "A09:2021",
    "Server-Side Request Forgery": "A10:2021",
}


def owasp_name_for(category: str) -> str:
    owasp_id = CATEGORY_OWASP_MAP.get(category, "A03:2021")
    return OWASP_TOP_10_2021[owasp_id]["name"]


def owasp_id_for(category: str) -> str:
    return CATEGORY_OWASP_MAP.get(category, "A03:2021")


def all_owasp_ids() -> List[str]:
    return list(OWASP_TOP_10_2021.keys())


def remediation_text(owasp_id: str) -> str:
    """Join a category's remediation bullets into one paragraph for use as a
    Finding's default `remediation` field."""
    items = OWASP_TOP_10_2021.get(owasp_id, {}).get("remediation", [])
    return " ".join(items)

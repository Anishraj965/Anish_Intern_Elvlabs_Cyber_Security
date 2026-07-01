# 🖥️ Elevate Labs Cybersecurity Internship Portfolio

<p align="center">
  <img src="https://img.shields.io/badge/Internship-Completed-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Cybersecurity-Blue%20Team-2563EB?style=for-the-badge&logo=shield&logoColor=white"/>
  <img src="https://img.shields.io/badge/Cybersecurity-Red%20Team-DC2626?style=for-the-badge&logo=shield&logoColor=white"/>
  <img src="https://img.shields.io/badge/Kali%20Linux-Platform-557C94?style=for-the-badge&logo=kalilinux&logoColor=white"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Flask-Backend-000000?style=for-the-badge&logo=flask&logoColor=white"/>
  <img src="https://img.shields.io/badge/MongoDB-Database-47A248?style=for-the-badge&logo=mongodb&logoColor=white"/>
  <img src="https://img.shields.io/badge/OWASP-Top%2010%202021-7A0019?style=for-the-badge&logoColor=white"/>
  <img src="https://img.shields.io/badge/Threat%20Intelligence-Live-CC0000?style=for-the-badge&logoColor=white"/>
  <img src="https://img.shields.io/badge/IOC%20Enrichment-Multi--Source-6B21A8?style=for-the-badge&logoColor=white"/>
</p>

---

## 📑 Table of Contents

- [👋 About This Internship](#-about-this-internship)
- [🏆 Internship Highlights](#-internship-highlights)
- [🔎 Detailed Task Summaries](#-detailed-task-summaries)
- [📁 Projects](#-projects)
- [🌟 Why Hire Me?](#-why-hire-me)
- [📈 Key Skills Demonstrated](#-key-skills-demonstrated)

---

## 👋 About This Internship

**Role:** Cybersecurity Intern  
**Organization:** Elevate Labs  
**Duration:** 45 days (May–June 2026)

Welcome! This repository documents my hands-on journey as a Cybersecurity Intern at Elevate Labs. I have successfully completed **6 practical tasks** covering network scanning, phishing analysis, vulnerability assessment, firewall configuration, traffic analysis, and password security — plus **2 capstone projects** applying these skills to build real offensive and defensive security tools from scratch.

---

## 🏆 Internship Highlights

| # | Task / Project | Focus Area | Key Tools | Badge |
|---|----------------|------------|-----------|-------|
| 1 | [Local Network Port Scan](#task-1-local-network-port-scan) | Network Reconnaissance | Nmap, Wireshark | <img src="https://img.shields.io/badge/Nmap-Port%20Scan-4682B4?style=flat-square&logo=wireshark&logoColor=white"/> |
| 2 | [Phishing Email Analysis](#task-2-phishing-email-analysis) | Social Engineering & Forensics | Outlook, MXToolbox | <img src="https://img.shields.io/badge/Email%20Forensics-SPF%2FDKIM%2FDMARC-CC0000?style=flat-square"/> |
| 3 | [Vulnerability Assessment](#task-3-vulnerability-assessment-project) | Vulnerability Management | Nessus Essentials | <img src="https://img.shields.io/badge/Nessus-CVSS%20Scanning-FF6600?style=flat-square"/> |
| 4 | [UFW Firewall Configuration](#task-4-ufw-firewall-configuration) | Network Defense & Hardening | UFW, Kali Linux | <img src="https://img.shields.io/badge/UFW-Default%20Deny-22C55E?style=flat-square&logo=linux&logoColor=white"/> |
| 5 | [Network Traffic Analysis](#task-5-network-traffic-analysis-with-wireshark) | Packet Analysis & Threat Detection | Wireshark | <img src="https://img.shields.io/badge/Wireshark-Live%20Capture-1679A7?style=flat-square&logo=wireshark&logoColor=white"/> |
| 6 | [Password Strength Evaluation](#task-6-password-strength-evaluation--security-best-practices) | Authentication & User Awareness | Bitwarden, Security.org | <img src="https://img.shields.io/badge/Auth%20Security-MFA%20%26%20Passkeys-EAB308?style=flat-square"/> |
| **7** | [**Web Vulnerability Scanner**](#project-1-web-vulnerability-scanner) | **Web App Pentesting — OWASP Top 10** | **Python, Flask, BeautifulSoup** | <img src="https://img.shields.io/badge/SQLi%20%7C%20XSS%20%7C%20CSRF%20%7C%20OWASP-7A0019?style=flat-square"/> |
| **8** | [**CTI Dashboard**](#project-2-evil-legend-cti-dashboard) | **Threat Intelligence & IOC Enrichment** | **Flask, MongoDB, APScheduler** | <img src="https://img.shields.io/badge/IOC%20Enrichment-5%20APIs%20%7C%206%20Feeds-6B21A8?style=flat-square"/> |

---

## 🔎 Detailed Task Summaries

### Task 1: Local Network Port Scan

🔗 [View Full Task](https://github.com/Anishraj965/Anish_Intern_Elvlabs_Cyber_Security/tree/Task-1)

**Objective:** Identify open ports and potential vulnerabilities in the local network using Nmap and Wireshark.

**Outcome:** Discovered 5 active devices, mapped exposed services (FTP, Telnet, SMB, MySQL), and identified a highly vulnerable device with 23 open ports including backdoor services. Performed SYN scans at the packet level and documented each device's attack surface.

**Key Learning:** Reinforced the importance of reducing exposed ports, the danger of legacy services like Telnet and FTP in production, and the value of regular network auditing.

---

### Task 2: Phishing Email Analysis

🔗 [View Full Task](https://github.com/Anishraj965/Anish_Intern_Elvlabs_Cyber_Security/tree/Task-2)

**Objective:** Analyse a real phishing email for classic red flags and security weaknesses.

**Outcome:** Identified spoofed sender domains, failed SPF/DKIM/DMARC authentication, suspicious redirect links, and urgency-based social engineering language. Documented the full attack chain from initial lure to credential harvesting.

**Key Learning:** Developed a systematic phishing indicator checklist and produced actionable recommendations for recognising and reporting phishing attempts in an enterprise environment.

---

### Task 3: Vulnerability Assessment Project

🔗 [View Full Task](https://github.com/Anishraj965/Anish_Intern_Elvlabs_Cyber_Security/tree/Task-3)

**Objective:** Conduct a full vulnerability scan and produce a remediation plan on a Kali Linux system using Nessus Essentials.

**Outcome:** Detected **72 vulnerabilities** — 7 critical (CVSS 10.0) — including VNC backdoor, SSLv2 protocol exposure, and vsFTPD backdoor. Delivered a prioritised remediation strategy aligned to CVSS severity scores.

**Key Learning:** Gained practical experience in professional vulnerability management: how to triage findings by CVSS score, map them to CVEs, and write remediation reports that security teams can act on.

---

### Task 4: UFW Firewall Configuration

🔗 [View Full Task](https://github.com/Anishraj965/Anish_Intern_Elvlabs_Cyber_Security/tree/Task-4)

**Objective:** Harden a Linux system by configuring and testing firewall rules with UFW (Uncomplicated Firewall).

**Outcome:** Implemented a default-deny policy, allowed only essential services (SSH port 22, HTTP port 80, HTTPS port 443), explicitly blocked Telnet (port 23), and validated all rules using Nmap post-configuration scans to confirm enforcement.

**Key Learning:** Demonstrated the practical balance between security and usability in real-world firewall management, and understood why default-deny with explicit allowlisting is the correct posture.

---

### Task 5: Network Traffic Analysis with Wireshark

🔗 [View Full Task](https://github.com/Anishraj965/Anish_Intern_Elvlabs_Cyber_Security/tree/Task-5)

**Objective:** Capture and analyse live network traffic to identify vulnerabilities and protocol usage patterns.

**Outcome:** Identified HTTP, DNS, ARP, NTP, ICMP, and TCP traffic streams. **Critical finding:** plaintext credential transmission captured over HTTP — `username: Jhon Ripper`, `password: 12345` — demonstrating a live credential interception scenario.

**Key Learning:** Understood why HTTPS is non-negotiable for any authenticated application, and how packet-level visibility can expose credentials that encrypted tunnels would protect.

---

### Task 6: Password Strength Evaluation & Security Best Practices

🔗 [View Full Task](https://github.com/Anishraj965/Anish_Intern_Elvlabs_Cyber_Security/tree/Task-6)

**Objective:** Evaluate password strengths, promote secure password management, and explore modern authentication technologies.

**Outcome:** Compared weak (`password123` — cracked in under 1 second) versus strong passwords (estimated centuries to crack). Evaluated password managers (Bitwarden), MFA implementations, and passkey adoption as a phishing-resistant alternative.

**Key Learning:** Enhanced authentication security awareness and produced a user-facing guide with actionable steps — covering entropy, password reuse risks, and the FIDO2/passkey standard.

---

## 📁 Projects

### Project 1: Web Vulnerability Scanner

🔗 [View Branch](https://github.com/Anishraj965/Anish_Intern_Elvlabs_Cyber_Security/tree/Project-1-Web-Vulnerability-Scanner)
🎥 [Demo Video](https://drive.google.com/file/d/1qDiHEcwk--GVCKNFeT2tCQb5pNAPYWyJ/view?usp=sharing)

**Objective:** Build an automated web application security assessment platform covering the full OWASP Top 10 2021 and three major injection vulnerability classes.

**Tools:** Python, Flask, BeautifulSoup4, ReportLab, SQLite, Jinja2, ThreadPoolExecutor

**Key Highlights:**
- Built **4 independent scanner modules** — each runs as an isolated subprocess: `evil_sqli` (Error-based, Union, Boolean, Time-based Blind, Stacked), `evil_xss` (Reflected, Stored, DOM with 100+ polyglot payloads), `evil_csrf` (token absence, active validation, referrer-based), `evil_owasp` (all 10 OWASP 2021 categories)
- Implemented a **multi-threaded web crawler** with configurable depth (1–10), page limits (1–500), automatic form discovery, URL deduplication, and session/cookie persistence
- Built a **real-time Flask dashboard** with SSE (Server-Sent Events) live progress streaming, severity distribution charts, and scan history comparison
- Generated **dual-format professional reports** — interactive HTML (Jinja2) and print-ready PDF (ReportLab) — with executive summary, OWASP risk metrics, per-finding evidence, CWE references, and remediation steps
- Every finding is **mapped to OWASP Top 10 2021** (A01–A10), classified by 5-level severity (Critical → Info), scored with confidence (0.0–1.0), and persisted to SQLite
- Built-in **DVWA integration** with configurable authentication and security level (Low / Medium / High) for scanner validation

**Deliverables:** Flask web app, 4 scanner modules, SQLite persistence layer, HTML + PDF report pipeline, OWASP mapping engine

---

### Project 2: Evil Legend CTI Dashboard

🔗 [View Branch](https://github.com/Anishraj965/Anish_Intern_Elvlabs_Cyber_Security/tree/Project-2-CTI-Dashboard)
🎥 [Demo Video](https://drive.google.com/file/d/19iWYySFSDjom-_YFwlkK7A0ZEwjDKy1q/view?usp=sharing)

**Objective:** Build a full-stack Cyber Threat Intelligence platform that aggregates IOC data from multiple threat intelligence APIs and live OSINT feeds into a unified analyst interface.

**Tools:** Python, Flask, MongoDB (PyMongo), bcrypt, APScheduler, ThreadPoolExecutor

**Key Highlights:**
- Integrated **5 threat intelligence APIs** — VirusTotal, AbuseIPDB, AlienVault OTX, Shodan, and GreyNoise — with **parallel enrichment** via `ThreadPoolExecutor`, firing all relevant APIs simultaneously and returning a combined weighted verdict
- Built an **auto IOC type classifier** that detects IP, domain, URL, MD5, SHA1, SHA256, and CVE from any raw input before routing to the correct API endpoints
- Aggregated **6 live OSINT feeds** on automated schedules: Feodo Tracker (botnet C2 IPs, every 4 hrs), MalwareBazaar (malware hashes, every 2 hrs), URLhaus (phishing URLs, every 2 hrs), ThreatFox (daily IOCs, every 2 hrs), CISA KEV (known exploited CVEs, daily), and Emerging Threats IP blocklist (daily)
- Designed **6 MongoDB collections** with TTL-indexed caching (15 min for VirusTotal, 24 hrs for Shodan), per-API rate state tracking (minute/day/month quotas), and upsert-based IOC deduplication with `first_seen` / `last_seen` / `hit_count`
- Built **Bulk Scan mode** — submit up to 500 IOCs simultaneously; background daemon threads process them with 0.25s inter-request delays to respect free-tier API limits
- Implemented **bcrypt-hashed password authentication** with Flask session management and `login_required` decorators protecting all API endpoints

**Deliverables:** Flask REST API, MongoDB schema (6 collections), 5-API enrichment engine, 6-feed aggregator, bulk scan system, geographic & trend analytics

---

## 🌟 Why Hire Me?

- **Offensive + Defensive Balance:** Built both an attack tool (Web Vulnerability Scanner — SQLi, XSS, CSRF, OWASP) and a defence platform (CTI Dashboard — IOC enrichment, threat feed aggregation), demonstrating full-spectrum security awareness
- **Hands-On Tool Builder:** Didn't just run existing tools — built production-grade Python applications with Flask backends, database persistence, real-time streaming, and professional report generation
- **Threat Intelligence Mindset:** Designed and implemented IOC lifecycle management from ingestion (6 live feeds) through enrichment (5 APIs in parallel) to storage (MongoDB with TTL caching) and analysis (geographic distribution, 30-day trends)
- **Vulnerability Management Experience:** Conducted real Nessus scans, triaged 72 vulnerabilities by CVSS score, and mapped findings to CVEs — the same workflow used in professional penetration testing engagements
- **Protocol-Level Understanding:** Captured and analysed live credentials in Wireshark, implemented SPF/DKIM/DMARC analysis in phishing triage, and validated firewall rules at the packet level with Nmap
- **Professional Documentation:** Every task and project includes detailed READMEs, screenshot libraries, and reproducibility instructions — the standard expected in professional security teams

---

## 📈 Key Skills Demonstrated

- **Network Reconnaissance:** Nmap SYN scans, service fingerprinting, OS detection, open port mapping, network topology discovery
- **Phishing Analysis:** Email header inspection, SPF/DKIM/DMARC validation, link defanging, social engineering indicator identification
- **Vulnerability Assessment:** Nessus scanning, CVSS scoring, CVE analysis, prioritised remediation planning, professional security reporting
- **Firewall Configuration:** UFW default-deny policy, allowlist management, rule validation, port blocking, post-configuration verification
- **Packet Analysis:** Wireshark live capture, protocol filtering, plaintext credential extraction, traffic pattern analysis
- **Authentication Security:** Password entropy evaluation, hash cracking awareness, MFA implementation, FIDO2/passkey standards
- **Web Application Pentesting:** SQL Injection (Error, Union, Boolean, Time-based Blind), XSS (Reflected, Stored, DOM), CSRF, OWASP Top 10 2021 (A01–A10), WAF fingerprinting and evasion
- **Threat Intelligence Operations:** IOC enrichment across 5 APIs, OSINT feed aggregation, TTL-cached lookups, combined threat verdict scoring, geographic and trend analysis
- **Security Tool Development:** Flask REST APIs, multi-threaded crawling, subprocess isolation, SSE real-time streaming, SQLite and MongoDB persistence
- **Report Generation:** ReportLab PDF reports with executive summaries, Jinja2 HTML reports, OWASP risk metrics, per-finding evidence and CWE mapping
- **Tools & Environment:** Python 3.10+, Kali Linux, Nmap, Wireshark, Nessus Essentials, UFW, Flask, MongoDB, SQLite, BeautifulSoup4, ReportLab, APScheduler, bcrypt, ThreadPoolExecutor

---

<p align="center">
  <em>Thank you for reviewing my Cybersecurity internship portfolio!</em>
</p>

<p align="center">
  <em>⭐ If you found this portfolio helpful, please give it a star!</em>
</p>

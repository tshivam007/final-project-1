# AegisTrace — Security Log & Alert Triage Workbench
### Module 06 Capstone Project &bull; Cybersecurity & Ethical Hacking Virtual Internship
**Codomax Digital Solutions**

---

## 📌 Intern & Project Metadata

| Attribute | Details |
| :--- | :--- |
| **Intern Name** | Shivam Tiwari |
| **Intern ID** | CDS/INTERN/261153 |
| **Internship Track** | Cybersecurity & Ethical Hacking |
| **Module** | **Module 06 — Cybersecurity Capstone Project (Day 26 – Day 30)** |
| **Project Title** | **AegisTrace — Security Log & Alert Triage Workbench** |
| **Primary Focus** | Defensive SecOps, Threat Hunting, Log Correlation & Incident Triage |
| **Live Web App** | `https://<your-username>.github.io/codomax-cybersecurity-capstone/web/` |
| **Repository** | `https://github.com/<your-username>/codomax-cybersecurity-capstone` |

---

## 🛡️ Executive Summary & Solution Overview

In modern Security Operations Centers (SOCs), junior and mid-level analysts face overwhelming alert fatigue and fragmented telemetry across operating system authentication trails (`sshd`, `sudo`), web reverse proxies/WAFs (Nginx, Apache, Cloudflare), and perimeter stateful firewalls (`iptables`, kernel netfilter). Unifying raw log streams and correlating indicators into prioritized triage queues often demands complex server infrastructure that creates privacy and compliance risks.

**AegisTrace** is an autonomous, zero-dependency, client-side **Security Log Analyzer & Incident Triage Workbench**. It delivers instantaneous heuristic detection, Indicator of Compromise (IoC) extraction, MITRE ATT&CK technique mapping, and automated SecOps remediation playbooks directly in the analyst's browser sandbox—ensuring sensitive log data never leaves the local perimeter.

---

## 🚀 Key Architectural & Operational Features

1. **Multi-Vector Log Telemetry Parsing**
   - Ingests Linux authentication logs (`auth.log`), web access/WAF logs (Common/Combined Log Format), and perimeter firewall dropped/forwarded packet records (`iptables` / kernel).
   - Features one-click preloaded attack scenarios for rapid verification alongside drag-and-drop file ingestion (`.log`, `.txt`, `.json`, `.csv`).

2. **Heuristic Detection & MITRE ATT&CK Mapping**
   - Rules engine correlates signature patterns to standardized techniques:
     - **T1059.004 / T1105**: Command Injection & Remote Shell Payload Ingestion
     - **T1190**: Exploitation of Public-Facing Applications (SQLi, Shellshock)
     - **T1083 / T1005**: Directory Traversal & Sensitive File Exposure (`/etc/passwd`, `.env`)
     - **T1110.001**: SSH Password Guessing & Credential Stuffing
     - **T1078.003**: Unauthorized Root Privilege Transitions
     - **T1046 / T1595.002**: Network Port Sweeps & Automated Scanners (`sqlmap`, `nikto`)
     - **T1071.001**: Suspicious Outbound Egress / C2 Beaconing (Port 4444, 1337)

3. **Dynamic Threat Scoring & Real-Time Metrics**
   - Immediate metric telemetry: Total Events, Critical Incidents, High-Risk Alerts, Medium Anomalies, and Unique Adversary IoCs.
   - Interactive severity chips (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) and substring query filters across source IPs, identities, categories, and MITRE techniques.

4. **Actionable Incident Response Playbooks**
   - Interactive deep-dive modal for every event provides granular field isolation, normalized telemetry, and tailored, step-by-step remediation procedures aligned with **NIST SP 800-61 Rev. 2**.

5. **Multi-Format Forensic Reporting**
   - Export structured **Markdown (`.md`)** executive triage reports.
   - Export raw machine-readable **JSON (`.json`)** security records.
   - Export filtered **CSV (`.csv`)** logs for spreadsheet auditing.

6. **Privacy-Preserving & Zero-Trust Client Model**
   - Operates 100% locally via client-side JavaScript. No backend database or third-party analytics telemetry is required.
   - Strict DOM sanitization prevents Stored Cross-Site Scripting (XSS) from malicious User-Agent or command injection payloads.

---

## 🔒 Safe Testing & Authorized Usage Disclaimer

> **IMPORTANT NOTICE:**  
> This solution was developed exclusively for academic research, defensive security evaluation, and educational demonstration as part of the **Codomax Digital Solutions Cybersecurity & Ethical Hacking Virtual Internship**.  
> All sample attack patterns and logs included in this workbench are synthetic or sanitized. Users must obtain explicit written authorization before ingesting live production telemetry or running active network scans against any system or infrastructure. The author and Codomax Digital Solutions assume no liability for misuse.

---

## 📁 Repository Directory Structure

```text
codomax-cybersecurity-capstone/
├── .gitignore
├── index.html                               # Zero-config root launcher & redirector
├── README.md                                # Comprehensive capstone documentation
├── LINKEDIN_POST.md                         # Publication-ready internship completion post
├── web/                                     # Live Static Web Application
│   ├── index.html                           # SecOps Dashboard Markup & UI
│   ├── styles.css                           # High-contrast Cyber SOC Dark Theme
│   └── app.js                               # Ingestion, Heuristics, Triage & Export Engine
└── docs/                                    # Technical Specifications & Reports
    ├── security-architecture.md             # System design, data flow & threat model
    ├── testing-and-verification-report.md   # Functional & adversarial testing results
    └── demo-walkthrough.md                  # Video demonstration script & step-by-step guide
```

---

## 💻 Local Quickstart & Testing

### Option A: Direct Browser Launch
Open `web/index.html` directly in any modern browser (Chrome, Edge, Firefox, Brave, Safari).

### Option B: Local Python HTTP Server
```bash
# Clone the repository
git clone https://github.com/<your-username>/codomax-cybersecurity-capstone.git
cd codomax-cybersecurity-capstone

# Start a lightweight local server
python -m http.server 8080
```
Open your browser and navigate to `http://localhost:8080`.

---

## 🌐 Live Cloud Deployment Guide

AegisTrace is designed with zero server-side dependencies and can be deployed in under 60 seconds to static hosting platforms:

### 1. GitHub Pages (Recommended)
1. Push this repository to your GitHub account:
   ```bash
   git init
   git add .
   git commit -m "feat: complete Module 06 Capstone project"
   git branch -M main
   git remote add origin https://github.com/<your-username>/codomax-cybersecurity-capstone.git
   git push -u origin main
   ```
2. Navigate to **Settings** &rarr; **Pages** in your GitHub repository.
3. Under **Branch**, select `main` and root `/ (root)`, then click **Save**.
4. GitHub Pages will publish the site at `https://<your-username>.github.io/codomax-cybersecurity-capstone/`.

### 2. Vercel / Cloudflare Pages / Netlify
- Link your GitHub repository. Set the output directory to root (`/`) or `web/`.
- Build command: *None* (Static site).

---

## 📚 Deliverable Verification Matrix

| Deliverable | Location | Status |
| :--- | :--- | :---: |
| **Capstone Overview & Setup** | [README.md](file:///c:/Users/AYAN%20MONDAL/Desktop/codomax-cybersecurity-capstone/README.md) | ✅ Complete |
| **SecOps Triage Dashboard** | [web/index.html](file:///c:/Users/AYAN%20MONDAL/Desktop/codomax-cybersecurity-capstone/web/index.html) | ✅ Complete |
| **Security Architecture Specification** | [docs/security-architecture.md](file:///c:/Users/AYAN%20MONDAL/Desktop/codomax-cybersecurity-capstone/docs/security-architecture.md) | ✅ Complete |
| **Testing & Verification Report** | [docs/testing-and-verification-report.md](file:///c:/Users/AYAN%20MONDAL/Desktop/codomax-cybersecurity-capstone/docs/testing-and-verification-report.md) | ✅ Complete |
| **Demo Walkthrough Guide** | [docs/demo-walkthrough.md](file:///c:/Users/AYAN%20MONDAL/Desktop/codomax-cybersecurity-capstone/docs/demo-walkthrough.md) | ✅ Complete |
| **LinkedIn Announcement** | [LINKEDIN_POST.md](file:///c:/Users/AYAN%20MONDAL/Desktop/codomax-cybersecurity-capstone/LINKEDIN_POST.md) | ✅ Complete |

---

## 👨‍💻 Author & Acknowledgments

- **Intern:** Ayan Mondal
- **ID:** `CDS/INT/2026/26637504`
- **Program:** Virtual Internship in Cybersecurity & Ethical Hacking
- **Organization:** Codomax Digital Solutions

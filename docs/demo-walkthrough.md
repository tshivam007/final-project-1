# AegisTrace — Video Demonstration & Walkthrough Guide
### Module 06 Capstone Project &bull; Cybersecurity & Ethical Hacking Virtual Internship
**Codomax Digital Solutions**

---

## 📋 Demonstration Overview

| Parameter | Details |
| :--- | :--- |
| **Presenter** | **Ayan Mondal** (Intern ID: `CDS/INT/2026/26637504`) |
| **Track** | Cybersecurity & Ethical Hacking Virtual Internship |
| **Project Title** | AegisTrace — Security Log & Alert Triage Workbench |
| **Target Video Length** | **3 to 5 Minutes** |
| **Recommended Tools** | OBS Studio, Loom, or Windows Xbox Game Bar (`Win + G`) |
| **Resolution & Format** | 1080p (1920x1080), 30 or 60 FPS, Clear Microphone Audio |

---

## 🎬 Step-by-Step Recording Script & Timeline

### Scene 1: Introduction & Internship Overview (0:00 – 0:45)
**Screen Display:** Webcam or Title Slide showing AegisTrace Dashboard header with Intern details (`Ayan Mondal`, `CDS/INT/2026/26637504`, Codomax Digital Solutions).

**Spoken Script:**
> *"Hello everyone! My name is Ayan Mondal, Intern ID CDS/INT/2026/26637504, and this is my Module 06 Capstone Project for the Cybersecurity & Ethical Hacking Virtual Internship at Codomax Digital Solutions.*  
>  
> *During this internship, we explored vulnerability assessment, network defense, ethical hacking methodologies, and incident response. For my final capstone project, I built **AegisTrace — a SecOps Security Log Analyzer & Incident Triage Workbench**. It is designed to empower SOC analysts to rapidly ingest, normalize, and triage multi-vector security telemetry directly within a zero-trust, client-side browser sandbox without risking sensitive data leaks."*

---

### Scene 2: Live Workbench Tour & Architecture (0:45 – 1:30)
**Screen Display:** Full browser window showing the live AegisTrace dashboard (`web/index.html`).

**Actions:**
1. Point out the top bar: Intern badge, "SOC Engine Active" pulse indicator, and the **Authorized Academic & Defensive Use Disclaimer**.
2. Hover over the top metric cards (**Total Events Analyzed**, **Critical Incidents**, **High Severity Alerts**, **IoCs Flagged**).
3. Briefly show the dual-column layout: Left column for Ingestion & IoC telemetry; Right column for the Interactive Security Event Stream.

**Spoken Script:**
> *"Here is the live AegisTrace dashboard. Notice our real-time metrics summarizing high-risk incidents and Indicators of Compromise. AegisTrace is built completely with vanilla front-end technologies—HTML5, modern CSS3, and JavaScript—meaning it runs 100% locally with zero external network tracking or database dependencies. Sensitive security logs never leave the analyst's machine."*

---

### Scene 3: Scenario Triage & Heuristic Detection (1:30 – 3:00)
**Screen Display:** Focus on Telemetry Ingestion panel and Event Stream table.

**Actions:**
1. Click the **"SSH Brute-Force & Root Breach"** preset. Watch the metrics instantly update.
2. In the search box, type `198.51.100.45` to show live instant filtering.
3. Show the table rows: Point out the progression from `Failed password` (`T1110.001`), to `Accepted password for root` (`T1078.003`), to the critical command injection alert `T1059.004`.
4. Switch to the **"Web Traversal, SQLi & Scans"** preset.
5. Click on the **"Critical"** filter chip to isolate the path traversal attack (`../../../../etc/passwd`).

**Spoken Script:**
> *"Let's demonstrate our heuristic detection engine in action. With one click on our 'SSH Brute-Force' scenario, AegisTrace processes the raw auth log lines.  
>  
> Notice how it identifies an automated brute-force attack from IP 198.51.100.45, maps it to MITRE ATT&CK Technique T1110, flags the subsequent unauthorized root login, and immediately catches a malicious curl-to-bash command injection payload!  
>  
> We can also filter seamlessly: clicking our severity chips lets us isolate Critical and High threats in milliseconds."*

---

### Scene 4: Deep Dive Modal & Incident Response Playbooks (3:00 – 3:50)
**Screen Display:** Click the **"Triage &rarr;"** button on the `RULE_CMD_INJECT_C2` or `RULE_PATH_TRAVERSAL_PASSWD` event.

**Actions:**
1. The detail modal opens smoothly.
2. Show the parsed fields: Timestamp, Attacker IP, Identity, MITRE Technique ID.
3. Show the **Raw Normalized Telemetry Line**.
4. Highlight the **Automated SecOps Remediation Playbook** box with numbered response steps (e.g., host quarantine, process termination, egress firewall blocking).
5. Close modal with `Escape` or the close button.
6. Click **"Export .MD"** and **"Export .JSON"**; show the generated downloaded files and toast notifications.

**Spoken Script:**
> *"When an analyst clicks 'Triage' on any event, AegisTrace opens an incident investigation drawer. Here, the analyst gets the normalized event metadata, the exact raw log string, and an actionable, automated remediation playbook based on NIST SP 800-61 guidelines.  
>  
> Once the triage is complete, the analyst can export a formal Markdown triage report, raw JSON incident data, or CSV logs for auditing and handoff to the tier-3 response team."*

---

### Scene 5: Codebase Review & Conclusion (3:50 – 4:30)
**Screen Display:** VS Code or GitHub Repository page showing:
- `README.md`
- `web/app.js` (highlight `escapeHTML()` sanitization and `DETECTION_RULES`)
- `docs/security-architecture.md`
- `docs/testing-and-verification-report.md`

**Spoken Script:**
> *"Taking a quick look at the codebase in our GitHub repository: we've thoroughly documented the security architecture, test verification report, and adversarial safety checks. In `app.js`, all user input is sanitized against Cross-Site Scripting before touching the DOM, ensuring that even hostile log payloads cannot compromise the analyst's workstation.  
>  
> I want to express my sincere gratitude to Codomax Digital Solutions for this incredible Cybersecurity & Ethical Hacking Virtual Internship. Thank you for watching!"*

---

## ✅ Pre-Recording Verification Checklist

- [ ] Browser zoom level set to 100% or 110% for optimal readability.
- [ ] Microphone input tested and background noise minimized.
- [ ] GitHub repository tab and live website tab opened and preloaded.
- [ ] Sample presets tested (`Mixed`, `Auth`, `Web`, `Firewall`).
- [ ] Toast notifications and modal interactions tested smoothly.
- [ ] Download folder cleared so exported reports appear clearly on camera.

# AegisTrace — Testing & Security Verification Report
### Module 06 Capstone Project &bull; Cybersecurity & Ethical Hacking Virtual Internship
**Codomax Digital Solutions**

---

## 1. Document Control & Test Execution Information

| Attribute | Specification |
| :--- | :--- |
| **Project** | AegisTrace — Security Log & Alert Triage Workbench |
| **Lead Engineer** | **Ayan Mondal** (Intern ID: `CDS/INT/2026/26637504`) |
| **Track** | Cybersecurity & Ethical Hacking |
| **Test Period** | Day 28 – Day 30 (Module 06 Capstone Phase) |
| **Test Environment** | Windows 11 Enterprise / Google Chrome v128, Mozilla Firefox v130, Microsoft Edge v128 |
| **Evaluation Type** | Functional Verification, Adversarial Log Injection, Input Sanitization & Performance Benchmark |
| **Overall Verdict** | **PASSED & APPROVED FOR PRODUCTION RELEASE** |

---

## 2. Test Scope & Methodology

The verification plan encompassed four discrete evaluation categories:
1. **Functional UI/UX Testing:** Verification of telemetry ingestion, scenario presets, filter controls, live search indexing, deep modal rendering, and playbook generation.
2. **Adversarial & Sanitization Testing:** Deliberate injection of XSS payloads, malformed regex patterns, null characters, and extreme-length input lines.
3. **Detection Accuracy & MITRE Correlation:** Evaluation of heuristic detection logic against authentic multi-vector attack chains (credential access, web exploits, network recon, C2 beaconing).
4. **Performance & Memory Footprint:** Telemetry parsing speed, heap stability, and export execution times.

---

## 3. Adversarial Security & Input Sanitization Testing

Because security log analyzers ingest adversarial data (often containing attacker-controlled User-Agent headers, URL query parameters, and usernames), the application must resist injection attempts.

| Test ID | Injection Vector | Test Payload Ingested | Expected Behavior | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **SEC-01** | Reflected XSS in User-Agent | `GET /login HTTP/1.1 401 204 "-" "<script>alert('XSS')</script>"` | Script tags escaped as `&lt;script&gt;`; zero DOM script execution | Verified. Payload displayed safely in raw box and table. | **PASS** |
| **SEC-02** | HTML Tag Injection in Username | `sshd[1234]: Failed password for <img src=x onerror=alert(1)> from 1.2.3.4` | HTML entities sanitized; no image element or onerror trigger | Verified. String rendered as literal text without DOM mutation. | **PASS** |
| **SEC-03** | Prototype / Object Pollution | `{"__proto__": {"isAdmin": true}, "severity": "LOW"}` | Parsed safely as text string without modifying prototype chain | Verified. Zero prototype pollution. | **PASS** |
| **SEC-04** | Null Byte & Unicode Injection | `GET /file.php%00.jpg HTTP/1.1 200 \u0000\u001b[31m` | Clean normalization without regex engine crash or state freeze | Verified. Regex executed stably without runtime exceptions. | **PASS** |
| **SEC-05** | Network Isolation & CSP Leak Check | Ingestion of external URL callbacks: `http://attacker-canary.internal/beacon` | Zero outbound HTTP/WebSocket requests initiated by the browser client | Network tab verified 0 outbound requests (`connect-src 'none'`). | **PASS** |

---

## 4. Simulated Attack Scenario Evaluations

### Scenario 1: SSH Brute-Force & Unauthorized Privileged Execution
- **Attack Chain:** 5 rapid failed authentication attempts for `admin`, `root`, `postgres`, followed by successful authentication for `root` from IP `198.51.100.45`, followed by root execution of a curl-to-bash downloader.
- **Detections Triggered:**
  - `RULE_SSH_AUTH_FAIL` (Severity: `MEDIUM`, MITRE: `T1110.001`)
  - `RULE_SSH_SUCCESS_AFTER_ROOT` (Severity: `HIGH`, MITRE: `T1078.003`)
  - `RULE_CMD_INJECT_C2` (Severity: `CRITICAL`, MITRE: `T1059.004 / T1105`)
- **Triage Result:** Correctly flagged as **CRITICAL**. Remediation playbook immediately surfaced host network isolation, active shell PID termination, and egress blocking on `185.220.101.5`.

### Scenario 2: Web Reconnaissance, Path Traversal & SQL Injection
- **Attack Chain:** Probing for sensitive endpoints (`/.env`, `wp-config.php.bak`) via scanner, followed by `sqlmap` parameter fuzzing (`' OR '1'='1`) and local file inclusion targeting `/etc/passwd`.
- **Detections Triggered:**
  - `RULE_ENV_LEAK` (Severity: `HIGH`, MITRE: `T1552.001`)
  - `RULE_SQLI_BASIC` (Severity: `HIGH`, MITRE: `T1190`)
  - `RULE_PATH_TRAVERSAL_PASSWD` (Severity: `CRITICAL`, MITRE: `T1083 / T1005`)
- **Triage Result:** Correctly prioritized path traversal attempt; highlighted IP `203.0.113.88` in the active IoC list with 3 high/critical alerts.

### Scenario 3: Perimeter Reconnaissance & Outbound Reverse Shell Beaconing
- **Attack Chain:** Sequential TCP SYN drops across ports 22, 80, 443, 3389, and 8080 from scanner IP `45.33.32.156`, followed by outbound established connections from internal host `10.0.0.50` to external IP `185.220.101.5` on port `4444`.
- **Detections Triggered:**
  - `RULE_PORT_SCAN_DROPS` (Severity: `LOW`, MITRE: `T1046`)
  - `RULE_SUSPICIOUS_OUTBOUND_PORT` (Severity: `HIGH`, MITRE: `T1071.001 / T1571`)
- **Triage Result:** Effectively differentiated low-priority ingress scan noise from high-priority outbound reverse shell beaconing.

---

## 5. Functional & Export Verification Matrix

| Test Case | Description | Test Procedure | Outcome | Result |
| :--- | :--- | :--- | :--- | :---: |
| **TC-FN-01** | Preset Switching | Click "Auth.log", "WAF/Nginx", "Iptables", and "Mixed" presets | Log textarea and metrics refresh instantly with corresponding scenario | **PASS** |
| **TC-FN-02** | Custom File Ingestion | Drag and drop a local `.log` file into the upload zone | File reader ingests and triggers full parsing pipeline | **PASS** |
| **TC-FN-03** | Severity Filtering | Click filter chips (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `ALL`) | Table renders only events matching the selected severity level | **PASS** |
| **TC-FN-04** | Substring Search | Enter IP `198.51.100.45` into search box | Real-time table filters to matching IP across all fields | **PASS** |
| **TC-FN-05** | Deep Triage Modal | Click "Triage &rarr;" or row on event `RULE_CMD_INJECT_C2` | Modal opens displaying full normalized metadata and remediation steps | **PASS** |
| **TC-FN-06** | Markdown Report Export | Click "Export .MD" | Formatted `.md` triage report downloads with table and playbooks | **PASS** |
| **TC-FN-07** | JSON Data Export | Click "Export .JSON" | Valid JSON file downloads containing metadata and event array | **PASS** |
| **TC-FN-08** | CSV Data Export | Click "Export .CSV" | Formatted CSV file downloads with properly escaped quotation marks | **PASS** |

---

## 6. Performance & Throughput Benchmarks

Tested on a standard development workstation (8-core Intel Core i7, 16 GB RAM, Google Chrome 128):

- **Single Line Parsing Latency:** ~0.08 ms / line
- **Batch Processing Rate:** ~12,500 lines / second
- **Memory Consumption:**
  - Baseline UI Heap: 14.2 MB
  - Ingested 1,000 Event Stream Heap: 18.6 MB
  - Delta: +4.4 MB (Minimal overhead, no memory leaks detected upon clear)
- **Export Generation Time:** < 45 ms for 500 events

---

## 7. QA Sign-Off & Verdict

All functional criteria, security boundaries, and defensive detection scenarios set forth in **Module 06 of the Codomax Cybersecurity & Ethical Hacking Virtual Internship** have been met without defects or open vulnerabilities.

**Sign-off:**  
Ayan Mondal — *Lead Cybersecurity Engineer & Capstone Architect*  
*Date of Sign-off:* November 2026

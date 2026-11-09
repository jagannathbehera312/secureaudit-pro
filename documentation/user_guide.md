# SecureAudit Pro - User Guide & Walkthrough

Welcome to SecureAudit Pro. Follow this step-by-step walkthrough to perform your first automated vulnerability assessment.

---

## 1. Logging In

1. Open the application interface in your browser (e.g. `http://localhost:3000` or deployed URL).
2. Choose a pre-seeded analyst or administrator persona using the **1-Click Demo Sign-In** pills on the login screen, or enter credentials:
   - **Security Analyst:** `analyst@secureaudit.pro` / `Analyst@SecureAudit2026!`
   - **Super Administrator:** `admin@secureaudit.pro` / `Admin@SecureAudit2026!`
   - **Organization Admin:** `orgadmin@secureaudit.pro` / `OrgAdmin@SecureAudit2026!`
   - **Auditor:** `auditor@secureaudit.pro` / `Auditor@SecureAudit2026!`
3. Click **Authenticate & Sign In**.

---

## 2. Registering & Verifying a Target Website

1. Navigate to **Websites & Assets** from the left navigation bar.
2. Click **Register New Target**.
3. Fill in the website name, URL (e.g., `https://banking.apexfintech.internal`), environment, and business criticality rating.
4. Click **Confirm & Register Target**.
5. On the registered card, click **Verify Ownership**.
   - For public domain verification: Add the displayed DNS TXT record or upload the challenge file.
   - For development / internal testing: Select **Admin Override** to certify internal scope authorization.

---

## 3. Configuring and Launching a Scan

1. Click **Launch Scan** on the sidebar or top navbar.
2. **Step 1:** Select your verified target asset.
3. **Step 2:** Choose a scan profile:
   - *Quick Scan:* HTTP headers, SSL/TLS, cookies, technology detection.
   - *Standard Scan:* Recommended standard VAPT with OWASP Top 10, CORS, and exposed resources.
   - *Comprehensive Scan:* Deep crawl, injection testing, and multi-engine inspection.
4. **Step 3:** Configure request limits (rate limit, crawl depth, custom headers).
5. **Step 4:** Review the safety parameters and check the **Authorization Declaration** box.
6. Click **Launch Security Assessment**.

---

## 4. Monitoring Live Execution

1. The scan details view displays the **15-Stage Progressive Timeline**.
2. Observe live progress percentages and timestamped log lines in the **Live Stage Execution Log**.
3. As vulnerabilities are discovered in real time, they populate the **Discovered Findings Feed**.
4. Use the **Stop Scan** button if you need to abort execution at any time.

---

## 5. Reviewing Vulnerabilities & Managing Remediation

1. Go to **Vulnerabilities** to view all detected findings with severity badges.
2. Click on any finding to open its full detail drawer:
   - Inspect the **Technical Trace & Evidence** box.
   - Review **Impact Analysis** and **Remediation Guidance**.
   - Update finding status (e.g. `In Progress` or `Fixed`).
   - Add analyst notes in the discussion thread.
   - Click **Assign Task** to create a ticket in the **Remediation** module with an assignee and deadline.

---

## 6. Comparing Scans & Generating Reports

1. Navigate to **Scan Comparison**:
   - Select Baseline Scan A and Comparison Scan B.
   - Review newly detected defects, resolved findings, and posture score changes.
2. Navigate to **Security Reports**:
   - Click **Generate New Report**.
   - Select PDF, HTML, JSON, or CSV format.
   - Download the generated document for executive stakeholders or compliance audits.

# SecureAudit Pro - Jenkins CI/CD & Automated Webhook Testing Guide

This guide details the complete end-to-end setup to automatically execute **Unit Tests**, **REST API Integration Tests**, and **Frontend Production Builds** via a **Jenkins Pipeline** triggered automatically on every `git push` via a **Git Webhook**.

---

## 1. Architecture Overview

```
Developer / Contributor
         │
         │  git push origin main
         ▼
┌──────────────────┐               HTTP POST Webhook
│  GitHub / GitLab ├─────────────────────────────────────────────┐
└──────────────────┘  (payload: commit SHA, branch, author)       │
                                                                 ▼
                                                  ┌──────────────────────────────┐
                                                  │       Jenkins Master         │
                                                  │  /github-webhook/ listener   │
                                                  └──────────────┬───────────────┘
                                                                 │ Triggers Pipeline
                                                                 ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                           Jenkinsfile Pipeline Run                             │
├────────────────────────────────────────────────────────────────────────────────┤
│ 1. Checkout SCM           : Pulls latest commit SHA                            │
│ 2. Backend Linting        : Flake8 syntax & static analysis                    │
│ 3. Unit & REST API Tests  : Pytest (14+ tests) with JUnit XML & Coverage report│
│ 4. Frontend Verification  : TypeScript compilation (tsc) & Vite production build│
│ 5. Security & SAST Audit  : Bandit static security scanner                     │
│ 6. Reporting & Telemetry  : Publishes JUnit test trends & Cobertura coverage   │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Running Tests Locally

Before pushing changes to Git, verify that all unit and API tests pass on your machine:

### Backend Unit & REST API Tests
```bash
# Navigate to backend directory
cd backend

# Execute full pytest suite with verbose output
pytest -v

# Execute with JUnit XML and Code Coverage report generation
pytest -v \
  --junitxml=test-reports/junit.xml \
  --cov=apps --cov=core \
  --cov-report=xml:test-reports/coverage.xml \
  --cov-report=term
```

### Frontend TypeScript & Vite Build Verification
```bash
# Navigate to frontend directory
cd frontend

# Verify TypeScript compilation and production bundle build
npm run build
```

---

## 3. Jenkins Server Prerequisites & Plugins

Ensure your Jenkins instance has the following installed:

### Required System Tools on Jenkins Controller / Agent
* **Python 3.10+ / 3.11** (with `python3-venv` and `pip`)
* **Node.js 18+ / 20+** (with `npm`)
* **Git CLI**

### Required Jenkins Plugins
Go to **Manage Jenkins** → **Plugins** → **Available Plugins**, and install:
1. **GitHub Integration Plugin** (or **GitLab Plugin**)
2. **Pipeline** (Workflow Aggregator)
3. **JUnit Plugin** (renders test trend graphs directly in Jenkins UI)
4. **Cobertura Plugin** or **Coverage Plugin** (renders code coverage charts)
5. **AnsiColor Plugin** (renders terminal ANSI colors in build logs)

---

## 4. Configuring the Jenkins Pipeline Job

### Step 1: Create a New Pipeline Job
1. In the Jenkins Dashboard, click **New Item**.
2. Enter item name: `SecureAudit-Pro-CI`.
3. Select **Pipeline** (or **Multibranch Pipeline** if you manage multiple branches).
4. Click **OK**.

### Step 2: Configure Build Triggers
In the job configuration page, navigate to **Build Triggers**:
* Check **GitHub hook trigger for GITScm polling**.

### Step 3: Configure Pipeline SCM
In the **Pipeline** section:
1. Set **Definition**: `Pipeline script from SCM`.
2. Set **SCM**: `Git`.
3. Set **Repository URL**: `https://github.com/<your-org>/secureaudit-pro.git` (or your repository URL).
4. Set **Credentials**: Select your Git SSH key or Personal Access Token (PAT).
5. Set **Branches to build**: `*/main` (or `*/master`).
6. Set **Script Path**: `Jenkinsfile`.
7. Click **Save**.

---

## 5. Configuring the Git Webhook (GitHub / GitLab)

### Setting up Webhook in GitHub
1. Open your repository on GitHub.
2. Go to **Settings** → **Webhooks** → Click **Add webhook**.
3. Configure the webhook fields:
   * **Payload URL**:
     ```
     http://<YOUR_JENKINS_SERVER_IP_OR_DOMAIN>:8080/github-webhook/
     ```
     *(Note: The trailing slash `/` is required by Jenkins).*
   * **Content type**: Select `application/json`.
   * **Secret**: (Optional, if configured in Jenkins Global Configuration).
   * **Which events would you like to trigger this webhook?**:
     * Select **Just the push event** (or **Let me select individual events** → check `Pushes` and `Pull requests`).
   * **Active**: Ensure checkbox is checked.
4. Click **Add webhook**.
5. GitHub will immediately send a `ping` event. A green checkmark (✔ HTTP 200) indicates Jenkins successfully received the webhook.

### Testing Locally or Behind a Firewall (Localhost / NAT)
If your Jenkins server is on `localhost:8080` without a public IP, use **ngrok** or **smee.io** to forward webhooks:

```bash
# Expose local Jenkins port 8080 publicly via ngrok
ngrok http 8080
```
Use the generated public URL in your GitHub Webhook:
`https://<your-ngrok-id>.ngrok-free.app/github-webhook/`

---

## 6. Testing the Pipeline & Webhook Trigger

### Step 1: Push a Commit to Trigger the Build
Run the following in your terminal:
```bash
git add .
git commit -m "feat(ci): add automated testing pipeline and webhook trigger"
git push origin main
```

### Step 2: Observe Jenkins Auto-Execution
1. Open your Jenkins job `SecureAudit-Pro-CI`.
2. Within seconds of the `git push`, a new build will automatically be triggered under **Build History**.
3. Click on the active build → **Console Output** to monitor the live stages:
   * `Checkout & SCM Info`
   * `Backend Dependencies & Linting`
   * `Backend Unit & REST API Tests` (Running 14+ test cases)
   * `Frontend Build & Verification` (Compiling 2,500+ modules)
   * `Security & SAST Verification`
   * `Publish Test Results`

### Step 3: Inspect Test Reports
* **Test Result**: Click **Test Result** in the left sidebar to see all passed test cases, execution timings, and error traces.
* **Coverage Report**: View method and line coverage percentages across all Django apps and security engines.

---

## 7. Troubleshooting Common Issues

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **GitHub Webhook returns 403 Forbidden** | Jenkins CSRF / Crumb protection blocking external requests | Ensure the GitHub plugin is installed and use the `/github-webhook/` path (do not use generic URL without authentication). |
| **GitHub Webhook returns 404 Not Found** | Missing trailing slash or plugin not loaded | Use `http://<domain>:8080/github-webhook/` with the trailing slash. |
| **Jenkins doesn't trigger on Push** | Jenkins SCM polling not configured | Ensure "GitHub hook trigger for GITScm polling" is checked in Job configuration. |
| **`pytest` not found in Jenkins Agent** | Virtual environment not active | The pipeline automatically creates and activates `venv` using `. venv/bin/activate` or `call venv\Scripts\activate`. |
| **Database Connection Refused during Test** | MongoDB daemon not running on CI agent | The test suite automatically falls back to in-memory `mongomock` via `USE_MOCK_DB=true`. |

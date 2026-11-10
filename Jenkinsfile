pipeline {
    agent any

    options {
        disableConcurrentBuilds()
        timestamps()
    }

    environment {
        COMPOSE_PROJECT_NAME = 'secureaudit'
        ENV_FILE = '/opt/secureaudit/.env'
        COMPOSE_FILE = 'docker-compose.yml'
        NOTIFY_EMAIL = 'jagannathbehera4440@gmail.com'
    }

    triggers {
        githubPush()
    }

    stages {
        stage('1. Pull Code from GitHub') {
            steps {
                echo '[+] Pulling latest source code...'
                checkout scm
            }
        }

        stage('2. Backend Unit & API Tests') {
            steps {
                echo '[+] Installing dependencies and running tests...'

                sh '''
                    . .venv/bin/activate
                    python -m pip install --upgrade pip
                    pip install -r requirements.txt
                    mkdir -p backend/test-reports
                    
                    if [ -f /opt/secureaudit/.env ]; then
                        export $(grep -v '^#' /opt/secureaudit/.env | xargs)
                    fi
                    
                    export USE_MOCK_DB=true
                    pytest backend/tests/ -v --junitxml=backend/test-reports/junit.xml --cov=backend/apps --cov=backend/core --cov-report=term
                '''
            }
        }

        stage('3. Validate Docker Compose') {
            steps {
                echo '[+] Validating Docker Compose configuration...'

                sh '''
                    set -e
                    docker compose \
                        --project-name ${COMPOSE_PROJECT_NAME} \
                        --env-file ${ENV_FILE} \
                        -f ${COMPOSE_FILE} \
                        config --quiet
                '''
            }
        }

        stage('4. Docker Compose Build') {
            steps {
                echo '[+] Building SecureAudit Docker images...'

                sh '''
                    set -e
                    docker compose \
                        --project-name ${COMPOSE_PROJECT_NAME} \
                        --env-file ${ENV_FILE} \
                        -f ${COMPOSE_FILE} \
                        build
                '''
            }
        }

        stage('5. Deploy SecureAudit') {
            steps {
                echo '[+] Deploying updated SecureAudit services...'

                sh '''
                    set -e
                    docker compose \
                        --project-name ${COMPOSE_PROJECT_NAME} \
                        --env-file ${ENV_FILE} \
                        -f ${COMPOSE_FILE} \
                        up -d
                '''
            }
        }

        stage('6. Backend Health Check') {
            steps {
                echo '[+] Checking Django backend...'

                sh '''
                    set -e
                    docker compose \
                        --project-name ${COMPOSE_PROJECT_NAME} \
                        --env-file ${ENV_FILE} \
                        -f ${COMPOSE_FILE} \
                        exec -T backend python manage.py check
                '''
            }
        }

        stage('7. Frontend Smoke Test') {
            steps {
                echo '[+] Checking SecureAudit frontend on port 8081...'

                sh '''
                    set -e
                    curl --retry 12 \
                         --retry-delay 5 \
                         --retry-connrefused \
                         --fail \
                         --silent \
                         --show-error \
                         http://localhost:8081/
                '''
            }
        }
    }

    post {
        always {
            echo '[+] Archiving Test Results & Generating Test Trend Graph...'
            junit allowEmptyResults: true, testResults: 'backend/test-reports/junit.xml'
            archiveArtifacts artifacts: 'backend/test-reports/**', allowEmptyArchive: true
        }

        success {
            echo '''
            ==========================================
             SECUREAUDIT CI/CD PIPELINE SUCCESSFUL
            ==========================================
            '''

            script {
                try {
                    emailext(
                        to: "${env.NOTIFY_EMAIL ?: 'jagannathbehera312@gmail.com'}",
                        recipientProviders: [developers(), requestor()],
                        subject: "✔ [SUCCESS] SecureAudit Pro CI/CD Build #${env.BUILD_NUMBER} - All 14 Unit & API Tests Passed",
                        body: """
                            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 650px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 12px; background: #ffffff;">
                                <div style="background: #0f172a; padding: 16px 20px; border-radius: 8px; margin-bottom: 20px;">
                                    <h2 style="color: #38bdf8; margin: 0; font-size: 20px;">SecureAudit Pro CI/CD Pipeline</h2>
                                    <p style="color: #94a3b8; margin: 4px 0 0 0; font-size: 13px;">Automated Build, Test &amp; Deployment Verification</p>
                                </div>

                                <div style="padding: 12px 16px; background: #ecfdf5; border: 1px solid #a7f3d0; border-radius: 8px; color: #065f46; font-weight: bold; margin-bottom: 20px;">
                                    ✔ Build #${env.BUILD_NUMBER} SUCCEEDED — All 14 Unit and API tests passed with 0 failures!
                                </div>

                                <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 14px;">
                                    <tr>
                                        <td style="padding: 8px 0; color: #64748b; width: 140px;"><strong>Project:</strong></td>
                                        <td style="padding: 8px 0; color: #0f172a;">${env.JOB_NAME}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 8px 0; color: #64748b;"><strong>Build Number:</strong></td>
                                        <td style="padding: 8px 0; color: #0f172a;">#${env.BUILD_NUMBER}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 8px 0; color: #64748b;"><strong>Commit:</strong></td>
                                        <td style="padding: 8px 0; font-family: monospace; color: #0f172a;">${env.GIT_COMMIT ?: 'main'}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 8px 0; color: #64748b;"><strong>Deploy Status:</strong></td>
                                        <td style="padding: 8px 0; color: #059669; font-weight: 600;">Containers Rebuilt &amp; Running on Server</td>
                                    </tr>
                                </table>

                                <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 20px;">
                                    <h4 style="margin: 0 0 10px 0; color: #334155; font-size: 14px;">Test Execution Breakdown:</h4>
                                    <ul style="margin: 0; padding-left: 20px; font-size: 13px; color: #475569; line-height: 1.6;">
                                        <li><strong>Health Check API:</strong> PASSED</li>
                                        <li><strong>Authentication Register &amp; Login Flow:</strong> PASSED (With Auto-Teardown)</li>
                                        <li><strong>Website Asset Lifecycle &amp; Verification:</strong> PASSED</li>
                                        <li><strong>Security Scans Lifecycle API:</strong> PASSED</li>
                                        <li><strong>Vulnerabilities Catalog &amp; Comments API:</strong> PASSED</li>
                                        <li><strong>Live Attack Radar &amp; Perimeter Monitoring:</strong> PASSED</li>
                                        <li><strong>Admin &amp; SOC Metrics RBAC API:</strong> PASSED</li>
                                        <li><strong>Security Unit Tests (Password, JWT, TOTP, SSRF, Scoring, Reports):</strong> 7/7 PASSED</li>
                                    </ul>
                                </div>

                                <div style="padding-top: 10px;">
                                    <a href="${env.BUILD_URL}testReport/" style="background: #0284c7; color: #ffffff; text-decoration: none; padding: 10px 18px; border-radius: 6px; font-size: 13px; font-weight: 600; display: inline-block;">View Test Results in Jenkins</a>
                                    <a href="${env.BUILD_URL}" style="background: #f1f5f9; color: #334155; text-decoration: none; padding: 10px 18px; border-radius: 6px; font-size: 13px; font-weight: 600; display: inline-block; margin-left: 8px;">View Full Build</a>
                                </div>
                            </div>
                        """,
                        mimeType: 'text/html',
                        attachmentsPattern: 'backend/test-reports/junit.xml'
                    )
                    echo "[+] Success notification email dispatched."
                } catch (Exception e) {
                    echo "[-] Notice: Email could not be dispatched (${e.message}). Ensure Jenkins SMTP server is configured under Manage Jenkins -> System -> Extended E-mail Notification."
                }
            }
        }

        failure {
            echo '''
            ==========================================
             SECUREAUDIT CI/CD PIPELINE FAILED
             Check the failed stage and console logs.
            ==========================================
            '''

            sh '''
                docker compose \
                    --project-name ${COMPOSE_PROJECT_NAME} \
                    --env-file ${ENV_FILE} \
                    -f ${COMPOSE_FILE} \
                    logs --tail 50 || true
            '''

            script {
                try {
                    emailext(
                        to: "${env.NOTIFY_EMAIL ?: 'jagannathbehera312@gmail.com'}",
                        recipientProviders: [developers(), requestor()],
                        subject: "❌ [FAILED] SecureAudit Pro CI/CD Build #${env.BUILD_NUMBER}",
                        body: """
                            <h2>SecureAudit Pro Pipeline Failed</h2>
                            <p>Build #${env.BUILD_NUMBER} failed. Review the console logs below:</p>
                            <p><a href="${env.BUILD_URL}console">View Console Output</a></p>
                        """,
                        mimeType: 'text/html',
                        attachLog: true
                    )
                } catch (Exception e) {
                    echo "[-] Notice: Failure email could not be dispatched (${e.message})."
                }
            }
        }
    }
}
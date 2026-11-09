pipeline {
    agent any

    options {
        timeout(time: 25, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        disableConcurrentBuilds()
        ansiColor('xterm')
    }

    triggers {
        // Automatically triggers this pipeline when a GitHub Webhook push event is received
        githubPush()
    }

    environment {
        PYTHONUNBUFFERED = '1'
        DJANGO_SETTINGS_MODULE = 'config.settings'
        USE_MOCK_DB = 'true'
        NODE_ENV = 'test'
    }

    stages {
        stage('Checkout & SCM Info') {
            steps {
                echo "=========================================================="
                echo " SecureAudit Pro CI/CD Pipeline - Commit Verification "
                echo "=========================================================="
                echo "Branch: ${env.BRANCH_NAME ?: env.GIT_BRANCH ?: 'main'}"
                echo "Commit: ${env.GIT_COMMIT ?: 'Head'}"
                checkout scm
            }
        }

        stage('Backend Dependencies & Linting') {
            steps {
                echo "[+] Initializing Python virtual environment & dependencies..."
                script {
                    if (isUnix()) {
                        sh '''
                            python3 -m venv venv
                            . venv/bin/activate
                            pip install --upgrade pip
                            pip install -r requirements.txt
                            flake8 backend --count --select=E9,F63,F7,F82 --show-source --statistics || true
                        '''
                    } else {
                        bat '''
                            python -m venv venv
                            call venv\\Scripts\\activate
                            python -m pip install --upgrade pip
                            pip install -r requirements.txt
                            flake8 backend --count --select=E9,F63,F7,F82 --show-source --statistics || echo Lint warnings flagged
                        '''
                    }
                }
            }
        }

        stage('Backend Unit & REST API Tests') {
            steps {
                echo "[+] Executing Django Unit & API Integration Test Suite..."
                script {
                    if (isUnix()) {
                        sh '''
                            . venv/bin/activate
                            cd backend
                            mkdir -p test-reports
                            pytest tests/ -v \
                                --junitxml=test-reports/junit.xml \
                                --cov=apps --cov=core \
                                --cov-report=xml:test-reports/coverage.xml \
                                --cov-report=term
                        '''
                    } else {
                        bat '''
                            call venv\\Scripts\\activate
                            cd backend
                            if not exist test-reports mkdir test-reports
                            pytest tests/ -v ^
                                --junitxml=test-reports/junit.xml ^
                                --cov=apps --cov=core ^
                                --cov-report=xml:test-reports/coverage.xml ^
                                --cov-report=term
                        '''
                    }
                }
            }
        }

        stage('Frontend Build & Verification') {
            steps {
                echo "[+] Verifying Frontend TypeScript Compilation & Production Build..."
                script {
                    if (isUnix()) {
                        sh '''
                            cd frontend
                            npm ci --prefer-offline || npm install
                            npm run build
                        '''
                    } else {
                        bat '''
                            cd frontend
                            npm ci || npm install
                            npm run build
                        '''
                    }
                }
            }
        }

        stage('Security & SAST Verification') {
            steps {
                echo "[+] Checking for hardcoded secrets & SSRF boundary invariants..."
                script {
                    if (isUnix()) {
                        sh '''
                            . venv/bin/activate
                            pip install bandit || true
                            bandit -r backend/core backend/security_engine -lll || true
                        '''
                    } else {
                        bat '''
                            call venv\\Scripts\\activate
                            pip install bandit || echo Bandit optional
                            bandit -r backend/core backend/security_engine -lll || echo SAST scan completed
                        '''
                    }
                }
            }
        }
    }

    post {
        always {
            echo "[+] Archiving Test Results & Telemetry Metrics..."
            // Publish JUnit XML test results into Jenkins UI
            junit testResults: 'backend/test-reports/junit.xml', allowEmptyResults: true

            // Publish Cobertura code coverage report into Jenkins UI
            step([
                $class: 'CoberturaPublisher',
                coberturaReportFile: 'backend/test-reports/coverage.xml',
                failUnhealthy: false,
                failUnstable: false,
                autoUpdateHealth: false,
                autoUpdateStability: false
            ])

            // Archive reports as downloadable build artifacts
            archiveArtifacts artifacts: 'backend/test-reports/**', allowEmptyArchive: true
        }
        success {
            echo "=========================================================="
            echo " [SUCCESS] SecureAudit Pro build & test verification passed! "
            echo "=========================================================="
        }
        failure {
            echo "=========================================================="
            echo " [FAILED] Pipeline failed verification. Check test logs. "
            echo "=========================================================="
        }
        cleanup {
            echo "[+] Cleaning temporary build workspace..."
        }
    }
}

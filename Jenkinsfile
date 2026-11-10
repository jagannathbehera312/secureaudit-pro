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
                    
                    pytest backend/tests/ -v --junitxml=backend/test-reports/junit.xml --cov=backend/apps --cov=backend/core --cov-report=term
                '''
            }

            post {
                always {
                    junit allowEmptyResults: true,
                          testResults: 'backend/test-reports/junit.xml'
                }
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
            echo '[+] Pipeline execution completed.'
        }

        success {
            echo '''
            ==========================================
             SECUREAUDIT CI/CD PIPELINE SUCCESSFUL
            ==========================================
            '''
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
        }
    }
}
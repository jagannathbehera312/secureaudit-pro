# SecureAudit Pro - Deployment Guide

This guide covers deployment procedures for Docker Compose and bare-metal Ubuntu Server environments.

---

## 1. Quick Start with Docker Compose

Ensure Docker and Docker Compose are installed on your target host.

```bash
# Clone the repository
git clone https://github.com/organization/secureaudit-pro.git
cd secureaudit-pro

# Configure environment variables
cp .env.example .env
# Edit .env with your production secrets:
nano .env

# Build and start all 8 services in background
docker compose up -d --build

# Verify all containers are healthy
docker compose ps
```

The application will be accessible at `http://<your-server-ip>` or domain name on port 80.

---

## 2. Production Ubuntu Server Deployment (Bare Metal / VM)

### Step 1: System Package Prerequisites

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y python3.11 python3.11-venv python3-pip nodejs npm redis-server mongodb-org nginx curl dnsutils
```

### Step 2: Backend Setup

```bash
cd /opt/secureaudit-pro/backend
python3.11 -m venv venv
source venv/bin/activate
pip install -r ../requirements.txt

# Run system checks and verification tests
python manage.py check
pytest tests/test_platform.py -v
```

### Step 3: Configure Systemd Services

Create `/etc/systemd/system/secureaudit-backend.service`:

```ini
[Unit]
Description=SecureAudit Pro Gunicorn Backend
After=network.target mongodb.service redis.service

[Service]
User=www-data
WorkingDirectory=/opt/secureaudit-pro/backend
ExecStart=/opt/secureaudit-pro/backend/venv/bin/gunicorn config.wsgi:application --bind 127.0.0.1:8000 --workers 4 --timeout 120
Restart=always

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/secureaudit-celery.service`:

```ini
[Unit]
Description=SecureAudit Pro Celery Worker
After=network.target redis.service

[Service]
User=www-data
WorkingDirectory=/opt/secureaudit-pro/backend
ExecStart=/opt/secureaudit-pro/backend/venv/bin/celery -A config worker --loglevel=info --concurrency=4
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now secureaudit-backend secureaudit-celery
```

### Step 4: Frontend Build & Nginx Configuration

```bash
cd /opt/secureaudit-pro/frontend
npm install
npm run build
sudo cp -r dist/* /var/www/secureaudit-pro/
```

Configure Nginx `/etc/nginx/sites-available/secureaudit-pro`:

```nginx
server {
    listen 80;
    server_name vapt.yourdomain.com;

    location / {
        root /var/www/secureaudit-pro;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable site and configure SSL with Let's Encrypt Certbot:

```bash
sudo ln -s /etc/nginx/sites-available/secureaudit-pro /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d vapt.yourdomain.com
```

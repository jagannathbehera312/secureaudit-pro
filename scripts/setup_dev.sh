#!/usr/bin/env bash
# SecureAudit Pro - Ubuntu / Linux Setup Script
set -e

echo "=========================================="
echo " SecureAudit Pro - Ubuntu / Linux Setup"
echo "=========================================="

echo "[1/4] Installing system packages..."
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv nodejs npm curl dnsutils ca-certificates

echo "[2/4] Setting up Python virtual environment..."
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r ../requirements.txt

echo "[3/4] Validating Django backend..."
python manage.py check
pytest tests/test_platform.py -v

echo "[4/4] Setting up React Frontend..."
cd ../frontend
npm install
npm run build

echo "=========================================="
echo " Setup Finished Successfully!"
echo " Start backend: cd backend && source venv/bin/activate && python manage.py runserver 0.0.0.0:8000"
echo " Start frontend: cd frontend && npm run dev"
echo "=========================================="

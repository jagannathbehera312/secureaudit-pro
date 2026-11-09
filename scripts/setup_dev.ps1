# SecureAudit Pro - Windows Development Environment Setup Script

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " SecureAudit Pro - Local Development Setup" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Setup Backend
Write-Host "`n[1/3] Checking Backend Python Environment..." -ForegroundColor Yellow
cd backend
python manage.py check
if ($LASTEXITCODE -ne 0) {
    Write-Host "Django check failed. Ensure dependencies in requirements.txt are installed." -ForegroundColor Red
} else {
    Write-Host "Backend system checks passed successfully!" -ForegroundColor Green
}

# 2. Run Tests
Write-Host "`n[2/3] Running Backend Verification Tests..." -ForegroundColor Yellow
pytest tests/test_platform.py -v

# 3. Setup Frontend
Write-Host "`n[3/3] Building Frontend UI..." -ForegroundColor Yellow
cd ..\frontend
npm run build
if ($LASTEXITCODE -eq 0) {
    Write-Host "Frontend compiled successfully!" -ForegroundColor Green
}

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " Setup Complete!" -ForegroundColor Green
Write-Host " To start backend: cd backend; python manage.py runserver 8000"
Write-Host " To start frontend: cd frontend; npm run dev"
Write-Host "==========================================" -ForegroundColor Cyan

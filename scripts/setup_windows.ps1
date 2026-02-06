# Cereberus Setup Script for Windows
# Run as Administrator for full functionality

param(
    [switch]$SkipVenv,
    [switch]$Dev
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════╗" -ForegroundColor DarkRed
Write-Host "  ║         CEREBERUS SETUP               ║" -ForegroundColor DarkRed
Write-Host "  ║   AI-Powered Cybersecurity Defense     ║" -ForegroundColor DarkRed
Write-Host "  ╚═══════════════════════════════════════╝" -ForegroundColor DarkRed
Write-Host ""

# Check Python version
Write-Host "[*] Checking Python version..." -ForegroundColor Cyan
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Python not found. Install Python 3.11+ first." -ForegroundColor Red
    exit 1
}
Write-Host "    Found: $pythonVersion" -ForegroundColor Green

# Create virtual environment
if (-not $SkipVenv) {
    Write-Host "[*] Creating virtual environment..." -ForegroundColor Cyan
    if (-not (Test-Path "venv")) {
        python -m venv venv
    }

    # Activate venv
    Write-Host "[*] Activating virtual environment..." -ForegroundColor Cyan
    & .\venv\Scripts\Activate.ps1
}

# Install dependencies
Write-Host "[*] Installing Python dependencies..." -ForegroundColor Cyan
if ($Dev) {
    pip install -r requirements-dev.txt
} else {
    pip install -r requirements.txt
}

# Create .env if not exists
if (-not (Test-Path ".env")) {
    Write-Host "[*] Creating .env from template..." -ForegroundColor Cyan
    Copy-Item .env.example .env

    # Generate a secret key
    $secretKey = python -c "import secrets; print(secrets.token_urlsafe(64))"
    (Get-Content .env) -replace 'changeme_generate_a_real_secret_key', $secretKey | Set-Content .env
    Write-Host "    Secret key generated." -ForegroundColor Green
} else {
    Write-Host "[*] .env already exists, skipping." -ForegroundColor Yellow
}

# Create models directory
if (-not (Test-Path "models")) {
    New-Item -ItemType Directory -Path "models" | Out-Null
}

# Setup frontend
Write-Host "[*] Setting up frontend..." -ForegroundColor Cyan
if (Get-Command npm -ErrorAction SilentlyContinue) {
    Push-Location frontend
    npm install
    Pop-Location
    Write-Host "    Frontend dependencies installed." -ForegroundColor Green
} else {
    Write-Host "[!] npm not found. Install Node.js to set up the frontend." -ForegroundColor Yellow
}

# Check admin privileges for VPN features
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ""
    Write-Host "[!] Not running as Administrator." -ForegroundColor Yellow
    Write-Host "    VPN kill switch and DNS remediation require admin privileges." -ForegroundColor Yellow
    Write-Host "    Re-run this script as Administrator for full functionality." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[+] Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  To start the backend:" -ForegroundColor Cyan
Write-Host "    python -m backend.main" -ForegroundColor White
Write-Host ""
Write-Host "  To start the frontend:" -ForegroundColor Cyan
Write-Host "    cd frontend && npm run dev" -ForegroundColor White
Write-Host ""
Write-Host "  API docs:" -ForegroundColor Cyan
Write-Host "    http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host ""

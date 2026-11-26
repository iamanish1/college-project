<#
.SYNOPSIS
    One-command start for Mini Guardrail on Windows.

.DESCRIPTION
    1. Finds Python 3.10+
    2. Creates the .venv virtual environment (first run only)
    3. Installs or updates dependencies (only when pyproject.toml changed)
    4. Runs the test suite
    5. Starts the API server and opens the playground in the browser

    Normally run through start.bat, which handles the PowerShell execution policy.

.EXAMPLE
    .\start.bat
    .\start.bat -Port 8080 -SkipTests -NoBrowser
#>
param(
    [int]$Port = 8000,
    [switch]$SkipTests,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Write-Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Stop-WithError([string]$Message) {
    Write-Host "`nERROR: $Message" -ForegroundColor Red
    exit 1
}

function Find-Python {
    # Each candidate is a command plus its leading arguments.
    foreach ($candidate in @(@('py', '-3'), @('python'), @('python3'))) {
        $exe = $candidate[0]
        $pyArgs = @($candidate | Select-Object -Skip 1)
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        try {
            & $exe @pyArgs -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
        } catch { continue }
        if ($LASTEXITCODE -eq 0) { return , $candidate }
    }
    return $null
}

$venvPy = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
$url = "http://127.0.0.1:$Port"

# 1-2. Virtual environment --------------------------------------------------
if (-not (Test-Path $venvPy)) {
    Write-Step 'Creating virtual environment (.venv)'
    $py = Find-Python
    if (-not $py) {
        Stop-WithError 'Python 3.10 or newer was not found. Install it from https://www.python.org/downloads/ (tick "Add python.exe to PATH") and run this again.'
    }
    & $py[0] @($py | Select-Object -Skip 1) -m venv .venv
    if ($LASTEXITCODE -ne 0) { Stop-WithError 'Could not create the virtual environment.' }
}

# 3. Dependencies -----------------------------------------------------------
$hashFile = Join-Path $PSScriptRoot '.venv\.installed-hash'
$currentHash = (Get-FileHash -Algorithm SHA256 pyproject.toml).Hash
$installedHash = if (Test-Path $hashFile) { (Get-Content $hashFile -Raw).Trim() } else { '' }

if ($currentHash -ne $installedHash) {
    Write-Step 'Installing dependencies (first run can take a minute)'
    & $venvPy -m pip install --disable-pip-version-check -q --upgrade pip
    & $venvPy -m pip install --disable-pip-version-check -q -e ".[dev]"
    if ($LASTEXITCODE -ne 0) { Stop-WithError 'Dependency installation failed. See the messages above.' }
    Set-Content -Path $hashFile -Value $currentHash -Encoding ascii
} else {
    Write-Step 'Dependencies already up to date'
}

# 4. Tests ------------------------------------------------------------------
if (-not $SkipTests) {
    Write-Step 'Running tests'
    & $venvPy -m pytest -q -p no:warnings
    if ($LASTEXITCODE -ne 0) { Stop-WithError 'Tests failed. Fix them, or start anyway with: start.bat -SkipTests' }
}

# 5. Server -----------------------------------------------------------------
$probe = New-Object System.Net.Sockets.TcpClient
try {
    $probe.Connect('127.0.0.1', $Port)
    Stop-WithError "Port $Port is already in use. Try another one: start.bat -Port 8080"
} catch [System.Net.Sockets.SocketException] {
    # Nothing listening: the port is free.
} finally {
    $probe.Close()
}

Write-Host ''
Write-Host '  Mini Guardrail is starting' -ForegroundColor Green
Write-Host "  Playground : $url"
Write-Host "  API docs   : $url/docs"
Write-Host '  Press Ctrl+C to stop.'
Write-Host ''

$serveArgs = @('-m', 'guardrail', 'serve', '--port', $Port)
if (-not $NoBrowser) { $serveArgs += '--open' }
& $venvPy @serveArgs

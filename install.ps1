# AegisScan installer for Windows (PowerShell)
Write-Host "AegisScan installer" -ForegroundColor Cyan
Write-Host "-------------------"

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "Python 3.9+ is required. Install it from https://www.python.org/downloads/ (check 'Add to PATH')." -ForegroundColor Red
    exit 1
}

$ver = & python -c 'import sys; print("{}.{}".format(*sys.version_info[:2]))'
Write-Host "Python $ver found" -ForegroundColor Green

# optional: install as a global CLI command (still zero dependencies)
& pip install . 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "installed as 'aegisscan' command" -ForegroundColor Green
    $cmd = "aegisscan"
} else {
    Write-Host "pip install skipped - you can still run: python -m aegisscan"
    $cmd = "python -m aegisscan"
}

Write-Host ""
Write-Host "Quick start:"
Write-Host "  $cmd demo                 # scan the bundled vulnerable demo app"
Write-Host "  $cmd ui                   # professional web dashboard -> http://127.0.0.1:8899"
Write-Host "  $cmd scan --repo C:\path\to\project"
Write-Host "  $cmd scan --url https://example.com"
Write-Host "  $cmd scan --github owner/repo"
Write-Host "  $cmd --help               # all Kali-style subcommands"

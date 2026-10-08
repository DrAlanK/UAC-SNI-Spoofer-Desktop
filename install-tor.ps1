# install-tor.ps1
# Downloads Tor Expert Bundle and prepares bin/tor/ for UAC Spoofer.
#
# Usage:
#   .\install-tor.ps1
#   .\install-tor.ps1 -TorBrowserPath "C:\Program Files\Tor Browser\Browser\TorBrowser\Tor"
#
# Notes:
#   - Tor Expert Bundle contains tor.exe + geoip files only.
#   - WebTunnel client (webtunnel-client.exe) lives in Tor Browser.
#   - If you already have Tor Browser installed, pass its path with
#     -TorBrowserPath to copy the pluggable transport automatically.

param(
    [string]$TorBrowserPath = ""
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$dest = Join-Path $root 'bin\tor'
$transportsDir = Join-Path $dest 'pluggable_transports'

Write-Host "=== UAC Spoofer :: Tor bootstrap ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Discover latest Tor Expert Bundle version
# ---------------------------------------------------------------------------
Write-Host "[1/4] Resolving latest Tor Expert Bundle version..."

$version = $null
try {
    $listing = Invoke-WebRequest -Uri "https://dist.torproject.org/torbrowser/" `
        -UseBasicParsing -TimeoutSec 20
    $matches = [regex]::Matches($listing.Content, 'href="(\d+\.\d+\.\d+)/"')
    $versions = $matches | ForEach-Object { $_.Groups[1].Value } |
        Sort-Object { [version]$_ } -Descending
    if ($versions.Count -gt 0) {
        $version = $versions[0]
        Write-Host "       Latest detected: $version" -ForegroundColor Green
    }
} catch {
    Write-Warning "Could not query dist.torproject.org; falling back to 13.5.7"
    $version = "13.5.7"
}
if (-not $version) { $version = "13.5.7" }

# ---------------------------------------------------------------------------
# 2. Download the Expert Bundle
# ---------------------------------------------------------------------------
$url = "https://dist.torproject.org/torbrowser/$version/" +
       "tor-expert-bundle-windows-x86_64-$version.tar.gz"
$tmp = Join-Path $env:TEMP "tor-expert-$version.tar.gz"

Write-Host "[2/4] Downloading: $url"
if (Test-Path $tmp) { Remove-Item $tmp -Force }
Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
Write-Host "       Downloaded: $((Get-Item $tmp).Length / 1MB) MB" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Extract into bin/tor/
# ---------------------------------------------------------------------------
Write-Host "[3/4] Extracting into $dest"
New-Item -ItemType Directory -Path $dest -Force | Out-Null
New-Item -ItemType Directory -Path $transportsDir -Force | Out-Null

# Clean previous contents (keep pluggable_transports if already populated)
Get-ChildItem -Path $dest -Exclude 'pluggable_transports' |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

tar -xzf $tmp -C $dest
Remove-Item $tmp -Force

# Expert Bundle tarball usually extracts into a folder named "tor".
$inner = Join-Path $dest 'tor'
if (Test-Path (Join-Path $inner 'tor.exe')) {
    Get-ChildItem -Path $inner -Force | ForEach-Object {
        Move-Item -Path $_.FullName -Destination $dest -Force
    }
    Remove-Item $inner -Recurse -Force
}

if (-not (Test-Path (Join-Path $dest 'tor.exe'))) {
    throw "tor.exe not found after extraction. Check the tarball layout."
}
Write-Host "       tor.exe ready: $(Join-Path $dest 'tor.exe')" -ForegroundColor Green
# ---------------------------------------------------------------------------
# 4. Verify modern pluggable transports (lyrebird.exe)
# ---------------------------------------------------------------------------
Write-Host "[4/4] Verifying pluggable transports"
$lyrebird = Join-Path $transportsDir 'lyrebird.exe'
if (Test-Path $lyrebird) {
    Write-Host "       lyrebird.exe ready (webtunnel/obfs4/snowflake/meek_lite)" -ForegroundColor Green
} else {
    Write-Warning "lyrebird.exe not found. Tor will start but bridges will fail."
}

# ---------------------------------------------------------------------------
# 5. Python dependencies
# ---------------------------------------------------------------------------
Write-Host "Installing Python dependencies (stem, requests[socks])..."
python -m pip install --upgrade "stem>=1.8.2" "requests[socks]>=2.31"

Write-Host ""
Write-Host "=== Tor bundle ready ===" -ForegroundColor Cyan
Get-ChildItem -Path $dest -Recurse -File |
    Select-Object FullName, Length |
    Format-Table -AutoSize
Write-Host "All set." -ForegroundColor Green
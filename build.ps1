$ErrorActionPreference = 'Stop'

Set-Location $PSScriptRoot

Write-Host "Installing Python requirements..."
python -m pip install -r .\requirements.txt

if ($LASTEXITCODE -ne 0) {
    throw "pip failed with exit code $LASTEXITCODE"
}

Write-Host "Preparing network engines..."
& .\install-engine.ps1

$distDir = Join-Path $PSScriptRoot 'dist\UAC-Spoofer-Desktop'
$buildDir = Join-Path $PSScriptRoot 'build\UAC-Spoofer-Desktop'

if (Test-Path -LiteralPath $distDir) {
    Write-Host "Removing previous dist..."
    Remove-Item `
        -LiteralPath $distDir `
        -Recurse `
        -Force
}

if (Test-Path -LiteralPath $buildDir) {
    Write-Host "Removing previous build cache..."
    Remove-Item `
        -LiteralPath $buildDir `
        -Recurse `
        -Force
}

Write-Host "Building application..."
python -m PyInstaller `
    --noconfirm `
    --clean `
    .\UAC-Spoofer-Desktop.spec

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE"
}

$exe = Join-Path `
    $distDir `
    'UAC-Spoofer-Desktop.exe'

if (-not (Test-Path -LiteralPath $exe)) {
    throw "Build finished without producing $exe"
}

Write-Host ""
Write-Host "Build ready: $exe"
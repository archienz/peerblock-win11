# Optional local test-sign for pbfilter.sys
# Run as Administrator, from the folder that contains pbfilter.sys:
#   sign-pbfilter.cmd
#
# Creates CN=PeerBlock Test, trusts it on this PC, and signs the .sys.
# Windows still needs test signing (bcdedit /set testsigning on) and a reboot
# if that is not already enabled. This is not a Microsoft/WHQL signature.

param(
    [Parameter(Mandatory = $false)]
    [string]$SysPath
)

$ErrorActionPreference = "Stop"
$certSubject = "CN=PeerBlock Test"
$certName = "PeerBlock Test"

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "Restarting elevated..." -ForegroundColor Yellow
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath)
    if ($SysPath) { $argList += @("-SysPath", $SysPath) }
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList
    exit 0
}

if (-not $SysPath) {
    $SysPath = Join-Path $PSScriptRoot "pbfilter.sys"
}

if (-not (Test-Path -LiteralPath $SysPath)) {
    throw "pbfilter.sys not found at $SysPath"
}

Write-Host "Signing $SysPath" -ForegroundColor Cyan

$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $certSubject } |
    Select-Object -First 1

if (-not $cert) {
    Write-Host "Creating $certSubject" -ForegroundColor Yellow
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $certSubject `
        -CertStoreLocation Cert:\CurrentUser\My `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy Exportable
}

$tempCert = Join-Path $env:TEMP "PeerBlockTest.cer"
Export-Certificate -Cert $cert -FilePath $tempCert | Out-Null
Import-Certificate -FilePath $tempCert -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Write-Host "Trusted $certSubject (LocalMachine\Root)" -ForegroundColor Green

$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Select-Object -Last 1 -ExpandProperty FullName
if (-not $signtool) {
    $signtool = Get-ChildItem "C:\Program Files\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Select-Object -Last 1 -ExpandProperty FullName
}
if (-not $signtool) {
    throw "signtool.exe not found. Install the Windows SDK or WDK."
}

& $signtool sign /fd SHA256 /s my /n $certName /td SHA256 /tr http://timestamp.digicert.com $SysPath
if ($LASTEXITCODE -ne 0) {
    Write-Host "Timestamp failed, signing without timestamp..." -ForegroundColor Yellow
    & $signtool sign /fd SHA256 /s my /n $certName $SysPath
    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed with exit code $LASTEXITCODE"
    }
}

& $signtool verify /pa $SysPath
if ($LASTEXITCODE -ne 0) {
    Write-Host "signtool verify returned $LASTEXITCODE (test signatures can still load in test mode)" -ForegroundColor Yellow
}

$testsigning = $false
$bcd = & bcdedit
if ($bcd -match "testsigning\s+Yes") { $testsigning = $true }

if (-not $testsigning) {
    Write-Host "Enabling test signing (reboot required once)..." -ForegroundColor Yellow
    & bcdedit /set testsigning on | Out-Null
    Write-Host "Reboot, then run peerblock.exe as Administrator." -ForegroundColor Yellow
} else {
    Write-Host "Test signing is already on." -ForegroundColor Green
    Write-Host "Run peerblock.exe as Administrator from this folder." -ForegroundColor Green
}

Write-Host "Done." -ForegroundColor Green

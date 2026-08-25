# Test-signs pbfilter.sys for local Windows 11 development.
# Requires an elevated PowerShell prompt.
# This does NOT make the driver load on a stock Windows 11 machine with
# Secure Boot + Memory Integrity. See WINDOWS11.md.

param(
    [Parameter(Mandatory = $true)]
    [string]$SysPath
)

$ErrorActionPreference = "Stop"
$certName = "CN=PeerBlock Test"

$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $certName } |
    Select-Object -First 1

if (-not $cert) {
    Write-Host "Creating test code-signing certificate $certName"
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $certName `
        -CertStoreLocation Cert:\CurrentUser\My `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy Exportable
}

$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Select-Object -Last 1 -ExpandProperty FullName

if (-not $signtool) {
    throw "signtool.exe not found. Install the Windows SDK / WDK."
}

& $signtool sign /fd SHA256 /a /n "PeerBlock Test" /td SHA256 /tr http://timestamp.digicert.com $SysPath
if ($LASTEXITCODE -ne 0) {
    throw "signtool failed with $LASTEXITCODE"
}

Write-Host @"

Signed: $SysPath

On the target Windows 11 machine, as Administrator:

  1. Disable Memory Integrity (Core isolation) if it is on.
  2. bcdedit /set testsigning on
  3. Reboot.
  4. Copy pbfilter.sys next to peerblock.exe and run the app elevated.

Microsoft will not load an unsigned or self-signed kernel driver on a
normal Windows 11 Home/Pro install. Test signing is the only local path
without Hardware Dev Center attestation.

"@

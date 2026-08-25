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

Prefer sign-pbfilter.cmd next to pbfilter.sys (creates the cert, trusts it,
enables test signing if needed). Then reboot if test mode was just turned on,
and run peerblock.exe as Administrator.

Microsoft will not load an unsigned kernel driver on a stock Windows 11
Home/Pro install with test signing off. Test signing plus this test cert is
the local path without Hardware Dev Center attestation.

"@

param(
  [Parameter(Mandatory = $true)][string]$PfxPath,
  [Parameter(Mandatory = $true)][string]$PfxPassword,
  [string]$TimestampServer = 'http://timestamp.digicert.com'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $root
$downloads = Join-Path $projectRoot 'sentinel_cloud_mock\downloads'
$outputs = 'C:\Users\Utente\Documents\Codex\2026-07-01\ie\outputs'

if (-not (Test-Path -LiteralPath $PfxPath)) {
  throw "PFX non trovato: $PfxPath"
}

$securePassword = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxPath, $securePassword)

$targets = @(
  (Join-Path $downloads 'SentinelAnticheat-Windows-x64.exe'),
  (Join-Path $downloads 'SentinelAnticheat-Windows-x86.exe'),
  (Join-Path $downloads 'Sentinel Anticheat.exe'),
  (Join-Path $downloads 'Sentinel Anticheat 32 bit.exe'),
  (Join-Path $outputs 'SentinelAnticheat-Windows-x64.exe'),
  (Join-Path $outputs 'SentinelAnticheat-Windows-x86.exe'),
  (Join-Path $outputs 'Sentinel Anticheat.exe'),
  (Join-Path $outputs 'Sentinel Anticheat 32 bit.exe')
)

foreach ($target in $targets) {
  if (-not (Test-Path -LiteralPath $target)) {
    Write-Warning "Salto file non trovato: $target"
    continue
  }

  $signature = Set-AuthenticodeSignature -FilePath $target -Certificate $certificate -TimestampServer $TimestampServer
  if ($signature.Status -ne 'Valid') {
    throw "Firma fallita per $target: $($signature.StatusMessage)"
  }

  Get-AuthenticodeSignature -FilePath $target | Select-Object Status, StatusMessage, SignerCertificate, Path
}

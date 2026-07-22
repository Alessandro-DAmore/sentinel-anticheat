param(
  [int]$KeySize = 3072
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$data = Join-Path $root 'data'
$publicPath = Join-Path $data 'report-admin-public-key.xml'
$privatePath = Join-Path $data 'report-admin-private-key.xml'

New-Item -ItemType Directory -Force -Path $data | Out-Null

$rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new($KeySize)
try {
  $rsa.PersistKeyInCsp = $false
  $publicXml = $rsa.ToXmlString($false)
  $privateXml = $rsa.ToXmlString($true)
} finally {
  $rsa.Dispose()
}

$publicXml | Set-Content -LiteralPath $publicPath -Encoding UTF8
$privateXml | Set-Content -LiteralPath $privatePath -Encoding UTF8

Get-Item -LiteralPath $publicPath, $privatePath | Select-Object FullName, Length, LastWriteTime

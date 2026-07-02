[CmdletBinding()]
param(
  [string]$InstallRoot = 'E:\Sentinel_Anticheat\fxserver_local',

  [string]$LicenseKey = '',

  [switch]$Force
)

$ErrorActionPreference = 'Stop'

$artifactListUrl = 'https://runtime.fivem.net/artifacts/fivem/build_server_windows/master/'
$serverDataRepo = 'https://github.com/citizenfx/cfx-server-data.git'
$projectRoot = Split-Path -Parent $PSScriptRoot
$serverPath = Join-Path $InstallRoot 'server'
$serverDataPath = Join-Path $InstallRoot 'server-data'
$archivePath = Join-Path $InstallRoot 'server.7z'

function Resolve-Git {
  $git = Get-Command git.exe -ErrorAction SilentlyContinue
  if ($git) {
    return $git.Source
  }

  $bundledGit = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\native\git\cmd\git.exe'
  if (Test-Path -LiteralPath $bundledGit) {
    return $bundledGit
  }

  throw 'Git was not found. Install Git or run this from Codex with bundled dependencies available.'
}

function Resolve-ArtifactUrl {
  Write-Host "Checking recommended FXServer artifact..."
  $listing = Invoke-WebRequest -Uri $artifactListUrl -UseBasicParsing

  $href = $null
  foreach ($link in $listing.Links) {
    if ($link.outerHTML -match 'LATEST RECOMMENDED') {
      $href = $link.href
      break
    }
  }

  if (-not $href -and $listing.Content -match 'href="([^"]+)"[^>]*LATEST RECOMMENDED') {
    $href = $Matches[1]
  }

  if (-not $href) {
    throw 'Could not find the latest recommended FXServer artifact link.'
  }

  return ([System.Uri]::new([System.Uri]$artifactListUrl, $href)).AbsoluteUri
}

function Expand-FXServerArchive {
  param(
    [string]$Archive,
    [string]$Destination
  )

  $sevenZip = Get-Command 7z.exe, 7za.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($sevenZip) {
    & $sevenZip.Source x $Archive "-o$Destination" -y | Out-Host
    return
  }

  $tar = Get-Command tar.exe -ErrorAction SilentlyContinue
  if ($tar) {
    & $tar.Source -xf $Archive -C $Destination
    return
  }

  throw 'Could not find 7-Zip or tar.exe to extract server.7z.'
}

if ((Test-Path -LiteralPath $InstallRoot) -and $Force) {
  Write-Warning "Force was set. Existing files under $InstallRoot may be overwritten."
}

New-Item -ItemType Directory -Force -Path $InstallRoot, $serverPath | Out-Null

if (-not (Test-Path -LiteralPath (Join-Path $serverPath 'FXServer.exe')) -or $Force) {
  $artifactUrl = Resolve-ArtifactUrl
  Write-Host "Downloading $artifactUrl"
  Invoke-WebRequest -Uri $artifactUrl -OutFile $archivePath -UseBasicParsing

  Write-Host "Extracting FXServer to $serverPath"
  Expand-FXServerArchive -Archive $archivePath -Destination $serverPath
}

if (-not (Test-Path -LiteralPath (Join-Path $serverPath 'FXServer.exe'))) {
  throw "FXServer.exe was not found after extraction in $serverPath"
}

$git = Resolve-Git
if (-not (Test-Path -LiteralPath $serverDataPath)) {
  Write-Host "Cloning server-data to $serverDataPath"
  & $git clone $serverDataRepo $serverDataPath
} else {
  Write-Host "server-data already exists: $serverDataPath"
}

& (Join-Path $PSScriptRoot 'Install-FXServerResources.ps1') -ServerDataPath $serverDataPath -Force

$sentinelCfg = Join-Path $serverDataPath 'sentinel.server.cfg'
if ($LicenseKey -ne '') {
  $content = Get-Content -LiteralPath $sentinelCfg -Raw
  $content = $content -replace 'sv_licenseKey "CHANGE_ME_FIVEM_LICENSE_KEY"', ('sv_licenseKey "{0}"' -f $LicenseKey)
  Set-Content -LiteralPath $sentinelCfg -Value $content -Encoding ASCII
} else {
  Write-Warning 'No license key was provided. Add it to sentinel.server.cfg before starting FXServer.'
}

$runScript = Join-Path $InstallRoot 'Run-SentinelFXServer.ps1'
@"
Set-Location -LiteralPath "$serverDataPath"
& "$serverPath\FXServer.exe" +exec sentinel.server.cfg
"@ | Set-Content -LiteralPath $runScript -Encoding ASCII

Write-Host ''
Write-Host 'Local FXServer test environment is ready.'
Write-Host "Server:      $serverPath"
Write-Host "Server-data: $serverDataPath"
Write-Host "Config:      $sentinelCfg"
Write-Host "Run:         powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$runScript`""

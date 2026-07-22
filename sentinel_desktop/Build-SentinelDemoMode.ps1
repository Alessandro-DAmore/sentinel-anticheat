param(
  [string]$OutputPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$source = Join-Path $root 'tools\SentinelRuntimeProbe.cs'
$tools = Join-Path $root 'tools'
$assets = Join-Path $root 'assets'
$icon = Join-Path $assets 'sentinel-app-icon.ico'

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
  $OutputPath = Join-Path $tools 'Sentinel Demo Mode.exe'
} else {
  $OutputPath = [IO.Path]::GetFullPath($OutputPath)
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc)) {
  $compilerRoot = Join-Path $env:WINDIR 'Microsoft.NET\Framework64'
  $csc = (Get-ChildItem -LiteralPath $compilerRoot -Recurse -Filter csc.exe | Sort-Object FullName -Descending | Select-Object -First 1).FullName
}

if (-not (Test-Path -LiteralPath $csc)) {
  throw 'C# compiler not found.'
}

$args = @(
  '/nologo',
  '/target:winexe',
  '/optimize+',
  '/platform:anycpu',
  '/reference:System.dll',
  '/reference:System.Drawing.dll',
  '/reference:System.Windows.Forms.dll',
  ('/out:{0}' -f $OutputPath),
  $source
)

if (Test-Path -LiteralPath $icon) {
  $args = @(
    '/nologo',
    '/target:winexe',
    '/optimize+',
    '/platform:anycpu',
    ('/win32icon:{0}' -f $icon),
    '/reference:System.dll',
    '/reference:System.Drawing.dll',
    '/reference:System.Windows.Forms.dll',
    ('/out:{0}' -f $OutputPath),
    $source
  )
}

& $csc @args
if ($LASTEXITCODE -ne 0) {
  throw 'Sentinel Demo Mode compilation failed.'
}

$legacyPath = Join-Path $tools 'Sentinel Runtime Probe.exe'
if ([IO.Path]::GetFullPath($legacyPath) -ne [IO.Path]::GetFullPath($OutputPath)) {
  Copy-Item -LiteralPath $OutputPath -Destination $legacyPath -Force
}

Get-Item -LiteralPath $OutputPath, $legacyPath | Select-Object FullName, Length, LastWriteTime

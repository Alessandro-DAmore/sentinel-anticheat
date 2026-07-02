[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory = $true)]
  [string]$ServerDataPath,

  [switch]$Force
)

$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$serverData = (Resolve-Path -LiteralPath $ServerDataPath).Path
$resourcesPath = Join-Path $serverData 'resources'
$resourceNames = @('sentinel_ac', 'sentinel_test_resource')

if (-not (Test-Path -LiteralPath $resourcesPath)) {
  New-Item -ItemType Directory -Path $resourcesPath | Out-Null
}

foreach ($name in $resourceNames) {
  $source = Join-Path $projectRoot $name
  $target = Join-Path $resourcesPath $name

  if (-not (Test-Path -LiteralPath $source)) {
    throw "Missing source resource: $source"
  }

  if ((Test-Path -LiteralPath $target) -and -not $Force) {
    throw "Target already exists: $target. Re-run with -Force to update it."
  }

  if ($PSCmdlet.ShouldProcess($target, "Copy $name")) {
    if (Test-Path -LiteralPath $target) {
      Copy-Item -Path (Join-Path $source '*') -Destination $target -Recurse -Force
    } else {
      Copy-Item -LiteralPath $source -Destination $resourcesPath -Recurse
    }
  }
}

$cfgSource = Join-Path $projectRoot 'fxserver_test\server.cfg'
$cfgTarget = Join-Path $serverData 'sentinel.server.cfg'

if ((Test-Path -LiteralPath $cfgTarget) -and -not $Force) {
  Write-Warning "Config already exists: $cfgTarget. Re-run with -Force to overwrite it."
} elseif ($PSCmdlet.ShouldProcess($cfgTarget, 'Copy sentinel server.cfg template')) {
  Copy-Item -LiteralPath $cfgSource -Destination $cfgTarget -Force:$Force
}

Write-Host "Sentinel resources installed in: $resourcesPath"
Write-Host "Template cfg: $cfgTarget"
Write-Host 'Start FXServer from its server-data folder with: +exec sentinel.server.cfg'

param(
  [string]$IconPng = 'C:\Users\Utente\Desktop\69be01b5-1310-44c6-8f43-d82c5999eb5e.png',
  [string]$SigningPfx = '',
  [string]$SigningPassword = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $root
$assets = Join-Path $root 'assets'
$build = Join-Path $root 'build'
$downloads = Join-Path $projectRoot 'sentinel_cloud_mock\downloads'
$cloudAssets = Join-Path $projectRoot 'sentinel_cloud_mock\assets'
$outputs = 'C:\Users\Utente\Documents\Codex\2026-07-01\ie\outputs'
$iconPngOut = Join-Path $assets 'sentinel-logo.png'
$iconIco = Join-Path $assets 'sentinel-app-icon.ico'
$sourcePath = Join-Path $build 'SentinelAnticheatLauncher.cs'
$assemblyInfoPath = Join-Path $build 'AssemblyInfo.cs'
$manifestPath = Join-Path $build 'SentinelAnticheat.exe.manifest'

New-Item -ItemType Directory -Force -Path $assets, $build, $downloads, $cloudAssets, $outputs | Out-Null

if (-not (Test-Path -LiteralPath $IconPng)) {
  throw "Icon PNG not found: $IconPng"
}

$desktopSourceLogo = Join-Path $assets 'sentinel-logo-source.png'
$cloudSourceLogo = Join-Path $cloudAssets 'sentinel-logo-source.png'
if ([IO.Path]::GetFullPath($IconPng) -ne [IO.Path]::GetFullPath($desktopSourceLogo)) {
  Copy-Item -LiteralPath $IconPng -Destination $desktopSourceLogo -Force
}
if ([IO.Path]::GetFullPath($IconPng) -ne [IO.Path]::GetFullPath($cloudSourceLogo)) {
  Copy-Item -LiteralPath $IconPng -Destination $cloudSourceLogo -Force
}

$python = Get-Command python -ErrorAction Stop
$pythonCode = @'
from PIL import Image, ImageDraw, ImageFilter
import sys

src, desktop_logo, cloud_logo, ico = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
img = Image.open(src).convert("RGBA")
crop_box = (232, 105, 792, 790)
crop = img.crop(crop_box)
w, h = crop.size
scale = 4
mask = Image.new("L", (w * scale, h * scale), 0)
d = ImageDraw.Draw(mask)
points = [
    (w * 0.50, h * 0.02),
    (w * 0.06, h * 0.16),
    (w * 0.08, h * 0.54),
    (w * 0.50, h * 0.98),
    (w * 0.92, h * 0.54),
    (w * 0.94, h * 0.16),
]
d.polygon([(int(x * scale), int(y * scale)) for x, y in points], fill=255)
mask = mask.filter(ImageFilter.GaussianBlur(2.1 * scale)).resize((w, h), Image.Resampling.LANCZOS)
crop.putalpha(mask)
bbox = crop.getchannel("A").getbbox()
trim = crop.crop(bbox)
size = max(trim.size) + 56
canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
canvas.alpha_composite(trim, ((size - trim.width) // 2, (size - trim.height) // 2))
canvas.save(desktop_logo)
canvas.save(cloud_logo)
canvas.save(ico, format="ICO", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
'@
$pythonCode | & $python.Source - $IconPng $iconPngOut (Join-Path $cloudAssets 'sentinel-logo.png') $iconIco

$launcherSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

namespace SentinelAnticheatBootstrapper
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            try
            {
                string root = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "SentinelAnticheat"
                );
                string assets = Path.Combine(root, "assets");
                Directory.CreateDirectory(root);
                Directory.CreateDirectory(assets);

                Extract("SentinelAnticheat.ps1", Path.Combine(root, "SentinelAnticheat.ps1"));
                Extract("Run-SentinelAnticheat.ps1", Path.Combine(root, "Run-SentinelAnticheat.ps1"));
                Extract("config.json", Path.Combine(root, "config.json"));
                Extract("signatures.json", Path.Combine(root, "signatures.json"));
                Extract("README.md", Path.Combine(root, "README.md"));
                Extract("Smoke-AgentReport.ps1", Path.Combine(root, "Smoke-AgentReport.ps1"));
                Extract("sentinel-logo.png", Path.Combine(assets, "sentinel-logo.png"));
                Extract("sentinel-app-icon.ico", Path.Combine(assets, "sentinel-app-icon.ico"));

                string installedLauncher = Path.Combine(root, "Sentinel Anticheat.exe");
                InstallLauncherCopy(installedLauncher);
                CreateDesktopShortcut(installedLauncher, Path.Combine(assets, "sentinel-app-icon.ico"));

                string powerShell = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "WindowsPowerShell\\v1.0\\powershell.exe"
                );
                if (!File.Exists(powerShell))
                {
                    powerShell = "powershell.exe";
                }

                string script = Path.Combine(root, "SentinelAnticheat.ps1");
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = powerShell;
                startInfo.Arguments = "-STA -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"" + script + "\"";
                startInfo.WorkingDirectory = root;
                startInfo.UseShellExecute = false;
                startInfo.CreateNoWindow = true;
                startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                Process.Start(startInfo);
            }
            catch (Exception error)
            {
                MessageBox.Show(
                    "Sentinel Anticheat non puo avviarsi.\n\n" + error.Message,
                    "Sentinel Anticheat",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
        }

        private static void Extract(string resourceName, string destination)
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            using (Stream input = assembly.GetManifestResourceStream(resourceName))
            {
                if (input == null)
                {
                    throw new InvalidOperationException("Risorsa mancante: " + resourceName);
                }

                using (FileStream output = File.Create(destination))
                {
                    input.CopyTo(output);
                }
            }
        }

        private static void InstallLauncherCopy(string destination)
        {
            try
            {
                string current = Assembly.GetExecutingAssembly().Location;
                if (string.Equals(current, destination, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                File.Copy(current, destination, true);
            }
            catch
            {
                // The app can still run even if the installed launcher copy cannot be refreshed.
            }
        }

        private static void CreateDesktopShortcut(string targetPath, string iconPath)
        {
            try
            {
                string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                string shortcutPath = Path.Combine(desktop, "Sentinel Anticheat.lnk");
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType == null)
                {
                    return;
                }

                dynamic shell = Activator.CreateInstance(shellType);
                dynamic shortcut = shell.CreateShortcut(shortcutPath);
                shortcut.TargetPath = targetPath;
                shortcut.WorkingDirectory = Path.GetDirectoryName(targetPath);
                shortcut.IconLocation = iconPath;
                shortcut.Description = "Sentinel Anticheat";
                shortcut.Save();
            }
            catch
            {
                // Shortcut creation is a convenience and must not block Sentinel startup.
            }
        }
    }
}
'@
$launcherSource | Set-Content -LiteralPath $sourcePath -Encoding UTF8

$assemblyInfo = @'
using System.Reflection;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("Sentinel Anticheat")]
[assembly: AssemblyDescription("Sentinel Anticheat desktop client for FiveM fair-play protection")]
[assembly: AssemblyCompany("Sentinel Anticheat")]
[assembly: AssemblyProduct("Sentinel Anticheat")]
[assembly: AssemblyCopyright("Copyright Sentinel Anticheat")]
[assembly: AssemblyTrademark("Sentinel Anticheat")]
[assembly: ComVisible(false)]
[assembly: Guid("b5a4fd40-fafb-4d4c-b152-72b3661f4542")]
[assembly: AssemblyVersion("0.2.0.0")]
[assembly: AssemblyFileVersion("0.2.0.0")]
'@
$assemblyInfo | Set-Content -LiteralPath $assemblyInfoPath -Encoding UTF8

$manifest = @'
<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity version="0.2.0.0" name="SentinelAnticheat.Desktop.Client"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
    </application>
  </compatibility>
</assembly>
'@
$manifest | Set-Content -LiteralPath $manifestPath -Encoding UTF8

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc)) {
  $csc = (Get-ChildItem -LiteralPath (Join-Path $env:WINDIR 'Microsoft.NET\Framework64') -Recurse -Filter csc.exe | Sort-Object FullName -Descending | Select-Object -First 1).FullName
}
if (-not (Test-Path -LiteralPath $csc)) {
  throw 'C# compiler not found.'
}

$resources = @(
  @{ Path = Join-Path $root 'SentinelAnticheat.ps1'; Name = 'SentinelAnticheat.ps1' },
  @{ Path = Join-Path $root 'Run-SentinelAnticheat.ps1'; Name = 'Run-SentinelAnticheat.ps1' },
  @{ Path = Join-Path $root 'config.json'; Name = 'config.json' },
  @{ Path = Join-Path $root 'signatures.json'; Name = 'signatures.json' },
  @{ Path = Join-Path $root 'README.md'; Name = 'README.md' },
  @{ Path = Join-Path $root 'Smoke-AgentReport.ps1'; Name = 'Smoke-AgentReport.ps1' },
  @{ Path = Join-Path $assets 'sentinel-logo.png'; Name = 'sentinel-logo.png' },
  @{ Path = Join-Path $assets 'sentinel-app-icon.ico'; Name = 'sentinel-app-icon.ico' }
)

$resourceArgs = @()
foreach ($resource in $resources) {
  if (-not (Test-Path -LiteralPath $resource.Path)) {
    throw "Resource missing: $($resource.Path)"
  }
  $resourceArgs += ('/resource:{0},{1}' -f $resource.Path, $resource.Name)
}

$builds = @(
  @{ Platform = 'x64'; FileName = 'SentinelAnticheat-Windows-x64.exe' },
  @{ Platform = 'x86'; FileName = 'SentinelAnticheat-Windows-x86.exe' }
)

foreach ($item in $builds) {
  $downloadExe = Join-Path $downloads $item.FileName
  $outputExe = Join-Path $outputs $item.FileName
  foreach ($path in @($downloadExe, $outputExe)) {
    if (Test-Path -LiteralPath $path) {
      Remove-Item -LiteralPath $path -Force
    }
  }

  $args = @(
    '/nologo',
    '/target:winexe',
    '/optimize+',
    ('/platform:{0}' -f $item.Platform),
    ('/win32icon:{0}' -f $iconIco),
    ('/win32manifest:{0}' -f $manifestPath),
    '/reference:Microsoft.CSharp.dll',
    '/reference:System.Windows.Forms.dll',
    ('/out:{0}' -f $downloadExe),
    $sourcePath,
    $assemblyInfoPath
  ) + $resourceArgs

  & $csc @args
  if ($LASTEXITCODE -ne 0) {
    throw "Compilation failed for $($item.Platform)."
  }

  if (-not [string]::IsNullOrWhiteSpace($SigningPfx) -and (Test-Path -LiteralPath $SigningPfx)) {
    $securePassword = ConvertTo-SecureString $SigningPassword -AsPlainText -Force
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($SigningPfx, $securePassword)
    $signature = Set-AuthenticodeSignature -FilePath $downloadExe -Certificate $certificate -TimestampServer 'http://timestamp.digicert.com'
    if ($signature.Status -ne 'Valid') {
      throw "Code signing failed for $($item.FileName): $($signature.StatusMessage)"
    }
  }

  Copy-Item -LiteralPath $downloadExe -Destination $outputExe -Force

  $friendlyName = if ($item.Platform -eq 'x64') { 'Sentinel Anticheat.exe' } else { 'Sentinel Anticheat 32 bit.exe' }
  Copy-Item -LiteralPath $downloadExe -Destination (Join-Path $downloads $friendlyName) -Force
  Copy-Item -LiteralPath $downloadExe -Destination (Join-Path $outputs $friendlyName) -Force
}

Get-Item -LiteralPath (Join-Path $downloads 'SentinelAnticheat-Windows-x64.exe'), (Join-Path $downloads 'SentinelAnticheat-Windows-x86.exe'), (Join-Path $downloads 'Sentinel Anticheat.exe'), (Join-Path $downloads 'Sentinel Anticheat 32 bit.exe'), (Join-Path $outputs 'SentinelAnticheat-Windows-x64.exe'), (Join-Path $outputs 'SentinelAnticheat-Windows-x86.exe'), (Join-Path $outputs 'Sentinel Anticheat.exe'), (Join-Path $outputs 'Sentinel Anticheat 32 bit.exe') |
  Select-Object FullName, Length, LastWriteTime

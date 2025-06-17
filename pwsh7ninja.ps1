#requires -version 5.1
<#
    ! THIS FILE IS A TEMPLATE !

    description: temp-install PowerShell 7, rerun self, then remove PS7 again after work is done.
    put any powershell 7 deployment work in the main {} function.
#>

# internal – do not set manually
param([switch]$cleanup)                  
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script_path = $MyInvocation.MyCommand.Definition
$temp_dir    = Join-Path $env:HOMEPATH 'pwsh_bootstrap'
$msi_path    = Join-Path $temp_dir 'pwsh7.msi'

function install_pwsh7 {
    if (Test-Path $temp_dir) { Remove-Item $temp_dir -Recurse -Force }
    New-Item $temp_dir -ItemType Directory -Force | Out-Null

    $arch    = if ([IntPtr]::Size -eq 8) {'x64'} else {'x86'}
    # pin to a known-good build
    $version = '7.4.2' 
    $uri     = "https://github.com/PowerShell/PowerShell/releases/download/v$version/PowerShell-$version-win-$arch.msi"

    Invoke-WebRequest $uri -OutFile $msi_path -UseBasicParsing
    Start-Process msiexec.exe -ArgumentList "/i `"$msi_path`" /quiet /norestart" -Wait -WindowStyle Hidden
}

function uninstall_pwsh7 {
    if (-not (Test-Path $msi_path)) { return }
    Start-Process msiexec.exe -ArgumentList "/x `"$msi_path`" /quiet /norestart" -Wait -WindowStyle Hidden
    Remove-Item $temp_dir -Recurse -Force -ErrorAction SilentlyContinue
}

function main {
    ############################################################################
    # >>>>>                     DEPLOYMENT WORK HERE                    <<<<<  #
    ############################################################################
    Write-Host "running workload in powershell $($PSVersionTable.PSVersion)."
}

# ---------- program flow ----------
if ($cleanup) { uninstall_pwsh7; return }

if ($PSVersionTable.PSVersion.Major -lt 7) {
    install_pwsh7
    $pwsh = Join-Path ${env:ProgramFiles} 'PowerShell\7\pwsh.exe'
    if (-not (Test-Path $pwsh)) { $pwsh = 'pwsh.exe' }  # PATH fallback

    Start-Process $pwsh -ArgumentList "-NoLogo","-NoProfile","-ExecutionPolicy","Bypass","-File","`"$script_path`"" -Wait
    # back in 5.1, now trigger cleanup
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "`"$script_path`"" -cleanup
    return
}

# we are now in PS7
main
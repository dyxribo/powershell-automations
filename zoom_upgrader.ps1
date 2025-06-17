param (
    [switch] $upgrade,
    [switch] $purge
)

function prompt_choice {
    write-host "`n`nhi there! would you like to purge zoom only, or install the 64 bit version?"
    $answer = Read-Host "`n1. purge zoom`n2. purge zoom & install 64 bit version`n`nselect an option"

    if ($answer -eq "1") {
        # if we're only removing zoom, then we can straight up scan for it and remove it
        (purge_zoom -zoom_installs (scan)) > $null
    } elseif ($answer -eq "2") {
        reinstall_zoom
    } else {
        write-host "`nhelp me help you: just pick a valid option. >:(`n"
        exit 0
    }
}

function reinstall_zoom {
    # otherwise if we're gonna upgrade, obviously purge zoom first
        # but if it doesn't exist (returns as 0), skip the purge and
        (purge_zoom -zoom_installs (scan)) > $null
        install_zoom_64
        install_zoom_outlook
}

function scan {
    # we make a list for the 32bit apps and filter their displaynames against the string "zoom". pretty simple.
    # we should also check HKCU *AND* HKLM, since zoom might be installed in either one depending on the method of installation.
    $zoom_installs = @()
    $reg_paths = @(
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $valid_paths = $reg_paths | Where-Object { Test-Path $_ }
    $zoom_installs += Get-ItemProperty $valid_paths | Where-Object { $_.DisplayName -like "*zoom*" }
    # if we get no matches, it's safe to assume that 32 bit zoom is not installed.
    if ($zoom_installs.Count -lt 1) {
        write-host "zoom is not on this pc. `"your princess is in another castle`" type beat."
        return 0
    }
    return $zoom_installs
}

function purge_zoom () {
    # Parameter help description
    param ($zoom_installs)

    if ($zoom_installs -eq 0) {
        return 0
    }

    write-host "purging zoom..."

    foreach ($zoom_install in $zoom_installs) {
        # lets notify the user on what we found
        Write-Host "found:", $zoom_install.DisplayName
        # will need to access this property a few times in this loop, so i'll store it
        $current_uninstaller = $zoom_install.UninstallString
        # if we're dealing with an MSI installer...
        if ($current_uninstaller -match "MsiExec\.exe.*") {
            # ...let it be known, add the /quiet + /norestart flags, and remove that sucka
            write-host "uninstalling application via $current_uninstaller..."
            Start-Process "msiexec.exe" -ArgumentList "/x $($zoom_install.PSChildName) /quiet /norestart" -Wait
        } else {
            # otherwise, if we're dealing with an exe installer, we should def sanitize the uninstall string...
            if ($current_uninstaller -match '^"?(?<exe>[^"]+)"?\s*(?<args>.*)$') {
                $exe_path = $matches.exe
                $exe_args = $matches.args

                # ...make sure we're performing the uninstalls silently...
                if ($exe_args -notmatch "/quiet|/silent") {
                    $exe_args += " /silent /norestart"
                }
            }
            # THEN we can remove that sucka.
            Write-Host "uninstalling application via $exe_path"
            Start-Process -FilePath $exe_path -ArgumentList $exe_args -WindowStyle Hidden -Wait
        }
    }   
}

function install_zoom_64 {
    # install mazda (zoom zoom zoom)
    write-host "installing zoom 64 bit..."
    $exe_path = Join-Path $PSScriptRoot 'zoom_installer_64.exe'
    Start-Process -FilePath $exe_path -ArgumentList "/silent /norestart" -WindowStyle Hidden -Wait
}

function install_zoom_outlook {
    write-host "installing zoom outlook plugin..."
    $msi_path = Join-Path $PSScriptRoot 'zoom_outlook_plugin.msi'

    #install mazdas for usps (zoom outlook plugin)
    Start-Process "msiexec.exe" -ArgumentList "/i `"$msi_path`" /quiet /norestart" -Wait -Verb RunAs
}

# handle script switch if given, or prompt for option
if ($upgrade -and $purge) {
    Write-Host "`nupgrade and purge flags cannot coexist. you must choose, young padawan. i believe in you.`n"
    exit 0
} elseif ($upgrade) {
    reinstall_zoom
} elseif ($purge) {
    (purge_zoom -zoom_installs (scan)) > $null
} else {
    prompt_choice
}
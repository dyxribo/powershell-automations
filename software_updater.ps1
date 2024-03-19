# just setting some constants we will need to use later
$required_app_versions = @{
    "Netwrix PolicyPak Client-Side Extension" = "23.10.3683"
    "Sentinel Agent"                          = "23.1.886" 
    "Carbon Black App Control Agent"          = "8.8.2.1042" 
    "Guardicore Agents"                       = "5.49.23314.46230" 
    "Ivanti Notifications Manager"            = "11.0.4.499" # ivanti endpoint manager is also needed, but this installer will install both.
    "Phish Alert"                             = "1.4.68" 
    "Local Administrator Password Solution"   = "6.2.0.0" 
    "UniversalForwarder"                      = "9.2.0.1" 
    "Google Chrome"                           = "122.0.6261.112"
    "MSTeams"                                 = "24004.1309.2689.2246"
}
$app_installers = @{
    "Netwrix PolicyPak Client-Side Extension" = "Netwrix\PolicyPak\Client Side Extension (CSE)\install.ps1"
    "Sentinel Agent"                          = "SentinelOne\Windows\Workstations\install.ps1" 
    "Carbon Black App Control Agent"          = "Carbon Black\CB App Control\install.ps1" 
    "Guardicore Agents"                       = "Guardicore\Agents\Workstations\install.ps1" 
    "Ivanti Notifications Manager"            = "Ivanti\install.ps1" # ivanti endpoint manager is also needed, but this installer will install both.
    "Phish Alert"                             = "Phish_Alert\install.ps1" 
    "Local Administrator Password Solution"   = "LAPS\install.ps1" 
    "UniversalForwarder"                      = "Splunk\install.ps1" 
    "Google Chrome"                           = "Chrome\install.ps1"
    "MSTeams"                                 = "Microsoft Teams\new_teams_install.ps1"
}
$required_application_list = [string[]]$required_app_versions.Keys
$num_apps_required = [int]($required_application_list | Measure-Object | Select-Object -Property Count).Count
$lanman_ws_path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$lanman_srv_path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$root_installer_path = "C:\Downloaded Software"
$root_installer_path_2 = "C:\packages"
# full list of installed apps, as pulled from the registry.
# first we'll get the 32-bit app list, followed by 64-bit app list.
# then, we'll get the apps installed in the Appx format (.msix), and concat them to the $all_apps array.
$all_apps = @()
$all_apps += Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object -Property DisplayName, DisplayVersion
$all_apps += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object -Property DisplayName, DisplayVersion
$all_apps += Get-AppxPackage -AllUsers | Select-Object -Property Name, Version

# now match the required apps list against the installed applications on the local machine
$found_apps = $all_apps | Where-Object { $required_application_list -contains $_.displayname }
$msix_apps += $all_apps | Where-Object { $required_application_list -contains $_.Name }
$num_apps_installed = [int]($found_apps | Measure-Object | Select-Object -Property Count).Count
# msix count is a little tricky to get, this is probably the cleanest solution:
$msix_unique = $msix_apps | Measure-Object | Select-Object -Unique
foreach ($app in $msix_unique) {
    $num_apps_installed += 1
}

# gonna need this function for comparing versions
function compare_versions {
    param([string] $has_version, [string] $needs_version)
    # we need to thoroughly check the versions down to the build number.
    # to do this, we break down the version numbers into arrays by splitting them by their dot separators.
    $v1Components = $has_version.Split(".")
    $v2Components = $needs_version.Split(".")
    # now we loop through the components of both versions and compare them iteratively
    for ($i = 0; $i -lt $v1Components.Length -and $i -lt $v2Components.Length; $i++) {
        $c1 = [int]$v1Components[$i] 
        $c2 = [int]$v2Components[$i]

        # if has_version's current component value is less than the needs_version current component, return a big ol' NOPE (not up-to-date)
        if ($c1 -lt $c2) {
            return -1
        # otherwise, if they're equal, continue iterating through the components
        } elseif ($c1 -eq $c2) {
            continue
        # if has > needs, then the rest doesnt matter; you're on a newer version than what's required
        } elseif ($c1 -gt $c2) {
            return 0
        }
    }

    # if versions are equal, then we can also return 0; we won't need to update
    return 0
}

# gonna need this function for checking for updates
function check_for_updates {
    foreach ($app in $required_app_versions.Keys) {

        # currently, "new teams" is the only msix app that is being installed on our machines regularly, so i'm choosing to explicitly check for that and get the current version.
        # later on, we can easily change this to match $app against any apps in the $msix_apps object.
        if ($app -eq "MSTeams") {
            $current_app_version = ($msix_apps | Where-Object { $_.Name -eq $app } | Select-Object -Property Version -First 1).version
        # otherwise, enumerate the current version of the current app in the typical way
        } else {   
            $current_app_version = [string]($found_apps | Where-Object { $_.displayname -eq $app } | Select-Object -Property displayversion).displayversion
        }
        # if the version we have is greater than or equal to the version we need, then we're good
        if ((compare_versions -has_version $current_app_version -needs_version $($required_app_versions[$app])) -eq 0) {
            write-host "$app is up to date."
        # otherwise let it be known the app needs to be updated and start doing so
        } else {
            if ($app -eq "Google Chrome") {
                # we'll skip google chrome in the iteration since it auto updates, 
                # but we'll still let it be known that an update is needed
                write-host "google chrome needs to be updated! open the browser and trigger an update."
                continue
            }
            # this branch will be for installers that are located in the 'packages' share.
            # again, there are only 2 so i'm choosing to check explicitly rather than match against some data structure. can be changed at a later date.
            if ($app -eq "MSTeams" -or $app -eq "UniversalForwarder") {
                & "$($root_installer_path_2)\$($app_installers[$app])"
                continue
            }
            # TODO: display "none" if $current_app_verison is null/empty
            write-host $app, "has", "v$current_app_version;", "needs", "v$($required_app_versions[$app])."
            write-host "$app needs to be updated; updating now."
            # update app using default installer path ("Downloaded Software" shared folder)
            & "$($root_installer_path)\$($app_installers[$app])"
        }
    }
}

# this is where the script actually starts running, calling on the functions and properties above to carry out update/install checks. 
# if the number of required apps found on this machine is equal the number of total required apps...
if ($num_apps_installed -eq $num_apps_required) {
    # ...then all required apps are installed, so now check installed versions.
    # now we have to go through each item in the required_app_versions object so we can check each app one by one.
    # we'll call the check_for_updates function above to do the heavy lifting.
    check_for_updates
    # if the script gets here, then the check_for_updates function completed successfully, and all apps are all up-to-date.
    # lets let the people know!
    write-host "`nall apps are up-to-date!"
# otherwise...
} else {
    # install the apps that are not installed one by one by looping (last loop i swear)
    foreach ($app in $app_installers.Keys) {
        # if the current app's name matches one of the apps we already confirmed as installed on this machine, then can_skip will be true...
        $can_skip = ($found_apps | Where-Object { $_.displayname -eq $app -or $_.name -eq $app } | Select-Object -Property displayname).displayname
        # ...meaning we can skip this iteration for the current app
        if ($can_skip) {
            continue
        }
        # otherwise, the app isn't installed, so let that be known and start installing
        Write-Host "$app is not installed at all; installing..."
        & "$($root_installer_path)\$($app_installers[$app])"
    }
    # if the script gets here, then the apps were installed, and should be on the latest version, so now we can check the others for updates
    check_for_updates
}

# check to see if the current registry entries for lanman workstation and server exist, respectively
$lanman_ws = Get-ItemProperty -Path $lanman_ws_path
$lanman_srv = Get-ItemProperty -Path $lanman_srv_path
# check if the values are valid
if (($lanman_ws.requiresecuritysignature -eq 1) -and ($lanman_srv.requiresecuritysignature -eq 1)) {
    # if they are then let it be known
    write-host "registry is up-to-date!"
# otherwise...
} else {
    # install registry entries manually
    write-host "installing reg keys..."
    New-ItemProperty -Path $lanman_ws_path -Name "requiresecuritysignature" -Value 1 -PropertyType DWORD
    New-ItemProperty -Path $lanman_srv_path -Name "requiresecuritysignature" -Value 1 -PropertyType DWORD
    Write-Host "registry properties written successfully."
}

# done! windows updates were planned, but seem to be blocked from being triggered by script, so they'll have to be done manually :(
write-host "software check complete :) make sure to run windows updates and reboot!`n"

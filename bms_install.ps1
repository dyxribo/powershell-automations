# script properties
# constants
$SUCCESS = 0
$ACCESS_PROTECTED_SECURITY = 1
$SHORTCUT_CREATION_FAILED = 2
# variables
$MSI = "$PSScriptRoot\BMSInstall\BmsInstaller.msi"
$INSTALLLOG = "$env:TEMP\BMS_INSTALL.log"
$INSTALL_LOCATION = "C:\Program Files (x86)\"
$bms_exe = "C:\Program Files (x86)\Basket Management System\BMS.exe"
$shortcut_path = "C:\Users\Public\Desktop\BMS.lnk"

# first we need to install the BMS package
Write-Host "installing Basket Management System..." 
Start-Process "msiexec.exe" -ArgumentList "/passive /qn /i `"${MSI}`" /log $INSTALLLOG" -Wait 
Write-Host "Successfully installed Basket Management System."

# then make sure that the folder has full permissions;
# so we define the permissions to add...
$god_mode_rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

# get the current ACL...
$folder_acl = Get-Acl -Path $INSTALL_LOCATION
# check if its protected...
if ($true -in $folder_acl.AreAccessRulesProtected) {
    # throw error if it is.
    Write-Error "ACL rules are protected for $INSTALL_LOCATION. please contact security admin."
    exit $ACCESS_PROTECTED_SECURITY
} else {
    # otherwise, modify the ACL itself...
    $folder_acl.SetOwner([System.Security.Principal.NTAccount] "BUILTIN\Administrators")
    $folder_acl.AddAccessRule($god_mode_rule)
}

# then try to apply the ACL to the target folder.
try {
    Set-Acl $INSTALL_LOCATION -AclObject $folder_acl -Passthru
} catch {
    Write-Error "you do not have permissions to write acl for $INSTALL_LOCATION. please contact security admin."
}

# finally, make a shortcut
Write-Host "creating shortcuts for Basket Management System..."
try {
    # create a WScript shell object to create the shortcut
    $wshell = New-Object -ComObject WScript.Shell
    $shortcut = $wshell.CreateShortcut($shortcut_path)

    # set the target path of the shortcut to the target file path
    $shortcut.TargetPath = $bms_exe
    $shortcut.WorkingDirectory = Split-Path $bms_exe
    $shortcut.Save()

    # create a hardlink from the target file path to the link path
    New-Item -ItemType HardLink -Path $shortcut_path -Target $bms_exe -Name "BMS"
}
catch {
    if (-not (Test-Path -Path $shortcut_path)) {
        Write-Host "failed to create shortcut, please make sure you have admin rights!`n`n"
        Exit $SHORTCUT_CREATION_FAILED
    }
}

Write-Host "shortcut created.`ninstallation complete.`n"
# done!
return $SUCCESS

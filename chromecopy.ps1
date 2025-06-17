param (
    [string] $targetuser
)

$ERROR_ZIP_FAIL = -1
$ERROR_COPY_FAIL = -2
$ERROR_USER_NOT_EXIST = -3
$ERROR_INSUFFICIENT_RIGHTS = -4
$TARGET_USER = ""

# check for admin privs and re-launch as admin if not elevated
$current_identity = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $current_identity.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "script requires administrator rights. please re-launch as administrator!"
    # Relaunch the script with administrator rights
    return "error code: ${ERROR_INSUFFICIENT_RIGHTS}"
}

# prompt for the target username whose Chrome profile should be copied, or pull from cmd switch

if ($targetuser) {
    $TARGET_USER = $targetuser
} else {
    $TARGET_USER = Read-Host "enter the target username for the Chrome profile copy"
}

# check the current user's appdata folder for a chrome profile
$CHROME_PROFILE_PATH = "C:\Users\$TARGET_USER\AppData\Local\Google\Chrome\User Data"

if (-not (Test-Path -Path $CHROME_PROFILE_PATH)) {
    Write-Host "chrome profile path not found for user '$TARGET_USER'. check the username and try again." -ForegroundColor Red
    return "exit code: ${ERROR_USER_NOT_EXIST}"
}

# create the zip file name in the format username.chromecopy.ddmmyyyy.zip
$date = (Get-Date).ToString("MMddyyyy")
$output_zip_name = "$TARGET_USER.chromecopy.$date.zip"

# temp location for the zipped file
$temp_zip_path = Join-Path -Path $env:TEMP -ChildPath $output_zip_name

# compress the entire chrome profile folder

Get-Process "chrome" -ErrorAction SilentlyContinue | ForEach-Object {
    write-host "closing google chrome..."
    $_.CloseMainWindow() | Out-Null
    Start-Sleep -Milliseconds 500
    if (!$_.HasExited) { $_.Kill() }
}

try {
    if (Test-Path $temp_zip_path) {
        Write-Host "older temp file exists, removing..."
        remove-item $temp_zip_path -Force
    }
    
    write-host "compressing chrome data..."
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $CHROME_PROFILE_PATH,
        $temp_zip_path,
        [System.IO.Compression.CompressionLevel]::Optimal,
        $false  # true keeps the top folder in the archive, but that's not ideal in this case
    )

    Write-Host "compression complete: $temp_zip_path"
} catch {
    Write-Host "error during compression: $_" -ForegroundColor Red
    return "exit code: ${ERROR_ZIP_FAIL}"
}


$desktop_path = "\\cs-it01\Software\chrome_profiles"
$destination_zip_path = Join-Path -Path $desktop_path -ChildPath $output_zip_name

# copy the zip file to cs-it01 > software > chrome_profiles
try {
    Copy-Item -Path $temp_zip_path -Destination $destination_zip_path -Force
    Write-Host "chrome profile copy created in remote folder: $destination_zip_path"
} catch {
    Write-Host "error while copying zip to remote folder: $_" -ForegroundColor Red
    return "exit code: ${ERROR_COPY_FAIL}"
}

# remove the temporary zip file
Remove-Item -Path $temp_zip_path -Force
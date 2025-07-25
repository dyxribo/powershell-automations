<#!
.SYNOPSIS
    Clone the **basicuser** template and fully provision or update an AD/Azure AD user.
    Compatible with **PowerShell 5.1**.

.EXAMPLE
    .\new_ad_user.ps1 -username klamar \
                      -givenname Kendrick \
                      -surname Lamar \
                      -jobtitle "The Boogeyman" \
                      -department Graphics \
                      -hiredate 2025.02.09 \
                      -company composecure \
                      -manager rkopacz \
                      -office Pierce \
                      -addgroups Graphics,'ZScaler ZIA' \
                      -addazuregroups 'ZScaler Conditional Access' \
                      -primarycompany composecure \
                      -employeeid 1324 \
                      -extension 1234 \
                      -license E3 \
                      -extraattr @{mailNickname='john.doe'}
#>

param(
    # ── identity ───────────────────────────────────────────
    [string]$username,
    [string]$givenname,
    [string]$surname,

    # ── mandatory HR data ─────────────────────────────────
    [string]$jobtitle,
    [string]$department,
    [ValidatePattern('^(?:\d{8}|\d{4}\.\d{2}\.\d{2}|)$')] [string]$hiredate,
    [ValidateSet('composecure', 'arculus')] [string]$company,
    [string]$manager,

    # ── location & phone ──────────────────────────────────
    [ValidateSet('Pierce', 'Davidson', 'Memorial', 'Apgar', 'Remote')] [string]$office,
    [ValidatePattern('^(?:\d{4,6}|TEMP|N/A|)$')] [string]$employeeid = 'N/A',
    [ValidatePattern('^(?:\d{4}|)$')] [string]$extension = '',

    # ── groups & license options ──────────────────────────
    [string[]]$addgroups,
    [string[]]$addazuregroups,
    [ValidateSet('composecure', 'arculus')] [string]$primarycompany = 'composecure',
    [string[]]$license,

    # ── misc ──────────────────────────────────────────────
    [hashtable]$extraattr,
    [switch]$force,
    [switch] $v
)

# ═════════════════════════════════════════════════════════
#  CONSTANTS & MODULES (import **before** any AD cmdlets)
# ═════════════════════════════════════════════════════════
$DOMAIN = 'COMPOSECURE.LOCAL'
$TEMPLATE_SAM = 'basicuser'
$DEFAULT_LOGONFILE = 'MapScript.cmd'
$INTRODUCTIONS = @('howdy, pardner.', 'yippie kye yay, mother dearest.', 'hola, mi amigo.', 'ni hao.', 'que lo que, mama huevos.')

if (-not (Get-Module ActiveDirectory)) { Import-Module ActiveDirectory -ErrorAction Stop }
if (-not (Get-Module AzureAD)) {
    try { Import-Module AzureAD -ErrorAction Stop } catch { Write-Warning 'AzureAD module not available; cloud tasks will be skipped.' }
}

# grab the template once modules are loaded
$TEMPLATE_USER = Get-ADUser $TEMPLATE_SAM -Server $DOMAIN -Properties * -ErrorAction Stop
$TEMPLATE_OU = ($TEMPLATE_USER.DistinguishedName -replace '^CN=[^,]+,')

# ═════════════════════════════════════════════════════════
#  SCRIPT-SCOPED VARIABLES
# ═════════════════════════════════════════════════════════
$script:MANAGER_DN = $null
$script:validated_ad_groups = @()
$script:validated_azure_groups = @()
$script:proxy_addresses = @()
$script:upn = $null
$script:new_user = $null
$script:azure_user = $null

# ═════════════════════════════════════════════════════════
#  FUNCTIONS
# ═════════════════════════════════════════════════════════
function Show-Walkthrough {
    $param_map = @{      # prompts for missing params
        username       = "username (firstinitial + lastname)"
        givenname      = 'first name'
        surname        = 'last name'
        jobtitle       = 'job title'
        department     = 'department'
        hiredate       = 'hire date (YYYYMMDD or YYYY.MM.DD)'
        company        = 'company (composecure|arculus)'
        manager        = 'manager (username)'
        office         = 'office (Pierce|Davidson|Memorial|Apgar|Remote)'
        employeeid     = 'employee id (digits|TEMP|N/A):'
        extension      = 'phone extension (4 digits or blank)'
        primarycompany = 'primary company (composecure|arculus)'
        addgroups      = 'additional AD groups (comma/semicolon separated)'
        addazuregroups = 'additional Azure AD groups (Intune/Entra)'
        license        = 'azure license(s) (comma/semicolon separated)'
    }

    $required = @(
        'username',
        'givenname',
        'surname',
        'jobtitle',
        'department',
        'manager',
        'company',
        'office'
    )
    
    $missing_inputs = $false

    # maps are random, this loop is mostly for prompt order
    for ($i = 0; $i -lt $required.Count; $i++) {
        $k = $required[$i]

        if (-not (Get-Variable $k -ErrorAction SilentlyContinue).Value) {
            if (-not $missing_inputs) {
                $missing_inputs = $true
                $greet = (Get-Random -InputObject $INTRODUCTIONS)
                Write-Host "`n$greet looks like you missed some input(s). i'll walk you through."
            }

            write-host "`nmissing $k.`n" -Foreground Cyan
            $val = Read-Host "-> $($param_map[$k])"

            if ($val) {
                Set-Variable -Name $k -Value $val -Scope Script
                continue
            }
        }   
    }
    
    # then we can do the others in whatever order
    foreach ($k in $param_map.Keys) {
        if (-not (Get-Variable $k -ErrorAction SilentlyContinue).Value) {
            
            write-host "`nmissing $k.`n" -Foreground Cyan
            do {
                $val = Read-Host "-> $($param_map[$k])"
                if ($k -in 'employeeid', 'extension', 'addgroups', 'addazuregroups' -or $val) {
                    Set-Variable -Name $k -Value $val -Scope Script
                    break
                }
            } while ($true)
        }
    }
}

function Test-Manager {
    if ($manager) {
        try { $script:MANAGER_DN = (Get-ADUser $manager -Server $DOMAIN).DistinguishedName }
        catch { throw "manager '$manager' not found in AD." }
    }
}

function Resolve-ADGroupName ([string]$Name) {
    Get-ADGroup -Filter "SamAccountName -like '*$Name*' -or Name -like '*$Name*'" |
        Sort-Object Name | Select-Object -First 1
}

function Resolve-AzureGroupName ([string]$Name) {
    try { Get-AzureADGroup -Filter "startswith(displayName,'$Name')" | Select-Object -First 1 } catch { }
}

function Set-GroupList {
    $localAD = ($addgroups -join ';').Replace(',', ';').Split(';') | Where-Object { $_ }
    $localAAD = ($addazuregroups -join ';').Replace(',', ';').Split(';') | Where-Object { $_ }

    # start with template's memberships
    $script:validated_ad_groups = Get-ADGroup -LDAPFilter (
        "(member:1.2.840.113556.1.4.1941:=$($TEMPLATE_USER.DistinguishedName))"
    )

    # validate all the listed groups, local and cloud
    foreach ($g in $localAD) { if ($r = Resolve-ADGroupName $g) { $script:validated_ad_groups += $r } else { Write-Warning "No on-prem match for '$g'" } }
    foreach ($g in $localAAD) { if ($r = Resolve-AzureGroupName $g) { $script:validated_azure_groups += $r } else { Write-Warning "No Azure match for '$g'" } }
}

function Open-AzureAD {
    if ($addazuregroups -or $license) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Connect-AzureAD -ErrorAction Stop | Out-Null
        } catch { Write-Warning 'AzureAD connect failed; cloud tasks skipped.'; $script:addazuregroups = @(); $script:license = @() }
    }
}

function Set-ProxyAddresses {
    $script:proxy_addresses = @( "smtp:$username@composecure.com", "smtp:$username@arculus.co", "smtp:$username@composecure.mail.onmicrosoft.com" )
    $primaryIndex = @{composecure = 0; arculus = 1 }[$primarycompany]
    $script:proxy_addresses[$primaryIndex] = $script:proxy_addresses[$primaryIndex] -replace '^smtp', 'SMTP'
}

function Show-Confirmation {
    if ($force) { return }

    if ($v) {
        Write-Host '== GROUPS TO BE APPLIED ==' -Foreground Cyan
        ($script:validated_ad_groups + $script:validated_azure_groups) |
            Sort-Object -Property Name -Unique |
            ForEach-Object { Write-Host " - $(if ($_.DisplayName) {$_.DisplayName} else {$_.Name})" }
    }

    Write-Host "$($script:validated_ad_groups.Count + $script:validated_azure_groups.Count) groups will be added."

    if ($license) { Write-Host "`nLicense(s): $($license -join ', ')" }
    if ((Read-Host "`nContinue? (Y/N)").ToUpper() -ne 'Y') { write-host 'Cancelled by user.' }
}

function Set-StandardAttributes {
    $companyDomain = if ($primarycompany -eq 'arculus') { 'arculus.co' } else { 'composecure.com' }
    $script:attr = @{
        mail                       = "$username@$companyDomain"
        proxyAddresses             = $script:proxy_addresses
        scriptPath                 = $DEFAULT_LOGONFILE
        title                      = Capitalize $jobtitle
        department                 = Capitalize $department
        extensionAttribute2        = $hiredate
        company                    = Capitalize $company
        description                = Capitalize $jobtitle
        manager                    = $MANAGER_DN
        physicalDeliveryOfficeName = Capitalize $office
        employeeID                 = $employeeid
        telephoneNumber            = $extension
    }
}

function Capitalize ([string] $phrase) {
    [string[]] $word_list = $phrase.Split(" ")
    [int16] $num_words = $word_list.Count

    if ($word_list.Count -gt 1) {
        for ($i = 0; $i -lt $num_words; $i++) {
            [string] $current_word = $word_list[$i].ToLower()

            if (-not ($current_word -eq 'of' -or $current_word -eq 'and')) {
                $word_list[$i] = CapitalizeWord $current_word
            }

        }
    } else {
        $word_list[0] = CapitalizeWord $word_list[0]
    }
    
    return $word_list -join " "

}

function CapitalizeWord([string] $word) {
    [string[]] $word_char_array = $word.ToCharArray()
    $word_char_array[0] = $word_char_array[0].ToUpper()
    return $word_char_array -join ""
}

function Compare-Secure ([SecureString]$a, [SecureString]$b) {
    $pa = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($a)
    $pb = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($b)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pa) -eq [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pb) } finally {
        if ($pa) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pa) }; if ($pb) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pb) }
    }
}

function Get-ConfirmedPassword {
    do {
        $p1 = Read-Host "initial password for $username" -AsSecureString
        $p2 = Read-Host 'confirm password' -AsSecureString
        if (-not (Compare-Secure $p1 $p2)) { Write-Host '❌ passwords do not match.`n' -Foreground Yellow; continue }

        try {
            New-ADUser -Name 'validation' -SamAccountName 'tmp' -AccountPassword $p1 -Enabled:$false -WhatIf
            return $p1
        } catch {
            Write-Warning 'Password fails complexity; try again.'
        }
    } while ($true)
}

function Update-User {
    $script:new_user = Get-ADUser -Filter "SamAccountName -eq '$username'" -Properties * -ErrorAction SilentlyContinue
    $script:upn = $script:new_user.UserPrincipalName
    $companyDomain = if ($primarycompany -eq 'arculus') { 'arculus.co' } else { 'composecure.com' }

    if ($script:new_user) {
        Write-Host "$username exists - running **update** mode." -Foreground Cyan
        # ensure base attributes & logon script
        foreach ($k in $script:attr.Keys) {
            if (-not $script:new_user.$k -and $null -ne $($script:attr[$k]) ) { 
                if ($v) {
                    write-host "$k : $($script:attr[$k])"
                }
                try {
                    Set-ADUser $script:new_user -Replace @{ $k = $script:attr[$k] } 
                } catch {}
            }
        }
        if (-not $script:new_user.proxyAddresses) {
            Set-ADUser $script:new_user -Add @{proxyAddresses = $proxy_addresses }
        }
    } else {
        # create fresh user
        $secret = Get-ConfirmedPassword
        $script:upn = "$username@$companyDomain"
        New-ADUser -SamAccountName $username -UserPrincipalName $script:upn -Name "$givenname $surname" -GivenName $givenname \ 
        -Surname $surname -DisplayName "$givenname $surname" -Path $TEMPLATE_OU -AccountPassword $secret \ 
        -ChangePasswordAtLogon:$false -Enabled:$true -OtherAttributes $script:attr
    }

    # extras
    if ($extraattr) {
        foreach ($kvp in $extraattr.GetEnumerator()) {
            try { Set-ADUser $script:new_user -Add @{ $kvp.Key = $kvp.Value } }
            catch { Write-Warning "attribute '$($kvp.Key)' invalid - skipped." }
        }
    }
}

function Add-OnPremGroups {
    Write-Host 'Adding on-prem groups...'
    $script:validated_ad_groups | Sort-Object -Unique | ForEach-Object {
        Add-ADGroupMember -Identity $_ -Members $username -ErrorAction SilentlyContinue
    }
}

function Wait-ForAzureSync {
    if (-not (Get-Module AzureAD) -or (-not $addazuregroups -and -not $license)) { return }

    Write-Host "Waiting up to 15 min for Azure sync - tap **S** to skip."
    $timeout = 900; $interval = 60; $elapsed = 0
    while ($elapsed -lt $timeout) {
        if ([Console]::KeyAvailable -and ([Console]::ReadKey($true)).Key -eq 'S') { Write-Warning 'Azure steps skipped by request.'; return }
        $script:azure_user = Get-AzureADUser -ObjectId $script:upn -ErrorAction SilentlyContinue
        if ($script:azure_user) { return }
        Start-Sleep -Seconds 1; $elapsed += $interval
    }
    Write-Warning 'Timed out waiting for Azure; skipping cloud tasks.'
}

function Add-AzureGroups {
    if ($script:azure_user -and $script:validated_azure_groups) {
        foreach ($g in $script:validated_azure_groups) {
            Add-AzureADGroupMember -ObjectId $g.ObjectId -RefObjectId $script:azure_user.ObjectId
        }
    }
}

function Add-AzureLicense {
    if (-not ($script:azure_user -and $license)) { return }
    $skuMap = @{ e3 = 'SPE_E3'; businesspremium = 'SBP' }
    
    foreach ($lic in $license) {
        $sku = Get-AzureADSubscribedSku | Where-Object skuPartNumber -eq $skuMap[$lic]
         
        if ($currentSkuIds -contains $sku.SkuId) {
            if ($v) { Write-Host "$lic already assigned - skipped." }
            continue
        }
        
        if (-not $sku) { Write-Warning "SKU for $lic not found."; continue }

        if ($currentSkuIds -contains $sku.SkuId) {
            if ($v) { Write-Host "$lic already assigned - skipped." }
            continue
        }

        $free = $sku.prepaidunits.enabled - $sku.consumedunits
        if ($free -le 0) { Write-Warning "No seats left for $lic license."; continue }
        if ((Read-Host "assign $lic to $script:username? (y/n)").ToUpper() -ne 'Y') { continue }
        if (-not $script:azure_user.usageLocation) { Set-AzureADUser -ObjectId $script:azure_user.ObjectId -UsageLocation US }
        $add = New-Object Microsoft.Open.AzureAD.Model.AssignedLicense; $add.SkuId = $sku.SkuId
        $pack = New-Object Microsoft.Open.AzureAD.Model.AssignedLicenses; $pack.AddLicenses = $add; $pack.RemoveLicenses = @()
        Set-AzureADUserLicense -ObjectId $script:azure_user.ObjectId -AssignedLicenses $pack
    }
}

function MAIN {
    Show-Walkthrough
    Test-Manager
    Set-ProxyAddresses
    Set-StandardAttributes
    Open-AzureAD
    Set-GroupList
    Show-Confirmation
    Update-User
    Add-OnPremGroups
    Wait-ForAzureSync
    Add-AzureGroups
    Add-AzureLicense
    Write-Host "`n$givenname $surname's account was created/updated successfully! :)`n" -ForegroundColor Green
}

MAIN

# @author   Deron Decamp
# @date     2025-07-23
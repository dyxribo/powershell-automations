<#
.SYNOPSIS
  this script clones the “basicuser” template object with full validation,
  mandatory HR metadata, on-prem & Azure groups, licenses, etc.

.EXAMPLE
  .\new_ad_user.ps1 -username klamar `
                     -givenname Kendrick `
                     -surname Lamar `
                     -jobtitle "The Boogeyman" `
                     -department "Graphics" `
                     -hiredate 2025.02.09 ` # yyyy.mm.dd
                     -company "Composecure" `
                     -manager rkopacz `
                     -office Pierce `
                     -addgroups 'Graphics','ZScaler ZIA' `
                     -addazuregroups 'ZScaler Conditional Access' `
                     -primarycompany composecure `
                     -employeeid 1324 `
                     -extension 1234 `
                     -license E3 `
                     -extraattr @{mailNickname='john.doe';attr2='something.else'}
#>

param(
    # ── identity ─────────────────────────────────────────────
    [string]$username,
    [string]$givenname,
    [string]$surname,

    # ── mandatory HR data ───────────────────────────────────
    [string]$jobtitle,
    [string]$department,
    [ValidatePattern('^(\d{8}|^$)$')][string]$hiredate,
    [ValidateSet('composecure', 'arculus')][string]$company,
    [string]$manager,

    # ── location & phone ────────────────────────────────────
    [ValidateSet('Pierce', 'Davidson', 'Memorial', 'Apgar', 'Remote')]
    [string]$office,
    [ValidatePattern('^\d+$|^(TEMP|N/A|^$)$')]
    [ValidatePattern('^(\d{4,6}|^$)$')][string]$employeeid = 'N/A',
    [ValidatePattern('^(\d{4}|^$)$')]
    [string]$extension,

    # ── groups & license options ────────────────────────────
    [string[]]$addgroups,
    [string[]]$addazuregroups,
    [ValidateSet('composecure', 'arculus')][string]$primarycompany = 'composecure',
    [string[]]$license,

    # ── misc ────────────────────────────────────────────────
    [hashtable]$extra_attributes,
    [switch]$force
)

# ═══════════════════════════════════════════════════════════
#  CONSTANTS, CLASS-SCOPED VARIABLES & MODULES
# ═══════════════════════════════════════════════════════════
$DOMAIN = 'COMPOSECURE.LOCAL'
$TEMPLATE_SAM = 'basicuser'
$DEFAULT_LOGON_SCRIPT = 'MapScript.cmd'
$MANAGER_DN = $manager
$TEMPLATE_USER = Get-ADUser $TEMPLATE_SAM -Server $DOMAIN -Properties * -ErrorAction Stop
$TEMPLATE_OU = ($TEMPLATE_USER.DistinguishedName -replace '^CN=[^,]+,')
$INTRODUCTIONS = @('howdy, pardner.', 'yippie kye yay, mother dearest.', 'hola, mi amigo.', 'ni hao.', 'que lo que, mama huevos.')

Install-Module -Name AzureAD -Scope CurrentUser
Import-Module AzureAD -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

$upn = $null
$proxy_addresses = @()
$attr = $null
$new_user = $null
$validated_ad_groups = @()
$validated_azure_groups = @()

$req_map = @{
    username            = "what's the username for the new user? (this is usually in the format 'firstinitial lastname')"
    givenname           = 'first name?'
    surname             = 'last name?'
    jobtitle            = 'job title?'
    department          = 'department?'
    extensionAttribute2 = 'hire date? (yyyymmdd)'
    company             = 'company (composecure | arculus)?'
    manager             = 'manager (formatted as first initial, last name)?'
    office              = 'office (Pierce | Davidson | Memorial | Apgar | Remote)?'
    employeeid          = 'employee id (digits (0-9+) | TEMP | N/A)?'
    extension           = 'phone extension (4 digits | blank)?'
    primarycompany      = 'primary company  (composecure | arculus)?'
    groups              = 'additional ad group(s) (semi-colon or comma separated)?'
    license             = 'azure license(s) (semi-colon or comma separated)?'
}

# ═══════════════════════════════════════════════════════════
#  FUNCTIONS
# ═══════════════════════════════════════════════════════════

function walkthrough {
    $missing_inputs = $false;

    foreach ($key in $req_map.Keys) {
        if (-not (Get-Variable $key -ErrorAction SilentlyContinue).Value) {
            if (-not $missing_inputs) {
                
                $missing_inputs = $true
                $random_greeting = get-random -InputObject $introductions

                $script:new_user = Get-ADUser -Filter "sAMAccountName -eq '$username'" -ErrorAction SilentlyContinue
                
                if ($null -ne $script:new_user) {
                    Write-Host "$random_greeting looks like you're updating an existing user. only the provided flags will be updated."
                    return
                } else {
                    write-host "`n`n$random_greeting you just ran this script with missing inputs, so i'll walk you through the possible options. :)`n`n"
                }
            }
            do {
                $value = Read-Host "→ $($req_map[$key])"
                # empty strings are allowed for employeeid / extension, so break anyway
                if ($key -in 'employeeid', 'extension' -or $value) {
                    Set-Variable -Name $key -Value $value -Scope Script
                    break
                }
            } while ($true)
        }

        # re-run validation attributes (throws if bad)
        $psboundparameters.Keys |
            Where-Object { $_ -notin 'extra_attributes', 'force' } |
            ForEach-Object { $null = (Get-Variable $_ -Scope Script).Value }
    }
}

function validate_manager {
    try {
        $script:MANAGER_DN = (Get-ADUser $manager -Server $DOMAIN -ErrorAction Stop).DistinguishedName
    } catch {
        if ($null -ne $script:new_user) {
            return
        } else {
            throw "$script:MANAGER_DN not found in AD."
        }
    }
}

function build_group_list {
    # promote the outer variables into this scope
    $script:validated_ad_groups = @()
    $script:validated_azure_groups = @()
    
    $local_add_groups = ($script:addgroups -join ';').Replace(',', ';').Split(';') | Where-Object { $_ }
    $local_add_azure_groups = ($script:addazuregroups -join ';').Replace(',', ';').Split(';') | Where-Object { $_ }

    # we're gonna skip adding the 'Domain Users' group here, 
    # since each user in a domain automatically gets added to it
    # also keep groups as objects so DisplayName property works
    $script:validated_ad_groups = Get-ADPrincipalGroupMembership $TEMPLATE_USER |
        Where-Object SamAccountName -ne 'Domain Users'

    foreach ($g in $local_add_groups) {
        if ($match = resolve_ad_group_name $g) { $script:validated_ad_groups += $match }
        else { Write-Warning "No on-prem match for '$g'" }
    }

    foreach ($g in $local_add_azure_groups) {
        if ($match = resolve_azure_group_name $g) { $script:validated_azure_groups += $match }
        else { Write-Warning "No Azure match for '$g'" }
    }
}

function prepare_azure_tasks {
    if ($addazuregroups -or $license) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Connect-AzureAD -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning 'AzureAD module/connection failed; cloud tasks skipped.'
            $script:license = @()
            $script:azure_groups = @()
        }
    }
}

function display_confirmation_prompt {
    if (-not $force) {
        Write-Host '== GROUPS TO BE APPLIED ==' -Foreground Cyan

        ($script:validated_ad_groups + $azure_groups) |
            ForEach-Object {
                # fall back to Name or bare string if DisplayName is empty
                $label = $_.DisplayName
                if (-not $label) { $label = $_.Name }
                # handle plain strings
                if (-not $label) { $label = $_ }          
                Write-Host " • $label"
            } | Sort-Object -Unique

        if ($license) { Write-Host "`nLicense(s): $($license -join ', ')" }
        if ((Read-Host "`nContinue? (Y/N)").ToUpper() -ne 'Y') { return }
    }
}

function generate_proxy_addresses {
    # we're just gonna add them all in lowercase,
    # then capitalize the prefix based on the primary company arg
    $script:proxy_addresses = @(
        "smtp:$username@composecure.com",
        "smtp:$username@arculus.co",
        "smtp:$username@composecure.mail.onmicrosoft.com"
    )
    $primary_index = @{'composecure' = 0; 'arculus' = 1 }[$primarycompany]
    $script:proxy_addresses[$primary_index] = $script:proxy_addresses[$primary_index] -replace '^smtp', 'SMTP'
}

function validate_standard_attributes {
    # we should, at bare minimum, make sure that each attribute is somewhat valid 
    # by 'auto-correcting' empty/null inputs.
    # could take this further and match specific patterns against each input,
    # which is slightly better for security.
    # but that may or may not be necessary? 
    $company_domain = $(if ($primarycompany -eq 'arculus') { 'arculus.co' } else { 'composecure.com' })
    $script:attr = @{
        mail                       = $(if ($script:username -and $company_domain) { "$username@$company_domain" } else { 'NO USERNAME OR COMPANY DOMAIN' }) 
        proxyAddresses             = $(if ($script:proxyaddresses) { $script:proxyaddresses } else { @() })
        scriptPath                 = $DEFAULT_LOGON_SCRIPT
        title                      = $(if ($script:jobtitle) { $script:jobtitle } else { '' })
        department                 = $(if ($script:department) { $script:department } else { '' })
        extensionAttribute2        = $(if ($script:hiredate) { $script:hiredate } else { '' })
        company                    = $(if ($script:company) { $script:company } else { '' })
        description                = $(if ($script:jobtitle) { $script:jobtitle } else { '' })
        manager                    = $(if ($script:MANAGER_DN) { $script:MANAGER_DN } else { '' })
        physicalDeliveryOfficeName = $(if ($script:office) { $script:office } else { '' })
        employeeID                 = $(if ($script:employeeid) { $script:employeeid } else { '' })
        telephoneNumber            = $(if ($script:extension) { $script:extension } else { 'N/A' })
    }
}

function apply_standard_attributes {
    write-host "applying standard attributes to $script:username"

    try {
        $existing = Get-ADUser -Filter "sAMAccountName -eq '$script:username'" -Properties *

        # add any missing proxy addresses
        $need_proxy = $proxy_addresses | Where-Object { $_ -notin $existing.proxyAddresses }
        
        if ($need_proxy) { 
            write-host "updating proxy addresses..."
            Set-ADUser $existing -Add @{proxyAddresses = $need_proxy } 
        }

        # add mail attribute if blank
        if (-not $existing.mail) {
            write-host "updating email address..."
            $company_domain = $(if ($script:primarycompany -eq 'arculus') { 'arculus.co' } else { 'composecure.com' })
            Set-ADUser $existing -Add @{mail = "$username@$company_domain" }
        }
    } catch {
        Write-Host ($_)
        write-error -Message "error updating proxy and email addresses."
    }
    
}

function apply_extra_attributes {
    # aint forget about them extra  A T T R I B U T E S
    write-host "writing extra attributes to $script:username"
    if ($null -ne $extraattr) {
        foreach ($kvp in $extraattr.GetEnumerator()) {
            try { 
                # validate it first...
                Set-ADUser $template_sam -Add @{ $kvp.Key = $kvp.Value } -WhatIf

                # valid!
                Set-ADUser $template_sam -Add @{ $kvp.Key = $kvp.Value }
                $script:extraattr[$kvp.Key] = $kvp.Value
            } catch { 
                Write-Warning "attribute '$($kvp.Key)' invalid – skipped." 
            }
        }
    }
}

function apply_upn {
    write-host "applying User Principal Name (UPN)..."
    # just wanna make sure that the UPN matches the user's primary company
    $upn_suffix = if ($primarycompany -eq 'composecure') {
        'composecure.com'
    } elseif ($primarycompany -eq 'arculus') {
        'arculus.co'
    } else {
        'composecure.com'
    }
    $script:upn = "$username@$upn_suffix"
}

function resolve_ad_group_name {
    param([string]$Name)
    write-host "resolving group '$Name'..."
    Get-ADGroup -Filter "SamAccountName -like '*$Name*' -or Name -like '*$Name*'" |
        Sort-Object Name | Select-Object -First 1
}

function resolve_azure_group_name {
    param([string]$Name)
    write-host "resolving azure group '$Name'..."
    Get-AzureADGroup -Filter "startswith(displayName,'$Name')"
}

function compare_secure {
    param(
        [System.Security.SecureString]$a,
        [System.Security.SecureString]$b
    )
    # marshal both to plain text only long enough to compare, then zero the buffers
    $pa = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($a)
    $pb = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($b)
    try {
        return ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pa) -eq
            [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pb))
    } finally {
        if ($pa) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pa) }
        if ($pb) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pb) }
    }
}

function get_confirmed_password {
    param([string]$username)

    do {
        $p1 = Read-Host "initial password for $username" -AsSecureString
        $p2 = Read-Host "confirm password" -AsSecureString

        if (-not (compare_secure $p1 $p2)) {
            write-host "❌ passwords don't match! please try again.`n" -foreground yellow
            continue
        }

        try {
            New-ADUser `
                -SamAccountName          "$username" `
                -UserPrincipalName       "$upn" `
                -Name                    "$givenname $surname" `
                -GivenName               "$givenname" `
                -Surname                 "$surname" `
                -DisplayName             "$givenname $surname" `
                -Path                    "$TEMPLATE_OU" `
                -AccountPassword         $password `
                -ChangePasswordAtLogon:  $false `
                -Enabled                 $true `
                -WhatIf
            return $p1 # ✅ good password
        } catch {
            write-warning ($_)
            write-host "password didn't meet complexity requirements. please try again. (14 chars, 1 upper, 1 lower, 1 number, 1 special char)`n"
        }
    } while ($true)
}

function create_user {
    try {
        $script:new_user = Get-ADUser -Filter "SamAccountName -eq '$username'" -Properties *
    } catch {
        if ($null -ne $script:new_user) {
            # most likely error due to already existing, let's switch gears
            Write-Host "$username already exists – switching to **add-only** mode" -Foreground Cyan

            if (-not $script:new_user.scriptPath) {
                Set-ADUser $script:new_user -Add @{scriptPath = $DEFAULT_LOGON_SCRIPT }
            }

            write-host "updating org info..."
            # organization info
            if (-not $script:new_user.title) {
                Set-ADUser $script:new_user -Add @{title = $jobtitle }
            }

            if (-not $script:new_user.department) {
                Set-ADUser $script:new_user -Add @{department = $department }
            }

            if (-not $script:new_user.company) {
                Set-ADUser $script:new_user -Add @{company = $company }
            }

            if (-not $script:new_user.Manager -and $MANAGER_DN) {
                Set-ADUser $script:new_user -Manager $MANAGER_DN
            }

            if (-not $script:new_user.physicalDeliveryOfficeName) {
                Set-ADUser $script:new_user -Add @{physicalDeliveryOfficeName = $office }
            }

            if (-not $script:new_user.employeeID) {
                Set-ADUser $script:new_user -Add @{employeeID = $employeeid }
            }

            if (-not $script:new_user.telephoneNumber) {
                Set-ADUser $script:new_user -Add @{telephoneNumber = $extension }
            }

            # add any missing proxy addresses
            $need_proxy = $proxy_addresses | Where-Object { $_ -notin $script:new_user.proxyAddresses }
            if ($need_proxy) { 
                write-host "updating proxy addresses..."
                Set-ADUser $script:new_user -Add @{proxyAddresses = $need_proxy } 
            }

            # add mail attribute if blank
            if (-not $script:new_user.mail) {
                write-host "updating email address..."
                $company_domain = $(if ($primarycompany -eq 'arculus') { 'arculus.co' } else { 'composecure.com' })
                Set-ADUser $script:new_user -Add @{ mail = "$username@$company_domain" }
            }

            write-host "verifying and updating on-prem groups..."
            # add any missing on-prem groups
            $current_groups = Get-ADPrincipalGroupMembership $script:new_user | Select-Object -Expand SamAccountName
            $script:validated_ad_groups | Where-Object { $_ -notin $current_groups } |
                ForEach-Object { Add-ADGroupMember -Identity $_ -Members $script:new_user }
            
            # only update attributes if some are provided
            if ($extraattr) {
                write-host "verifying and updating extra attributes..."
                validate_standard_attributes
            }

            $update_password = read-host "do you want to update the password for $username? (y|n)"

            if ($update_password -eq 'y' -or $update_password -eq "yes") {
                $pw = (get_confirmed_password) 
                Set-ADUser -AccountPassword $pw

                $change_pw_at_logon = read-host "force $username to change password at logon? (y|n)"

                if ($change_pw_at_logon -eq 'y' -or $change_pw_at_logon -eq "yes") {
                    Set-ADUser -ChangePasswordAtLogon $true
                    write-host "$username will be forced to change their password the next time they log on."
                }
            }

            write-host "verifying azure groups..."
            # azure section is already additive, so just continue into it
            wait_for_azure_sync
            return
        }
    }

    $company_domain = $(if ($primarycompany -eq 'arculus') { 'arculus.co' } else { 'composecure.com' })
    write-host "creating user '$username'..."
    $password = get_confirmed_password -username $username

    # come forth my child
    New-ADUser `
        -SamAccountName          "$username" `
        -UserPrincipalName       "$upn" `
        -Name                    "$givenname $surname" `
        -GivenName               "$givenname" `
        -Surname                 "$surname" `
        -DisplayName             "$givenname $surname" `
        -Path                    "$TEMPLATE_OU" `
        -AccountPassword         $password `
        -ChangePasswordAtLogon:  $false `
        -Enabled                 $true `
        -EmailAddress            $("$username@$company_domain") `
        -ScriptPath              $DEFAULT_LOGON_SCRIPT `
        -Title                   $jobtitle `
        -Department              $department `
        -Company                 $company `
        -Manager                 $MANAGER_DN `
        -Office                  $office `
        -EmployeeID              $employeeid `
        -EmployeeNumber          $extension `
        -Description             $jobtitle       

    
    apply_standard_attributes
    apply_extra_attributes
    add_onprem_groups
    wait_for_azure_sync
    add_azure_groups
    add_azure_license
}

function add_onprem_groups {
    write-host "adding on-prem AD groups..."
    $script:validated_ad_groups | Sort-Object -Unique | ForEach-Object {
        Add-ADGroupMember -Identity $_ -Members $username -ErrorAction SilentlyContinue
    }
}

function wait_for_azure_sync {
    $azure_user = $null
    if ($addazuregroups -or $license) {
        $timeout = 900   # 15 min
        $interval = 60    # 1 min
        $iteration_time = 1
        $iterations = 1

        Write-Host "waiting for $upn to sync to Azure (15 min max).  press **S** to skip wait and continue."

        for (; ($interval * $iterations) -lt $timeout; $iterations += 1) {

            # ── non-blocking key poll ───────────────────────────
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq [ConsoleKey]::S) {
                    Write-Host 'Azure steps skipped by request.'
                    $script:addazuregroups = @()
                    $script:license = @()
                    break
                }
            }
            if ($elapsed -eq $interval) {
                $elapsed = 0
                try {
                    $azure_user = Get-AzureADUser -ObjectId $script:upn -ErrorAction SilentlyContinue
                } catch {   
                    write-host "checked in with azure, $username still not available. waiting 1 min. $(($timeout - ($interval * $iterations)) / 60) min(s) left before skipping."
                }
            }
            
            if ($azure_user) { 
                add_azure_groups
                add_azure_license
                break
            }

            Start-Sleep -Seconds $iteration_time
        }

        if (-not $azure_user -and ($addazuregroups -or $license)) {
            Write-Warning 'user account took too long to sync to azure; cloud tasks skipped.'
            $addazuregroups = @(); $license = @()
        }
    }
}

function add_azure_groups {
    if ($azure_user -and $addazuregroups) {
        foreach ($g in $azure_groups) {
            Add-AzureADGroupMember -ObjectId $g.ObjectId -RefObjectId $azure_user.ObjectId
        }
    }
}

function add_azure_license {
    # license assignment (seat check & per-license confirmation)
    if ($azure_user -and $license) {
        $sku_map = @{ e3 = 'SPE_E3'; businesspremium = 'SBP' }

        foreach ($lic in $license) {
            $lic_sku = get-azureadsubscribedsku |
                where-object skupartnumber -eq $sku_map[$lic]

            if (-not $lic_sku) { write-warning "sku for $lic not found."; continue }

            $free = $lic_sku.prepaidunits.enabled - $lic_sku.consumedunits
            write-host ''
            write-host "license "$lic" → $free licenses available to assign / $($lic_sku.prepaidunits.enabled) licenses total." -foreground cyan
            if ($free -le 0) { write-warning "no seats left for $lic."; continue }

            if ((read-host "assign $lic license to $($azure_user.displayname)? (y/n)").trim().toupper() -ne 'Y') { continue }

            # ensure usage location (mandatory for license assignment)
            if (-not $azure_user.usagelocation) {
                set-azureaduser -objectid $azure_user.objectid -usagelocation US
            }

            # build the objects exactly as AzureAD expects
            $to_add = new-object microsoft.open.azuread.model.assignedlicense
            $to_add.skuId = $lic_sku.skuId

            $lic_pack = new-object microsoft.open.azuread.model.assignedlicenses
            $lic_pack.addlicenses = $to_add        # ← single object, **not** array
            $lic_pack.removelicenses = @()

            set-azureaduserlicense -objectid $azure_user.objectid -assignedlicenses $lic_pack
        }
    }
}

function PERFORMALL {
    validate_manager
    apply_upn
    prepare_azure_tasks
    build_group_list
    generate_proxy_addresses
    display_confirmation_prompt
    validate_standard_attributes
    create_user
}

walkthrough
PERFORMALL



Write-Host "`n✔`tUser $username created and configured! " -Foreground Green


# @author   Deron Decamp (ddecamp@composecure.com)
# @date     6.7.2025
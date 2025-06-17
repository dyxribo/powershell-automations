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
    [Parameter(Mandatory)][string]$username,
    [Parameter(Mandatory)][string]$givenname,
    [Parameter(Mandatory)][string]$surname,

    # ── mandatory HR data ───────────────────────────────────
    [Parameter(Mandatory)][string]$jobtitle,
    [Parameter(Mandatory)][string]$department,
    [Parameter(Mandatory)][string]$company,
    [Parameter(Mandatory)][string]$manager, # pass manager's sAMAccountName

    # ── location & phone ────────────────────────────────────
    [ValidateSet('Pierce', 'Davidson', 'Memorial', 'Apgar', 'Remote')]
    [string]$office = 'Remote',
    [ValidatePattern('^\d+$|^(TEMP|N/A)$')]
    [string]$employeeid = 'N/A',
    [ValidatePattern('^\d{4}$')]
    [string]$extension,

    # ── groups & license options ────────────────────────────
    [string[]]$addgroups,
    [string[]]$addazuregroups,
    [ValidateSet('composecure', 'arculus')][string]$primarycompany = 'composecure',
    [ValidateSet('E3', 'businesspremium')][string[]]$license,

    # ── misc ────────────────────────────────────────────────
    [hashtable]$extraattr,
    [switch]$force
)

# ═══════════════════════════════════════════════════════════
#  CONSTANTS & MODULES
# ═══════════════════════════════════════════════════════════
$DOMAIN = 'COMPOSECURE.LOCAL'
$TEMPLATE_SAM = 'basicuser'
$DEFAULT_LOGON_SCRIPT = 'MapScript.cmd'

Install-Module -Name AzureAD -Scope CurrentUser
Import-Module AzureAD -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

$MANAGER_DN = $manager
$upn = $null
$attr = $null
$template_user = Get-ADUser $TEMPLATE_SAM -Server $DOMAIN -Properties * -ErrorAction Stop
$template_ou = ($template_user.DistinguishedName -replace '^CN=[^,]+,')
$groups = @()
$azure_groups = @()

function validate_manager {
    try {
        $script:MANAGER_DN = (Get-ADUser $manager -Server $DOMAIN -ErrorAction Stop).DistinguishedName
    } catch {
        throw "Manager '$manager' not found in $DOMAIN."
    }
}

function build_group_list {
    # promote the outer variables into this scope
    $script:groups = @()
    $script:azure_groups = @()
    
    $localAddGroups = ($addgroups -join ';').Split(';')      | Where-Object { $_ }
    $localAddAzureGroups = ($addAzureGroups -join ';').Split(';') | Where-Object { $_ }

    # we're gonna skip adding domain users here, 
    # since each user in a domain automatically gets added to it
    # also keep groups as objects so DisplayName property works
    $script:groups = Get-ADPrincipalGroupMembership $template_user |
        Where-Object SamAccountName -ne 'Domain Users'

    foreach ($g in $localAddGroups) {
        if ($match = resolve_ad_group_name $g) { $script:groups += $match }
        else { Write-Warning "No on-prem match for '$g'" }
    }

    foreach ($g in $localAddAzureGroups) {
        if ($match = resolve_azure_group_name $g) { $script:azure_groups += $match }
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
            $license = @()
            $azure_groups = @()
        }
    }
}

function display_confirmation_prompt {
    if (-not $force) {
        Write-Host '== GROUPS TO BE APPLIED ==' -Foreground Cyan

        ($groups + $azure_groups) |
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
    $proxyaddresses = @(
        "smtp:$username@composecure.com",
        "smtp:$username@arculus.co",
        "smtp:$username@composecure.mail.onmicrosoft.com"
    )
    $primary_index = @{'composecure' = 0; 'arculus' = 1 }[$primarycompany]
    $proxyaddresses[$primary_index] = $proxyaddresses[$primary_index] -replace '^smtp', 'SMTP'
}

function validate_extra_attributes {
    # we should, at bare minimum, make sure that each attribute is somewhat valid 
    # by 'auto-correcting' empty/null inputs.
    # could take this further and match specific patterns against each input,
    # which is slightly better for security.
    # but that may or may not be necessary? 
    $company_domain = $(if ($primarycompany -eq 'arculus') { 'arculus.co' } else { 'composecure.com' })
    $script:attr = @{
        mail                       = $(if ($username -and $company_domain) {"$username@$company_domain"} else {'NO USERNAME OR COMPANY DOMAIN'}) 
        proxyAddresses             = $(if ($proxyaddresses) { $proxyaddresses } else {@()})
        scriptPath                 = $DEFAULT_LOGON_SCRIPT
        title                      = $(if ($jobtitle) {$jobtitle} else {''})
        department                 = $(if ($department) {$department} else {''})
        company                    = $(if ($company) {$company} else {''})
        description                = $(if ($jobtitle) {$jobtitle} else {''})
        manager                    = $(if ($MANAGER_DN) {$MANAGER_DN} else {''})
        physicalDeliveryOfficeName = $(if ($office) {$office} else {''})
        employeeID                 = $(if ($employeeid) {$employeeid} else {''})
        telephoneNumber            = $(if ($extension) { $extension } else { 'N/A' })
    }
}

function apply_extra_attributes {
    # aint forget about them extra  A T T R I B U T E S
    write-host "writing extra attributes to $script:username"
    if ($extraattr) {
        foreach ($kvp in $extraattr.GetEnumerator()) {
            try { Set-ADUser $TEMPLATE_SAM -Add @{ ($kvp.Key) = $null } -WhatIf; $script:attr[$kvp.Key] = $kvp.Value }
            catch { Write-Warning "Attribute '$($kvp.Key)' invalid – skipped." }
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
        'COMPOSECURE.LOCAL'
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

function create_user {
    $existing = Get-ADUser -Filter "SamAccountName -eq '$username'" -Properties *

    if ($existing) {

        Write-Host "$username already exists – switching to **add-only** mode" -Foreground Cyan

        if (-not $existing.scriptPath) {
            Set-ADUser $existing -Add @{scriptPath = $DEFAULT_LOGON_SCRIPT }
        }

        write-host "updating org info..."
        # organization info
        if (-not $existing.title) {
            Set-ADUser $existing -Add @{title = $jobtitle }
        }

        if (-not $existing.department) {
            Set-ADUser $existing -Add @{department = $department }
        }

        if (-not $existing.company) {
            Set-ADUser $existing -Add @{company = $company }
        }

        if (-not $existing.Manager -and $MANAGER_DN) {
            Set-ADUser $existing -Manager $MANAGER_DN
        }

        if (-not $existing.physicalDeliveryOfficeName) {
            Set-ADUser $existing -Add @{physicalDeliveryOfficeName = $office }
        }

        if (-not $existing.employeeID) {
            Set-ADUser $existing -Add @{employeeID = $employeeid }
        }

        if (-not $existing.telephoneNumber) {
            Set-ADUser $existing -Add @{telephoneNumber = $extension }
        }

        
        # add any missing proxy addresses
        $needProxy = $proxyAddresses | Where-Object { $_ -notin $existing.proxyAddresses }
        if ($needProxy) { 
            write-host "updating proxy addresses..."
            Set-ADUser $existing -Add @{proxyAddresses = $needProxy } 
        }

        # add mail attribute if blank
        if (-not $existing.mail) {
            write-host "updating email address..."
            $companyDomain = $(if ($primarycompany -eq 'arculus') { 'arculus.co' } else { 'composecure.com' })
            Set-ADUser $existing -Add @{mail = "$username@$companyDomain" }
        }
        write-host "verifying and updating on-prem groups..."
        # add any missing on-prem groups
        $current_groups = Get-ADPrincipalGroupMembership $existing | Select-Object -Expand SamAccountName
        $groups | Where-Object { $_ -notin $current_groups } |
            ForEach-Object { Add-ADGroupMember -Identity $_ -Members $existing }
    
        write-host "verifying and updating extra attributes..."
        if ($extraattr) {
            validate_extra_attributes
        }

        write-host "verifying azure groups..."
        # Azure section is already additive, so just continue into it
        wait_for_azure_sync
    } else {
        write-host "creating user '$username'..."
        $password = Read-Host "please set the initial password for $username" -AsSecureString
        # come forth my child
        New-ADUser `
            -SamAccountName          "$username" `
            -UserPrincipalName       "$upn" `
            -Name                    "$givenname $surname" `
            -GivenName               "$givenname" `
            -Surname                 "$surname" `
            -DisplayName             "$givenname $surname" `
            -Path                    "$template_ou" `
            -AccountPassword         "$password" `
            -ChangePasswordAtLogon:  $false `
            -Enabled                 $true `
            -OtherAttributes         $script:attr

        apply_extra_attributes
        add_onprem_groups
        wait_for_azure_sync
        add_azure_groups
        add_azure_license
    }
    
}

function add_onprem_groups {
    write-host "adding on-prem AD groups..."
    $groups | Sort-Object -Unique | ForEach-Object {
        Add-ADGroupMember -Identity $_ -Members $username -ErrorAction SilentlyContinue
    }
}

function wait_for_azure_sync {
    $azure_user = $null
    if ($addazuregroups -or $license) {
        $timeout = 900   # 15 min
        $interval = 60    # 1 min

        Write-Host "waiting for $upn to sync to Azure (15 min max).  Press **S** to skip wait and continue."

        for ($elapsed = 0; $elapsed -lt $timeout; $elapsed += $interval) {

            # ── non-blocking key poll ───────────────────────────
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq [ConsoleKey]::S) {
                    # ← enum comparison
                    Write-Host 'Azure steps skipped by request.'
                    $script:addazuregroups = @()          # clear *script-level* vars
                    $script:license = @()
                    break
                }
            }

            $azure_user = Get-AzureADUser -ObjectId $script:upn -ErrorAction SilentlyContinue
            if ($azure_user) { 
                add_azure_groups
                add_azure_license
                break
            }

            Start-Sleep -Seconds $interval
        }

        if (-not $azure_user -and ($addAzureGroups -or $license)) {
            Write-Warning 'user account took too long to sync to azure; cloud tasks skipped.'
            $addAzureGroups = @(); $license = @()
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

validate_manager
apply_upn
prepare_azure_tasks
build_group_list
generate_proxy_addresses
display_confirmation_prompt
validate_extra_attributes
create_user

Write-Host "`n✔`tUser $username created and configured! " -Foreground Green


# @author   Deron Decamp (ddecamp@composecure.com)
# @date     6.7.2025
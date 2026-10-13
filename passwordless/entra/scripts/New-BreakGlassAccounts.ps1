#Requires -Version 7.2
<#
.SYNOPSIS
  Creates two cloud-only emergency-access accounts, a CA exclusion group, and assigns Global Administrator.

.DESCRIPTION
  Run this FIRST. Every Conditional Access policy in this repo excludes the group this script creates,
  so a policy mistake can never lock the tenant. After it runs:
    1. Register a FIDO2 security key for each account (Security info page, sign in with the printed password once).
    2. Put the keys and the printed passwords in two separate physical safes.
    3. Paste the group id into entra/config.json -> placeholders.BREAK_GLASS_GROUP_ID.
    4. Alert on any sign-in by these accounts (see docs/99-rollout-runbook.md for the KQL).

.PARAMETER Domain
  Verified domain for the UPNs, e.g. contoso.onmicrosoft.com (use the .onmicrosoft.com domain so federation outages cannot affect them).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$Domain,
    [int]$Count = 2
)
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$config = Import-PasswordlessConfig -AllowMissingPlaceholders
$null = Connect-PasswordlessGraph -TenantId $config.tenantId -Scopes @('User.ReadWrite.All', 'Group.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'Directory.Read.All')

$prefix = $config.breakGlass.userPrefix
$groupName = $config.breakGlass.groupName
$globalAdminTemplate = '62e90394-69f5-4237-9190-012177145e10'

# Group (idempotent)
$existing = Get-GraphCollection -Uri "groups?`$filter=displayName eq '$groupName'&`$select=id,displayName"
if ($existing.Count -gt 0) {
    $group = $existing[0]
    Write-Host "Group '$groupName' already exists: $($group.id)"
}
else {
    $body = @{ displayName = $groupName; mailEnabled = $false; mailNickname = ($groupName -replace '[^A-Za-z0-9]', ''); securityEnabled = $true; description = 'Emergency access accounts. Excluded from all Conditional Access policies. Membership changes must be alerted on.' } | ConvertTo-Json
    $group = Invoke-GraphJson -Method POST -Uri 'groups' -Body $body
    Write-Host "Created group '$groupName': $($group.id)"
}

$created = @()
for ($i = 1; $i -le $Count; $i++) {
    $upn = ('{0}-{1:d2}@{2}' -f $prefix, $i, $Domain)
    $found = Get-GraphCollection -Uri "users?`$filter=userPrincipalName eq '$upn'&`$select=id,userPrincipalName"
    if ($found.Count -gt 0) {
        Write-Host "User $upn already exists: $($found[0].id)"
        $user = $found[0]
    }
    else {
        $password = New-RandomPassword -Length 64
        $body = @{
            accountEnabled = $true
            displayName = "Emergency Access $i"
            mailNickname = ('{0}-{1:d2}' -f $prefix, $i)
            userPrincipalName = $upn
            usageLocation = 'US'
            passwordPolicies = 'DisablePasswordExpiration'
            passwordProfile = @{ password = $password; forceChangePasswordNextSignIn = $false }
        } | ConvertTo-Json -Depth 5
        $user = Invoke-GraphJson -Method POST -Uri 'users' -Body $body
        if ($user) {
            $created += [pscustomobject]@{ UserPrincipalName = $upn; Id = $user.id; Password = $password }
        }
    }
    if ($user) {
        $memberBody = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.id)" } | ConvertTo-Json
        try { Invoke-GraphJson -Method POST -Uri "groups/$($group.id)/members/`$ref" -Body $memberBody | Out-Null } catch { if ($_ -notmatch 'already exist') { throw } }
        $roleBody = @{ '@odata.type' = '#microsoft.graph.unifiedRoleAssignment'; roleDefinitionId = $globalAdminTemplate; principalId = $user.id; directoryScopeId = '/' } | ConvertTo-Json
        try { Invoke-GraphJson -Method POST -Uri 'roleManagement/directory/roleAssignments' -Body $roleBody | Out-Null } catch { if ($_ -notmatch 'conflict|already exist') { throw } }
    }
}

Write-Host ''
Write-Host '==== RECORD THESE NOW; THEY ARE NOT STORED ANYWHERE ====' -ForegroundColor Yellow
$created | Format-List
Write-Host "Break-glass group id (put in entra/config.json -> placeholders.BREAK_GLASS_GROUP_ID): $($group.id)" -ForegroundColor Green
Write-Host 'Next: register two FIDO2 keys per account, store offline, and set up the sign-in alert.'

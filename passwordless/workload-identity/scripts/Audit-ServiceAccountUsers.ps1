#Requires -Version 7.2
<#
.SYNOPSIS
  Finds human-style accounts that behave like service accounts (passwords that never expire, no MFA methods,
  naming patterns like svc/service/automation/bot) and recommends a replacement identity type.
#>
[CmdletBinding()]
param(
    [string]$OutFile = './service-account-users.csv',
    [string[]]$NamePatterns = @('svc', 'service', 'automation', 'bot', 'scanner', 'backup', 'sync', 'noreply', 'no-reply')
)
Import-Module (Join-Path $PSScriptRoot '..' '..' 'entra' 'scripts' 'Common.psm1') -Force
$config = Import-PasswordlessConfig -AllowMissingPlaceholders
$null = Connect-PasswordlessGraph -TenantId $config.tenantId -Scopes @('User.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All')

$registration = @{}
foreach ($r in Get-GraphCollection -Uri 'reports/authenticationMethods/userRegistrationDetails') { $registration[$r.userPrincipalName.ToLowerInvariant()] = $r }

$rows = foreach ($u in Get-GraphCollection -Uri 'users?$select=id,userPrincipalName,displayName,accountEnabled,userType,passwordPolicies,createdDateTime,signInActivity&$top=999') {
    $upn = $u.userPrincipalName.ToLowerInvariant()
    $nameHit = ($NamePatterns | Where-Object { $upn -match $_ -or ($u.displayName -and $u.displayName.ToLowerInvariant() -match $_) }).Count -gt 0
    $neverExpires = $u.passwordPolicies -match 'DisablePasswordExpiration'
    $reg = $registration[$upn]
    $noMfa = $reg -and -not $reg.isMfaRegistered
    $lastInteractive = $u.signInActivity.lastSignInDateTime
    $lastNonInteractive = $u.signInActivity.lastNonInteractiveSignInDateTime
    $score = @($nameHit, $neverExpires, $noMfa, ($lastNonInteractive -and -not $lastInteractive)) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
    if ($score -eq 0) { continue }
    [pscustomobject]@{
        UserPrincipalName      = $u.userPrincipalName
        Enabled                = $u.accountEnabled
        NamePattern            = $nameHit
        PasswordNeverExpires   = $neverExpires
        NoMfaRegistered        = $noMfa
        LastInteractiveSignIn  = $lastInteractive
        LastNonInteractive     = $lastNonInteractive
        Score                  = $score
        Recommendation         = if ($score -ge 3) { 'REPLACE: managed identity / SP certificate / federated credential, then disable' } elseif ($score -eq 2) { 'REVIEW: likely automation; move to workload identity' } else { 'CHECK owner; enforce passkey if human' }
    }
}

$rows | Sort-Object -Property Score -Descending | Export-Csv -Path $OutFile -NoTypeInformation -Encoding utf8
$rows | Sort-Object -Property Score -Descending | Format-Table UserPrincipalName, Score, NamePattern, PasswordNeverExpires, NoMfaRegistered, Recommendation -AutoSize
Write-Host "Detail: $OutFile"

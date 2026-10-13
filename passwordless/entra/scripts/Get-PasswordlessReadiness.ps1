#Requires -Version 7.2
<#
.SYNOPSIS
  Reports who can already sign in passwordless / phishing-resistant, and who still depends on passwords, SMS or voice.

.OUTPUTS
  CSV at the path given by -OutFile (default ./passwordless-readiness.csv) and a console summary.
#>
[CmdletBinding()]
param(
    [string]$OutFile = './passwordless-readiness.csv'
)
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$config = Import-PasswordlessConfig -AllowMissingPlaceholders
$null = Connect-PasswordlessGraph -TenantId $config.tenantId -Scopes @('AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'User.Read.All')

$phishingResistant = @('passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello', 'fido2SecurityKey', 'windowsHelloForBusiness', 'x509Certificate', 'x509CertificateMultiFactor', 'passKeySynced')
$passwordlessOnly = @('microsoftAuthenticatorPasswordless')
$weak = @('mobilePhone', 'alternateMobilePhone', 'officePhone', 'email', 'securityQuestion', 'sms', 'voice')

$rows = Get-GraphCollection -Uri 'reports/authenticationMethods/userRegistrationDetails' | ForEach-Object {
    $methods = @($_.methodsRegistered)
    $hasPr = ($methods | Where-Object { $phishingResistant -contains $_ }).Count -gt 0
    $hasPwdless = $hasPr -or (($methods | Where-Object { $passwordlessOnly -contains $_ }).Count -gt 0)
    $hasWeak = ($methods | Where-Object { $weak -contains $_ }).Count -gt 0
    [pscustomobject]@{
        UserPrincipalName        = $_.userPrincipalName
        IsAdmin                  = $_.isAdmin
        MfaRegistered            = $_.isMfaRegistered
        PhishingResistant        = $hasPr
        PasswordlessCapable      = $hasPwdless
        WeakMethodsPresent       = $hasWeak
        SystemPreferredMethod    = $_.systemPreferredAuthenticationMethods -join ';'
        MethodsRegistered        = $methods -join ';'
        LastUpdated              = $_.lastUpdatedDateTime
        Recommendation           = if (-not $hasPwdless) { 'ISSUE TAP + REGISTER PASSKEY' } elseif (-not $hasPr) { 'ADD PASSKEY/WHfB (phone sign-in is not phishing-resistant)' } elseif ($hasWeak) { 'REMOVE SMS/VOICE/EMAIL' } else { 'READY' }
    }
}

$rows | Export-Csv -Path $OutFile -NoTypeInformation -Encoding utf8
$total = $rows.Count
Write-Host ("Users: {0}  Phishing-resistant: {1}  Passwordless-capable: {2}  Still weak methods: {3}" -f $total, ($rows | Where-Object PhishingResistant).Count, ($rows | Where-Object PasswordlessCapable).Count, ($rows | Where-Object WeakMethodsPresent).Count)
Write-Host "Admins without phishing-resistant method: $(($rows | Where-Object { $_.IsAdmin -and -not $_.PhishingResistant } | ForEach-Object UserPrincipalName) -join ', ')"
Write-Host "Detail: $OutFile"
$rows | Group-Object Recommendation | Select-Object Name, Count | Format-Table -AutoSize

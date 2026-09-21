#Requires -Version 7.2
<#
.SYNOPSIS
  Issues a Temporary Access Pass so a user can register a passkey / Windows Hello without ever using a password.

.EXAMPLE
  ./New-OnboardingTAP.ps1 -UserPrincipalName fayek@contoso.com -LifetimeMinutes 60
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$UserPrincipalName,
    [ValidateRange(10, 480)] [int]$LifetimeMinutes = 60,
    [switch]$UsableOnce
)
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$config = Import-PasswordlessConfig -AllowMissingPlaceholders
$null = Connect-PasswordlessGraph -TenantId $config.tenantId -Scopes @('UserAuthenticationMethod.ReadWrite.All')

$body = @{ lifetimeInMinutes = $LifetimeMinutes; isUsableOnce = [bool]$UsableOnce } | ConvertTo-Json
$tap = Invoke-GraphJson -Method POST -Uri "users/$UserPrincipalName/authentication/temporaryAccessPassMethods" -Body $body
if ($tap) {
    Write-Host "Temporary Access Pass for $UserPrincipalName (valid $LifetimeMinutes min, usable once: $([bool]$UsableOnce)):" -ForegroundColor Yellow
    Write-Host $tap.temporaryAccessPass -ForegroundColor Green
    Write-Host 'Hand it over out-of-band (call / in person). Have the user go to https://aka.ms/mysecurityinfo and add a passkey.'
}

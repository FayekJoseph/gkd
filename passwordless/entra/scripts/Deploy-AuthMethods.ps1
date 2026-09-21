#Requires -Version 7.2
<#
.SYNOPSIS
  Applies the authentication methods policy: passkeys (FIDO2), Authenticator with phone sign-in, Temporary Access Pass.

.DESCRIPTION
  -Phase 1 enables the passwordless methods (safe at any time).
  -Phase 2 disables SMS, voice, email OTP and software OATH. Run it only after Get-PasswordlessReadiness.ps1
  shows every active user has a passkey or Windows Hello registered.
  Also creates the 'c1' authentication context used by CA008 and the zta-gateway.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet(1, 2)] [int]$Phase = 1
)
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$config = Import-PasswordlessConfig -AllowMissingPlaceholders
$null = Connect-PasswordlessGraph -TenantId $config.tenantId -Scopes @('Policy.ReadWrite.AuthenticationMethod', 'Policy.ReadWrite.ConditionalAccess')

$root = Join-Path (Get-PasswordlessRoot) 'entra'
$folder = if ($Phase -eq 1) { Join-Path $root 'authentication-methods' } else { Join-Path $root 'authentication-methods' 'phase2-disable' }

foreach ($file in Get-ChildItem -Path $folder -Filter '*.json' -File) {
    $json = Get-Content -Raw -Path $file.FullName
    $obj = $json | ConvertFrom-Json
    Write-Host "PATCH authenticationMethodConfigurations/$($obj.id) <- $($file.Name)"
    Invoke-GraphJson -Method PATCH -Uri "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$($obj.id)" -Body $json | Out-Null
}

if ($Phase -eq 1) {
    foreach ($file in Get-ChildItem -Path (Join-Path $root 'authentication-contexts') -Filter '*.json' -File) {
        $obj = Get-Content -Raw -Path $file.FullName | ConvertFrom-Json
        $body = @{ displayName = $obj.displayName; description = $obj.description; isAvailable = $obj.isAvailable } | ConvertTo-Json
        Write-Host "PATCH authenticationContextClassReferences/$($obj.id) <- $($file.Name)"
        Invoke-GraphJson -Method PATCH -Uri "identity/conditionalAccess/authenticationContextClassReferences/$($obj.id)" -Body $body | Out-Null
    }
}

Write-Host 'Current state:'
(Get-GraphCollection -Uri 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations') | Select-Object id, state | Format-Table -AutoSize

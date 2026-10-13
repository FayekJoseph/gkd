#Requires -Version 7.2
<#
.SYNOPSIS
  Makes a user's password unknowable: sets a random 64-character password that is never displayed or stored.

.DESCRIPTION
  Entra cannot delete a cloud password yet, but once a user has a passkey / Windows Hello registered and the
  CA policies require passwordless strength, the password is dead weight that can still be phished for
  legacy endpoints. Scrambling it removes that. Refuses to touch break-glass accounts.
  Requires Password Administrator (or higher) and that the target user is not an admin unless -IncludeAdmins.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory, ValueFromPipeline)] [string[]]$UserPrincipalName,
    [switch]$IncludeAdmins
)
begin {
    Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
    $config = Import-PasswordlessConfig
    $null = Connect-PasswordlessGraph -TenantId $config.tenantId -Scopes @('User.ReadWrite.All', 'UserAuthenticationMethod.Read.All', 'Directory.Read.All')
    $breakGlass = @(Get-GraphCollection -Uri "groups/$($config.placeholders.BREAK_GLASS_GROUP_ID)/members?`$select=userPrincipalName" | ForEach-Object { $_.userPrincipalName.ToLowerInvariant() })
}
process {
    foreach ($upn in $UserPrincipalName) {
        if ($breakGlass -contains $upn.ToLowerInvariant()) {
            Write-Warning "$upn is a break-glass account. Skipped."
            continue
        }
        $methods = Get-GraphCollection -Uri "users/$upn/authentication/methods"
        $strong = $methods | Where-Object { $_.'@odata.type' -in @('#microsoft.graph.fido2AuthenticationMethod', '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod', '#microsoft.graph.platformCredentialAuthenticationMethod') }
        if (-not $strong) {
            Write-Warning "$upn has no passkey or Windows Hello registered. Skipped so they are not locked out."
            continue
        }
        if ($PSCmdlet.ShouldProcess($upn, 'Replace password with an unknown random value')) {
            $body = @{ passwordProfile = @{ password = (New-RandomPassword -Length 64); forceChangePasswordNextSignIn = $false } } | ConvertTo-Json -Depth 3
            Invoke-GraphJson -Method PATCH -Uri "users/$upn" -Body $body | Out-Null
            Write-Host "$upn : password scrambled. Registered strong methods: $($strong.Count)"
        }
    }
}

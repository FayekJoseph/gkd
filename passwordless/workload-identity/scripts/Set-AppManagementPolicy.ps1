#Requires -Version 7.2
<#
.SYNOPSIS
  Applies the tenant default app management policy: no new client secrets, short lifetimes for what remains.

.DESCRIPTION
  Requires Workload Identities Premium for enforcement of the default policy. Apps that legitimately need a
  secret for a short migration window can be exempted with a custom appManagementPolicy assigned to that app.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [datetime]$CutoverDateTime = [DateTime]::UtcNow
)
Import-Module (Join-Path $PSScriptRoot '..' '..' 'entra' 'scripts' 'Common.psm1') -Force
$config = Import-PasswordlessConfig -AllowMissingPlaceholders
$null = Connect-PasswordlessGraph -TenantId $config.tenantId -Scopes @('Policy.ReadWrite.ApplicationConfiguration')

$path = Join-Path (Get-PasswordlessRoot) 'workload-identity' 'policies' 'default-app-management-policy.json'
$json = Expand-Placeholders -Json (Get-Content -Raw -Path $path) -Placeholders @{ CUTOVER_DATETIME = $CutoverDateTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } -Source 'default-app-management-policy.json'
$obj = $json | ConvertFrom-Json -AsHashtable
$obj.Remove('$comment')
Invoke-GraphJson -Method PATCH -Uri 'policies/defaultAppManagementPolicy' -Body ($obj | ConvertTo-Json -Depth 10) | Out-Null
Write-Host 'Default app management policy applied:'
Invoke-GraphJson -Method GET -Uri 'policies/defaultAppManagementPolicy' | ConvertTo-Json -Depth 10

#Requires -Version 7.2
<#
.SYNOPSIS
  Adds a workload identity federation credential to an app registration (e.g. GitHub Actions OIDC), so the
  pipeline needs no stored secret at all.

.EXAMPLE
  ./New-FederatedCredential.ps1 -AppId <guid> -DefinitionFile ../federated-credentials/github-actions.json
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$AppId,
    [string]$DefinitionFile = (Join-Path $PSScriptRoot '..' 'federated-credentials' 'github-actions.json')
)
Import-Module (Join-Path $PSScriptRoot '..' '..' 'entra' 'scripts' 'Common.psm1') -Force
$config = Import-PasswordlessConfig -AllowMissingPlaceholders
$null = Connect-PasswordlessGraph -TenantId $config.tenantId -Scopes @('Application.ReadWrite.All')

$apps = Get-GraphCollection -Uri "applications?`$filter=appId eq '$AppId'&`$select=id,displayName"
if ($apps.Count -ne 1) { throw "App registration with appId $AppId not found." }
$def = Get-Content -Raw -Path $DefinitionFile | ConvertFrom-Json -AsHashtable
$def.Remove('$comment')
$existing = Get-GraphCollection -Uri "applications/$($apps[0].id)/federatedIdentityCredentials" | Where-Object { $_.name -eq $def.name }
if ($existing) {
    $patch = @{}
    foreach ($k in $def.Keys) { if ($k -ne 'name') { $patch[$k] = $def[$k] } }
    Invoke-GraphJson -Method PATCH -Uri "applications/$($apps[0].id)/federatedIdentityCredentials/$($existing[0].id)" -Body ($patch | ConvertTo-Json) | Out-Null
    Write-Host "Updated federated credential '$($def.name)' on $($apps[0].displayName)"
}
else {
    Invoke-GraphJson -Method POST -Uri "applications/$($apps[0].id)/federatedIdentityCredentials" -Body ($def | ConvertTo-Json) | Out-Null
    Write-Host "Created federated credential '$($def.name)' on $($apps[0].displayName)"
}
Write-Host "In the workflow: permissions: id-token: write; then azure/login@v2 with client-id $AppId, tenant-id $($config.tenantId) and no secret."

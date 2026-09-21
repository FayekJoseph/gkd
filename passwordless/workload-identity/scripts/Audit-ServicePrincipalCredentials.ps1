#Requires -Version 7.2
<#
.SYNOPSIS
  Inventories every app registration and service principal credential: secrets vs certificates, expiry, owners.

.DESCRIPTION
  Output is a CSV with one row per credential plus a console summary. Anything with CredentialType = Secret is a
  migration item for Convert-SecretToCertificate.ps1 (or, better, a managed identity / federated credential).
#>
[CmdletBinding()]
param(
    [string]$OutFile = './service-principal-credentials.csv'
)
Import-Module (Join-Path $PSScriptRoot '..' '..' 'entra' 'scripts' 'Common.psm1') -Force
$config = Import-PasswordlessConfig -AllowMissingPlaceholders
$null = Connect-PasswordlessGraph -TenantId $config.tenantId -Scopes @('Application.Read.All', 'Directory.Read.All')

$rows = [System.Collections.Generic.List[object]]::new()
$now = [DateTime]::UtcNow

function Add-CredentialRows {
    param($Object, [string]$ObjectType)
    $owners = try { (Get-GraphCollection -Uri "$($ObjectType)s/$($Object.id)/owners?`$select=userPrincipalName,displayName" | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } }) -join ';' } catch { '' }
    foreach ($c in @($Object.passwordCredentials)) {
        $end = [DateTime]$c.endDateTime
        $rows.Add([pscustomobject]@{ ObjectType = $ObjectType; DisplayName = $Object.displayName; AppId = $Object.appId; ObjectId = $Object.id; CredentialType = 'Secret'; CredentialName = $c.displayName; KeyId = $c.keyId; Expires = $end; DaysLeft = [int]($end - $now).TotalDays; Owners = $owners; Action = 'REPLACE WITH CERT / MANAGED IDENTITY / FEDERATION' })
    }
    foreach ($c in @($Object.keyCredentials)) {
        $end = [DateTime]$c.endDateTime
        $days = [int]($end - $now).TotalDays
        $rows.Add([pscustomobject]@{ ObjectType = $ObjectType; DisplayName = $Object.displayName; AppId = $Object.appId; ObjectId = $Object.id; CredentialType = "Certificate ($($c.type)/$($c.usage))"; CredentialName = $c.displayName; KeyId = $c.keyId; Expires = $end; DaysLeft = $days; Owners = $owners; Action = if ($days -lt 30) { 'ROTATE SOON' } elseif ($days -gt 400) { 'LIFETIME TOO LONG' } else { 'OK' } })
    }
    if (-not $Object.passwordCredentials -and -not $Object.keyCredentials) {
        $rows.Add([pscustomobject]@{ ObjectType = $ObjectType; DisplayName = $Object.displayName; AppId = $Object.appId; ObjectId = $Object.id; CredentialType = 'None'; CredentialName = ''; KeyId = ''; Expires = $null; DaysLeft = $null; Owners = $owners; Action = 'OK (no credential)' })
    }
}

Write-Host 'Reading app registrations...'
foreach ($app in Get-GraphCollection -Uri 'applications?$select=id,appId,displayName,passwordCredentials,keyCredentials&$top=999') { Add-CredentialRows -Object $app -ObjectType 'application' }
Write-Host 'Reading service principals owned by this tenant...'
foreach ($sp in Get-GraphCollection -Uri "servicePrincipals?`$filter=servicePrincipalType eq 'Application'&`$select=id,appId,displayName,passwordCredentials,keyCredentials,appOwnerOrganizationId&`$top=999") {
    if ($sp.appOwnerOrganizationId -eq $config.tenantId -and ($sp.passwordCredentials -or $sp.keyCredentials)) { Add-CredentialRows -Object $sp -ObjectType 'servicePrincipal' }
}
Write-Host 'Reading federated identity credentials (secretless, informational)...'
foreach ($app in Get-GraphCollection -Uri 'applications?$select=id,appId,displayName&$top=999') {
    foreach ($f in Get-GraphCollection -Uri "applications/$($app.id)/federatedIdentityCredentials") {
        $rows.Add([pscustomobject]@{ ObjectType = 'application'; DisplayName = $app.displayName; AppId = $app.appId; ObjectId = $app.id; CredentialType = 'Federated'; CredentialName = "$($f.name) <- $($f.issuer) [$($f.subject)]"; KeyId = $f.id; Expires = $null; DaysLeft = $null; Owners = ''; Action = 'OK (secretless)' })
    }
}

$rows | Sort-Object CredentialType, DaysLeft | Export-Csv -Path $OutFile -NoTypeInformation -Encoding utf8
$secrets = @($rows | Where-Object CredentialType -eq 'Secret')
Write-Host ''
Write-Host ("Credentials: {0}   Secrets to eliminate: {1}   Expiring <30d: {2}" -f $rows.Count, $secrets.Count, @($rows | Where-Object { $_.DaysLeft -ne $null -and $_.DaysLeft -lt 30 }).Count) -ForegroundColor Yellow
$secrets | Select-Object DisplayName, AppId, CredentialName, DaysLeft, Owners | Format-Table -AutoSize
Write-Host "Detail: $OutFile"

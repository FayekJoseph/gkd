#Requires -Version 7.2
<#
.SYNOPSIS
  Creates (or updates) the trusted IP named location used by CA009 from config.trustedIpRanges.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$DisplayName = 'Trusted egress IPs'
)
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$config = Import-PasswordlessConfig -AllowMissingPlaceholders
$null = Connect-PasswordlessGraph -TenantId $config.tenantId -Scopes @('Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All')

$ranges = @($config.trustedIpRanges | ForEach-Object {
        $type = if ($_ -match ':') { '#microsoft.graph.iPv6CidrRange' } else { '#microsoft.graph.iPv4CidrRange' }
        @{ '@odata.type' = $type; cidrAddress = $_ }
    })
if ($ranges.Count -eq 0) { throw 'config.trustedIpRanges is empty.' }

$body = @{ '@odata.type' = '#microsoft.graph.ipNamedLocation'; displayName = $DisplayName; isTrusted = $true; ipRanges = $ranges } | ConvertTo-Json -Depth 5
$existing = Get-GraphCollection -Uri "identity/conditionalAccess/namedLocations?`$filter=displayName eq '$DisplayName'"
if ($existing.Count -gt 0) {
    Invoke-GraphJson -Method PATCH -Uri "identity/conditionalAccess/namedLocations/$($existing[0].id)" -Body $body | Out-Null
    $id = $existing[0].id
    Write-Host "Updated named location '$DisplayName': $id"
}
else {
    $loc = Invoke-GraphJson -Method POST -Uri 'identity/conditionalAccess/namedLocations' -Body $body
    $id = $loc.id
    Write-Host "Created named location '$DisplayName': $id"
}
Write-Host "Put this in entra/config.json -> placeholders.TRUSTED_NAMED_LOCATION_ID: $id" -ForegroundColor Green

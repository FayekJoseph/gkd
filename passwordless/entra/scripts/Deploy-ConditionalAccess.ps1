#Requires -Version 7.2
<#
.SYNOPSIS
  Creates or updates the Conditional Access policies in entra/conditional-access, by display name.

.DESCRIPTION
  Policies are committed in report-only state. This script sets the state you ask for:
    -Mode ReportOnly  (default) enabledForReportingButNotEnforced
    -Mode Enforce     enabled   - refuses to run unless the break-glass group exists and has members
    -Mode Disable     disabled  - rollback
  Use -Only to target a subset, e.g. -Only CA001,CA002. Licensing notes are in the policy names (P2, Workload ID Premium).

.EXAMPLE
  ./Deploy-ConditionalAccess.ps1                       # everything, report-only
  ./Deploy-ConditionalAccess.ps1 -Mode Enforce -Only CA001,CA002,CA005
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('ReportOnly', 'Enforce', 'Disable')] [string]$Mode = 'ReportOnly',
    [string[]]$Only
)
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$config = Import-PasswordlessConfig
$null = Connect-PasswordlessGraph -TenantId $config.tenantId -Scopes @('Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Application.Read.All', 'Group.Read.All')

$state = switch ($Mode) { 'ReportOnly' { 'enabledForReportingButNotEnforced' } 'Enforce' { 'enabled' } 'Disable' { 'disabled' } }

if ($Mode -eq 'Enforce') {
    $bg = $config.placeholders.BREAK_GLASS_GROUP_ID
    $members = Get-GraphCollection -Uri "groups/$bg/members?`$select=id,userPrincipalName"
    if ($members.Count -lt 1) {
        throw "Break-glass group $bg has no members. Refusing to enforce."
    }
    Write-Host "Break-glass group has $($members.Count) member(s): $(($members | ForEach-Object { $_.userPrincipalName }) -join ', ')"
}

$folder = Join-Path (Get-PasswordlessRoot) 'entra' 'conditional-access'
$existing = Get-GraphCollection -Uri 'identity/conditionalAccess/policies?$select=id,displayName,state'

foreach ($file in Get-ChildItem -Path $folder -Filter 'CA*.json' -File | Sort-Object Name) {
    $code = $file.Name.Substring(0, 5)
    if ($Only -and ($Only -notcontains $code)) { continue }

    $json = Expand-Placeholders -Json (Get-Content -Raw -Path $file.FullName) -Placeholders $config.placeholders -Source $file.Name
    $policy = $json | ConvertFrom-Json -AsHashtable
    $policy.state = $state
    $body = $policy | ConvertTo-Json -Depth 20

    $match = $existing | Where-Object { $_.displayName -eq $policy.displayName } | Select-Object -First 1
    if ($match) {
        Write-Host ("PATCH {0,-6} {1,-40} -> {2}" -f $code, $match.id, $state)
        Invoke-GraphJson -Method PATCH -Uri "identity/conditionalAccess/policies/$($match.id)" -Body $body | Out-Null
    }
    else {
        Write-Host ("POST  {0,-6} {1,-40} -> {2}" -f $code, '(new)', $state)
        Invoke-GraphJson -Method POST -Uri 'identity/conditionalAccess/policies' -Body $body | Out-Null
    }
}

Write-Host ''
Write-Host 'Policies now in tenant:'
(Get-GraphCollection -Uri 'identity/conditionalAccess/policies?$select=displayName,state') | Where-Object { $_.displayName -like 'CA0*' } | Sort-Object displayName | Format-Table displayName, state -AutoSize

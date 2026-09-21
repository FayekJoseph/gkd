#Requires -Version 7.2
<#
.SYNOPSIS
  Deploys device-trust configuration: compliance policies (assigned to all devices), the Windows Hello for
  Business enrollment policy, and the Windows passwordless-experience settings catalog policy.

.DESCRIPTION
  Uses the beta Graph endpoint because the Defender for Endpoint risk-score and TPM/firewall compliance
  settings are only exposed there. Idempotent by display name. Requires Intune licensing and the
  Defender for Endpoint connector enabled in Intune (Endpoint security > Microsoft Defender for Endpoint).

.EXAMPLE
  ./Deploy-Intune.ps1                 # everything
  ./Deploy-Intune.ps1 -SkipConfiguration
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$SkipCompliance,
    [switch]$SkipConfiguration
)
Import-Module (Join-Path $PSScriptRoot '..' '..' 'entra' 'scripts' 'Common.psm1') -Force
$config = Import-PasswordlessConfig -AllowMissingPlaceholders
$null = Connect-PasswordlessGraph -TenantId $config.tenantId -Scopes @('DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementServiceConfig.ReadWrite.All')

$root = Join-Path (Get-PasswordlessRoot) 'intune'
$allDevices = @{ assignments = @(@{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }) } | ConvertTo-Json -Depth 5

if (-not $SkipCompliance) {
    $existing = Get-GraphCollection -Uri 'deviceManagement/deviceCompliancePolicies?$select=id,displayName' -ApiVersion beta
    foreach ($file in Get-ChildItem -Path (Join-Path $root 'compliance') -Filter '*.json' -File) {
        $json = Get-Content -Raw -Path $file.FullName
        $obj = $json | ConvertFrom-Json -AsHashtable
        $match = $existing | Where-Object { $_.displayName -eq $obj.displayName } | Select-Object -First 1
        if ($match) {
            $update = @{}
            foreach ($k in $obj.Keys) { if ($k -ne 'scheduledActionsForRule') { $update[$k] = $obj[$k] } }
            Write-Host "PATCH compliance '$($obj.displayName)' ($($match.id))"
            Invoke-GraphJson -Method PATCH -Uri "deviceManagement/deviceCompliancePolicies/$($match.id)" -Body ($update | ConvertTo-Json -Depth 10) -ApiVersion beta | Out-Null
            $id = $match.id
        }
        else {
            Write-Host "POST  compliance '$($obj.displayName)'"
            $created = Invoke-GraphJson -Method POST -Uri 'deviceManagement/deviceCompliancePolicies' -Body $json -ApiVersion beta
            $id = $created.id
        }
        if ($id) {
            Invoke-GraphJson -Method POST -Uri "deviceManagement/deviceCompliancePolicies/$id/assign" -Body $allDevices -ApiVersion beta | Out-Null
        }
    }
}

if (-not $SkipConfiguration) {
    # Windows Hello for Business: PATCH the tenant-default enrollment configuration.
    $whfb = Get-Content -Raw -Path (Join-Path $root 'configuration' 'windows-hello-for-business.json')
    $configs = Get-GraphCollection -Uri "deviceManagement/deviceEnrollmentConfigurations?`$filter=deviceEnrollmentConfigurationType eq 'windowsHelloForBusiness'" -ApiVersion beta
    if ($configs.Count -eq 0) { $configs = Get-GraphCollection -Uri 'deviceManagement/deviceEnrollmentConfigurations' -ApiVersion beta | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration' } }
    if ($configs.Count -gt 0) {
        Write-Host "PATCH Windows Hello for Business enrollment configuration ($($configs[0].id))"
        Invoke-GraphJson -Method PATCH -Uri "deviceManagement/deviceEnrollmentConfigurations/$($configs[0].id)" -Body $whfb -ApiVersion beta | Out-Null
    }
    else {
        Write-Warning 'No Windows Hello for Business enrollment configuration found; set it in Intune > Devices > Windows > Windows Hello for Business.'
    }

    # Settings catalog policy for the passwordless experience.
    $pwdless = Get-Content -Raw -Path (Join-Path $root 'configuration' 'windows-passwordless-experience.json')
    $obj = $pwdless | ConvertFrom-Json
    $existing = Get-GraphCollection -Uri "deviceManagement/configurationPolicies?`$filter=name eq '$($obj.name)'&`$select=id,name" -ApiVersion beta
    if ($existing.Count -gt 0) {
        Write-Host "PUT   configuration '$($obj.name)' ($($existing[0].id))"
        Invoke-GraphJson -Method PUT -Uri "deviceManagement/configurationPolicies/$($existing[0].id)" -Body $pwdless -ApiVersion beta | Out-Null
        $id = $existing[0].id
    }
    else {
        Write-Host "POST  configuration '$($obj.name)'"
        $created = Invoke-GraphJson -Method POST -Uri 'deviceManagement/configurationPolicies' -Body $pwdless -ApiVersion beta
        $id = $created.id
    }
    if ($id) {
        Invoke-GraphJson -Method POST -Uri "deviceManagement/configurationPolicies/$id/assign" -Body $allDevices -ApiVersion beta | Out-Null
    }
}
Write-Host 'Done. Verify in Intune: Devices > Compliance and Devices > Configuration.'

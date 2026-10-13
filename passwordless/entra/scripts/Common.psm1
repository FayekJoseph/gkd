#Requires -Version 7.2
<#
.SYNOPSIS
  Shared helpers for the passwordless deployment scripts (Microsoft Graph PowerShell SDK).
#>

function Get-PasswordlessRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
}

function Import-PasswordlessConfig {
    <#
    .SYNOPSIS Loads entra/config.json (git-ignored) and validates the placeholders.
    #>
    [CmdletBinding()]
    param(
        [string]$Path = (Join-Path (Get-PasswordlessRoot) 'entra' 'config.json'),
        [switch]$AllowMissingPlaceholders
    )
    if (-not (Test-Path $Path)) {
        throw "Config not found at $Path. Copy entra/config.example.json to entra/config.json and fill it in."
    }
    $config = Get-Content -Raw -Path $Path | ConvertFrom-Json -AsHashtable
    if (-not $config.ContainsKey('tenantId') -or -not $config['tenantId'] -or $config['tenantId'] -eq '00000000-0000-0000-0000-000000000000') {
        throw 'config.tenantId must be set to your tenant id.'
    }
    if (-not $config.ContainsKey('placeholders')) { $config['placeholders'] = @{} }
    if (-not $AllowMissingPlaceholders) {
        foreach ($k in @('BREAK_GLASS_GROUP_ID')) {
            if (-not $config['placeholders'].ContainsKey($k) -or -not $config['placeholders'][$k]) {
                throw "config.placeholders.$k is empty. Run New-BreakGlassAccounts.ps1 first; it prints the group id."
            }
        }
    }
    return $config
}

function Connect-PasswordlessGraph {
    <#
    .SYNOPSIS Interactive, least-privilege Graph sign-in. Uses your passkey / WHfB via the browser.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$TenantId,
        [Parameter(Mandatory)] [string[]]$Scopes
    )
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Install the SDK first: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $ctx = Get-MgContext
    $needed = @($Scopes | Where-Object { $ctx -eq $null -or $ctx.Scopes -notcontains $_ })
    if ($null -eq $ctx -or $ctx.TenantId -ne $TenantId -or $needed.Count -gt 0) {
        Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome -ErrorAction Stop | Out-Null
    }
    return Get-MgContext
}

function Expand-Placeholders {
    <#
    .SYNOPSIS Replaces {{KEY}} tokens in a JSON string; fails if any token is left unresolved.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Json,
        [Parameter(Mandatory)] [hashtable]$Placeholders,
        [string]$Source = 'json'
    )
    $result = $Json
    foreach ($key in $Placeholders.Keys) {
        $value = [string]$Placeholders[$key]
        if ($value) {
            $result = $result.Replace("{{$key}}", $value)
        }
    }
    $unresolved = [regex]::Matches($result, '\{\{([A-Z0-9_]+)\}\}') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    if ($unresolved) {
        throw "$Source still references unresolved placeholders: $($unresolved -join ', '). Fill them in entra/config.json."
    }
    return $result
}

function Invoke-GraphJson {
    <#
    .SYNOPSIS Thin wrapper over Invoke-MgGraphRequest that always sends/receives JSON and surfaces Graph errors.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')] [string]$Method,
        [Parameter(Mandatory)] [string]$Uri,
        [string]$Body,
        [ValidateSet('v1.0', 'beta')] [string]$ApiVersion = 'v1.0'
    )
    $full = if ($Uri -match '^https://') { $Uri } else { "https://graph.microsoft.com/$ApiVersion/$($Uri.TrimStart('/'))" }
    if ($Method -eq 'GET' -or $PSCmdlet.ShouldProcess($full, $Method)) {
        $params = @{ Method = $Method; Uri = $full; OutputType = 'PSObject'; ErrorAction = 'Stop' }
        if ($Body) {
            $params.Body = $Body
            $params.ContentType = 'application/json'
        }
        try {
            return Invoke-MgGraphRequest @params
        }
        catch {
            $detail = if ($null -ne $_.ErrorDetails) { $_.ErrorDetails.Message } else { '' }
            throw "Graph $Method $full failed: $($_.Exception.Message) $detail"
        }
    }
}

function Get-GraphCollection {
    <#
    .SYNOPSIS GET with @odata.nextLink paging.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Uri,
        [ValidateSet('v1.0', 'beta')] [string]$ApiVersion = 'v1.0'
    )
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-GraphJson -Method GET -Uri $next -ApiVersion $ApiVersion
        $props = $page.PSObject.Properties
        if ($props['value'] -and $page.value) { $items.AddRange([object[]]$page.value) }
        $next = if ($props['@odata.nextLink']) { $page.'@odata.nextLink' } else { $null }
    }
    return $items
}

function New-RandomPassword {
    <#
    .SYNOPSIS 64-character random password from a CSPRNG (used to make passwords unknowable, never to be typed).
    #>
    [CmdletBinding()]
    param([int]$Length = 64)
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+[]{}<>?'
    $bytes = [byte[]]::new($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $chars = foreach ($b in $bytes) { $alphabet[$b % $alphabet.Length] }
    return -join $chars
}

Export-ModuleMember -Function Get-PasswordlessRoot, Import-PasswordlessConfig, Connect-PasswordlessGraph, Expand-Placeholders, Invoke-GraphJson, Get-GraphCollection, New-RandomPassword

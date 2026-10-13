#Requires -Version 7.2
<#
.SYNOPSIS Parses every .ps1/.psm1 under passwordless/ and fails on syntax errors (no tenant access needed).
#>
[CmdletBinding()]
param([string]$Root = (Join-Path $PSScriptRoot '..'))
$failed = $false
foreach ($file in Get-ChildItem -Path $Root -Recurse -Include '*.ps1', '*.psm1' -File) {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
        $failed = $true
        foreach ($e in $errors) { Write-Host "$($file.FullName):$($e.Extent.StartLineNumber): $($e.Message)" -ForegroundColor Red }
    }
    else {
        Write-Host "OK  $($file.FullName)"
    }
}
if ($failed) { exit 1 }

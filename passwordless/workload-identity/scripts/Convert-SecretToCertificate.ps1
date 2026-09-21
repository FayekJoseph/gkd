#Requires -Version 7.2
<#
.SYNOPSIS
  Replaces an app registration's client secret with a certificate credential.

.DESCRIPTION
  1. Creates a certificate: in Azure Key Vault (-KeyVaultName, preferred: private key never leaves the HSM/vault)
     or a local self-signed one via openssl / New-SelfSignedCertificate (-SelfSigned; PFX exported for the workload).
  2. Adds the public key to the app registration's keyCredentials (existing certificates are kept).
  3. Optionally removes every client secret (-RemoveSecrets) once the workload has been switched to the certificate.
  The workload then authenticates with a signed client assertion; see zta-gateway/src/client-assertion.js.

.EXAMPLE
  ./Convert-SecretToCertificate.ps1 -AppId <guid> -KeyVaultName kv-identity -CertificateName svc-billing
  ./Convert-SecretToCertificate.ps1 -AppId <guid> -SelfSigned -OutDir ./out
  ./Convert-SecretToCertificate.ps1 -AppId <guid> -RemoveSecrets    # after cut-over
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'SelfSigned')]
param(
    [Parameter(Mandatory)] [string]$AppId,
    [Parameter(ParameterSetName = 'KeyVault', Mandatory)] [string]$KeyVaultName,
    [Parameter(ParameterSetName = 'KeyVault')] [string]$CertificateName,
    [Parameter(ParameterSetName = 'SelfSigned')] [switch]$SelfSigned,
    [Parameter(ParameterSetName = 'SelfSigned')] [string]$OutDir = './out',
    [ValidateRange(30, 365)] [int]$ValidityDays = 365,
    [switch]$RemoveSecrets
)
Import-Module (Join-Path $PSScriptRoot '..' '..' 'entra' 'scripts' 'Common.psm1') -Force
$config = Import-PasswordlessConfig -AllowMissingPlaceholders
$null = Connect-PasswordlessGraph -TenantId $config.tenantId -Scopes @('Application.ReadWrite.All')

$apps = Get-GraphCollection -Uri "applications?`$filter=appId eq '$AppId'&`$select=id,appId,displayName,keyCredentials,passwordCredentials"
if ($apps.Count -ne 1) { throw "App registration with appId $AppId not found." }
$app = $apps[0]
Write-Host "App: $($app.displayName) ($($app.appId)) secrets=$(@($app.passwordCredentials).Count) certs=$(@($app.keyCredentials).Count)"

$certBase64 = $null
$subject = "CN=$($app.displayName -replace '[^A-Za-z0-9-]', '-')"

if ($PSCmdlet.ParameterSetName -eq 'KeyVault') {
    if (-not (Get-Module -ListAvailable -Name Az.KeyVault)) { throw 'Install-Module Az.KeyVault first (and Connect-AzAccount).' }
    Import-Module Az.KeyVault -ErrorAction Stop
    if (-not $CertificateName) { $CertificateName = ($app.displayName -replace '[^A-Za-z0-9-]', '-') }
    $existingCert = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName -ErrorAction SilentlyContinue
    if (-not $existingCert -and $PSCmdlet.ShouldProcess("$KeyVaultName/$CertificateName", 'Create Key Vault certificate')) {
        $policy = New-AzKeyVaultCertificatePolicy -SubjectName $subject -IssuerName Self -ValidityInMonths ([math]::Ceiling($ValidityDays / 30)) -KeyType RSA -KeySize 2048 -KeyNotExportable -ReuseKeyOnRenewal:$false
        Add-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName -CertificatePolicy $policy | Out-Null
        do { Start-Sleep -Seconds 3; $existingCert = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName } while (-not $existingCert.Certificate)
        Write-Host "Created certificate in Key Vault: $KeyVaultName/$CertificateName (private key non-exportable)"
    }
    $certBase64 = [Convert]::ToBase64String($existingCert.Certificate.RawData)
}
elseif ($SelfSigned) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $safe = ($app.displayName -replace '[^A-Za-z0-9-]', '-')
    $certPath = Join-Path $OutDir "$safe.cer"
    if ($IsWindows) {
        $cert = New-SelfSignedCertificate -Subject $subject -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy Exportable -NotAfter (Get-Date).AddDays($ValidityDays) -CertStoreLocation 'Cert:\CurrentUser\My' -HashAlgorithm SHA256
        Export-Certificate -Cert $cert -FilePath $certPath -Type CERT | Out-Null
        $pfxPassword = Read-Host -AsSecureString -Prompt 'PFX password (workload import)'
        Export-PfxCertificate -Cert $cert -FilePath (Join-Path $OutDir "$safe.pfx") -Password $pfxPassword | Out-Null
        $certBase64 = [Convert]::ToBase64String($cert.RawData)
        Write-Host "Self-signed certificate in Cert:\CurrentUser\My thumbprint $($cert.Thumbprint); PFX exported to $OutDir"
    }
    else {
        $keyPath = Join-Path $OutDir "$safe.key.pem"
        $pemPath = Join-Path $OutDir "$safe.cert.pem"
        & openssl req -x509 -newkey rsa:2048 -sha256 -nodes -keyout $keyPath -out $pemPath -days $ValidityDays -subj "/$($subject)" 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'openssl failed to create the certificate.' }
        chmod 600 $keyPath
        $pem = Get-Content -Raw $pemPath
        $certBase64 = ($pem -replace '-----BEGIN CERTIFICATE-----', '' -replace '-----END CERTIFICATE-----', '' -replace '\s', '')
        Copy-Item $pemPath $certPath
        Write-Host "Self-signed certificate: $pemPath  private key: $keyPath (keep it in a vault, never in git)"
    }
}

if ($certBase64) {
    $keyCredentials = @(@($app.keyCredentials) | ForEach-Object { @{ keyId = $_.keyId; type = $_.type; usage = $_.usage; key = $null; displayName = $_.displayName } })
    # Graph requires existing keys to be re-sent with key = null; only the new one carries the public key.
    $keyCredentials += @{ type = 'AsymmetricX509Cert'; usage = 'Verify'; key = $certBase64; displayName = "passwordless-$(Get-Date -Format yyyyMMdd)" }
    if ($PSCmdlet.ShouldProcess($app.displayName, 'Add certificate credential to app registration')) {
        Invoke-GraphJson -Method PATCH -Uri "applications/$($app.id)" -Body (@{ keyCredentials = $keyCredentials } | ConvertTo-Json -Depth 5) | Out-Null
        Write-Host 'Certificate credential added. Update the workload to use client_assertion (see zta-gateway/src/client-assertion.js), then rerun with -RemoveSecrets.' -ForegroundColor Green
    }
}

if ($RemoveSecrets) {
    foreach ($secret in @($app.passwordCredentials)) {
        if ($PSCmdlet.ShouldProcess("$($app.displayName) secret '$($secret.displayName)' ($($secret.keyId))", 'Remove client secret')) {
            Invoke-GraphJson -Method POST -Uri "applications/$($app.id)/removePassword" -Body (@{ keyId = $secret.keyId } | ConvertTo-Json) | Out-Null
            Write-Host "Removed secret $($secret.keyId)"
        }
    }
}

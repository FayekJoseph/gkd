# Passwordless access architecture

Passwordless, phishing-resistant access to everything: Microsoft 365 / Entra tenant, email (Outlook and Gmail), Azure and on-prem assets, APIs, service accounts and the devices that reach them. Everything here is policy-as-code you can deploy in report-only mode, verify, then enforce.

**Read this first: `docs/99-rollout-runbook.md`.** Do not deploy any Conditional Access policy before the break-glass accounts exist.

## What is in here

| Path | What it does |
| --- | --- |
| `docs/` | Architecture per pillar, threat model, phased rollout runbook with rollback |
| `entra/authentication-methods/` | Authentication methods policy: passkeys (FIDO2), Authenticator phone sign-in, Temporary Access Pass; phase 2 disables SMS, voice, email OTP, TOTP |
| `entra/authentication-contexts/` | Authentication context `c1` used for step-up on privileged actions |
| `entra/conditional-access/` | 12 Conditional Access policies (CA001..CA012), committed report-only, placeholders resolved from `entra/config.json` |
| `entra/scripts/` | Break-glass creation, named location, deploy auth methods, deploy CA (report-only / enforce / disable), readiness report, onboarding TAP, password scrambling |
| `intune/` | Windows and Android compliance baselines with Defender for Endpoint risk score, Windows Hello for Business enrollment policy, passwordless-experience settings catalog policy, deploy script |
| `workload-identity/` | Credential inventory, secret-to-certificate conversion, service-account detection, tenant app management policy (block new secrets), GitHub Actions federated credential |
| `zta-gateway/` | Zero-dependency Node 22 library and reference API: Entra JWT verification, phishing-resistant `amr` policy, `acrs` claims challenges, certificate client assertions, managed identity tokens. 38 tests, `npm test` |
| `tools/` | JSON and PowerShell validation used by CI |

## Quick start

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
cp passwordless/entra/config.example.json passwordless/entra/config.json   # fill tenantId
cd passwordless/entra/scripts
./New-BreakGlassAccounts.ps1 -Domain <tenant>.onmicrosoft.com               # paste group id into config.json
./Deploy-AuthMethods.ps1 -Phase 1
./New-OnboardingTAP.ps1 -UserPrincipalName you@domain                       # register passkeys with it
./Get-PasswordlessReadiness.ps1
./Deploy-ConditionalAccess.ps1                                              # report-only
# ...review sign-in logs for a week...
./Deploy-ConditionalAccess.ps1 -Mode Enforce -Only CA001,CA002,CA005
```

```bash
cd passwordless/zta-gateway && npm test
ZTA_TENANT_ID=<tenant> ZTA_AUDIENCE=api://<app-id-uri> node src/server.js
```

## Licensing map

| Capability | Needs |
| --- | --- |
| CA001..CA005, CA008, CA011, CA012, auth methods, TAP, WHfB | Entra ID P1 (included in Microsoft 365 Business Premium) |
| CA006, CA007 (risk-based) | Entra ID P2 |
| CA009, CA010, default app management policy enforcement | Microsoft Entra Workload ID Premium |
| Intune compliance, MDE risk score | Intune Plan 1 + Defender for Business / MDE P1+ (Business Premium covers both) |

## Design rules

1. **Phishing-resistant by default.** Admin roles, privileged actions and unmanaged platforms require FIDO2 / Windows Hello / multi-factor CBA. All other users require at least passwordless MFA (phone sign-in allowed) until everyone has a passkey, then flip CA003 to phishing-resistant.
2. **Passwords become unknowable, not just unused.** After passkey registration, `Set-UnknownPassword.ps1` scrambles the password so nothing can be phished for it.
3. **No stored secrets for workloads.** Managed identity where the workload runs on Azure, federated credentials for CI, certificate assertions everywhere else. New secrets are blocked tenant-wide.
4. **Device trust is a gate, not a suggestion.** Compliance includes the Defender for Endpoint machine risk score. Non-compliant devices are blocked with zero grace.
5. **Every policy excludes the break-glass group and ships report-only.** Enforcement is an explicit, per-policy, scripted step with a scripted rollback.

# 1. Entra passwordless sign-in and Conditional Access

## Target state
- **Alienware (Windows 11):** Windows Hello for Business, TPM-backed, PIN + biometrics. FIDO2 key sign-in enabled as backup.
- **Galaxy Z Fold 7:** passkey in Microsoft Authenticator (device-bound, AAGUID `de1e552d-db1d-4423-a619-566b625cdc84`) plus phone sign-in during the transition.
- **Honor Pad 9:** passkey in Authenticator if the device has Google Mobile Services; otherwise browser-only access via cross-device passkey (QR to the phone).
- **Two FIDO2 security keys** (YubiKey 5 NFC or similar): one daily carry, one in a safe. Both registered to your account and to each break-glass account.
- SMS, voice, email OTP and TOTP disabled (phase 2). Password never typed again, then scrambled.

## Deploy
1. `New-BreakGlassAccounts.ps1 -Domain <tenant>.onmicrosoft.com` and record the outputs offline.
2. `Deploy-AuthMethods.ps1 -Phase 1` applies:
   - `fido2.json`: passkeys enabled for all users, self-service on, attestation off (needed for synced passkeys; flip to on and restrict AAGUIDs if you want only Authenticator + YubiKey).
   - `microsoftAuthenticator.json`: phone sign-in (`authenticationMode: any`), app and location context shown on every push.
   - `temporaryAccessPass.json`: 12-char TAP, 60 min default, up to 8 h, multi-use allowed.
   - Authentication context `c1` (privileged actions).
3. `New-OnboardingTAP.ps1 -UserPrincipalName <you>` and register in this order at <https://aka.ms/mysecurityinfo>: security key #1, security key #2, Authenticator passkey on the Fold, Windows Hello on the laptop (happens at next Windows sign-in once Intune WHfB policy is applied).
4. `Get-PasswordlessReadiness.ps1` until every active user shows `READY`.
5. `Deploy-ConditionalAccess.ps1` (report-only). Review **Entra > Monitoring > Sign-in logs > Report-only** for 3 to 7 days.
6. Enforce in this order, one step per day: `CA001,CA005` then `CA002` then `CA003` then `CA008` then `CA004` (after Intune enrollment) then `CA011,CA012` then risk policies.
7. `Deploy-AuthMethods.ps1 -Phase 2` and `Set-UnknownPassword.ps1` for every user that is `READY`.
8. When all users have a passkey or WHfB, edit CA003 to strength `...0004` (phishing-resistant) and redeploy.

## Policy set
| Policy | Purpose | Notes |
| --- | --- | --- |
| CA001 | Block legacy authentication (EAS, IMAP, POP, SMTP AUTH, older Office) | Also disable SMTP AUTH: `Set-CASMailbox -SmtpClientAuthenticationDisabled $true` |
| CA002 | 14 admin roles need phishing-resistant MFA, 12 h sign-in frequency, no persistent browser | Microsoft's recommended role list |
| CA003 | All users need passwordless MFA strength | Phone sign-in OK for now |
| CA004 | Compliant device for Windows/Android/iOS/macOS | Excludes Intune enrollment apps so devices can enroll |
| CA005 | Block device code flow | Very common phishing vector in 2025-2026 |
| CA006 | Medium/high sign-in risk needs phishing-resistant MFA every time | P2 |
| CA007 | High user risk blocked until an admin dismisses the risk | P2; there is no password to reset in a passwordless tenant, so the response is investigate + revoke sessions |
| CA008 | Authentication context `c1` needs phishing-resistant MFA every time | Tag PIM roles, admin portals, sensitive SharePoint sites and zta-gateway `/api/privileged` with `c1` |
| CA009 | Service principals blocked outside trusted IPs | Workload ID Premium. Create the named location first: `New-NamedLocation.ps1` |
| CA010 | Risky service principals blocked | Workload ID Premium |
| CA011 | Linux (Kali) and any unmanaged platform: phishing-resistant MFA, 4 h session, no persistence | Kali cannot be Intune-compliant; this is its lane |
| CA012 | Mobile Office apps: compliant device OR app protection policy | Use instead of CA004 for mobile if you keep the phone MAM-only |

## Grant control reference
Built-in authentication strengths: MFA `00000000-0000-0000-0000-000000000002`, Passwordless MFA `...0003`, Phishing-resistant MFA `...0004`.

## Verification
- `Get-MgContext` sign-in itself should now show `fido` or `hwk` in `amr`; use `zta-gateway` `node src/cli.js inspect <token>` on any access token to confirm.
- Sign-in logs > Authentication details column shows "Passkey (device-bound)" / "Windows Hello for Business".
- Try to sign in with the password on a fresh browser: it must be refused by CA003 even if the password were known.

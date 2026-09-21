# 5. Device trust: Intune, Defender for Endpoint, zero-trust access

## Enrollment plan
| Device | Enrollment | Credential | Notes |
| --- | --- | --- | --- |
| Alienware laptop | Entra join + Intune auto-enroll (Windows Autopilot optional). Kali as a VM or separate disk; the Windows side is the trusted endpoint | Windows Hello for Business (TPM) + FIDO2 key | MDE onboarded via Intune |
| Galaxy Z Fold 7 | Android Enterprise, personally-owned work profile | Authenticator passkey, phone sign-in | Work profile keeps business apps separate from personal; Defender for Endpoint app inside the work profile |
| Honor Pad 9 | Work profile if GMS is present; otherwise treat as untrusted and use browser with CA011 controls | Cross-device passkey via the Fold | Play Integrity needs GMS |
| Kali | Not enrollable (Intune Linux supports Ubuntu/RHEL only) | FIDO2 for web, `ed25519-sk` for SSH | Gets CA011: phishing-resistant, 4 h, no persistence |

## What the policies enforce
**Windows (`windows-zero-trust-baseline.json`)**: Windows 11 23H2+, TPM, Secure Boot, code integrity, ELAM, BitLocker, firewall on, Defender AV with real-time protection and current signatures, **MDE machine risk score Low or better**. No grace period.

**Android work profile (`android-work-profile-baseline.json`)**: Android 14+, security patch not older than the configured date, Play Integrity basic + device, not rooted, encrypted, Google Play Services and Verify Apps on, Company Portal integrity, **MDE risk score Low or better**, work-profile PIN 6+ numeric complex, 5 min lock.

**Windows Hello for Business (`windows-hello-for-business.json`)**: enabled tenant-wide, TPM required, PIN 6+, no expiry, biometrics on, FIDO2 security key sign-in on.

**Passwordless experience (`windows-passwordless-experience.json`)**: hides the password credential provider on Entra-joined Windows 11 so sign-in, lock screen and UAC only offer Hello/FIDO2; enables Web sign-in as the recovery path. Requires Windows 11 22H2+ with the 2023-09 update.

## Deploy
1. Intune > Endpoint security > Microsoft Defender for Endpoint: connect Windows and Android to MDE, turn on "compliance policy evaluation".
2. `intune/scripts/Deploy-Intune.ps1` (beta Graph). Assigned to all devices.
3. Enroll the laptop first, verify it shows **Compliant**, then enforce CA004. Then the phone.
4. Endpoint security > Attack surface reduction and Antivirus baselines (Microsoft's security baselines) are the next layer; not in scope of this repo.

## How access decisions combine
```
sign-in -> passkey/WHfB (CA002/CA003) -> device compliant incl. MDE risk (CA004)
        -> risk OK (CA006/CA007) -> session limits (CA002/CA011)
        -> privileged action? -> auth context c1 step-up (CA008 / zta-gateway)
        -> CAE: token revoked within minutes on user disable, password change, risk, location change
```
If MDE raises the machine risk to Medium (for example a Kali tool triggers a detection in the Windows VM host), the laptop becomes non-compliant and CA004 cuts access until the alert is resolved. Put the Kali VM's disk and tooling paths in MDE exclusions deliberately, and only for the lab share.

## Kali-specific notes
- Keep Kali as the tooling box, not the M365 client. If you must sign in from it, expect a passkey prompt every 4 hours and no "stay signed in".
- Chromium/Firefox on Kali support FIDO2 keys; Bluetooth/QR cross-device passkeys need `bluez` and a recent browser.
- Do not onboard Kali to MDE; it will not pass compliance and the noise is not useful.

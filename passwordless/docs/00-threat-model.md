# Threat model

## Assets
- Entra tenant and Microsoft 365 (Exchange, SharePoint, Teams), Azure subscriptions, Intune.
- Personal Google account (Gmail) used for some correspondence and account recovery.
- Business apps: GitHub, Linear, Notion, Canva, accounting and quoting tools; on-prem gear at Xlight Contracting / Blue Rock sites (NAS, cameras, building automation and temperature-control controllers).
- Devices: Alienware laptop (Windows 11 + Kali VM / dual boot), Galaxy Z Fold 7, Honor Pad 9.
- Workloads: scripts and services holding credentials to any of the above.

## Attackers and techniques we design against
| Technique | Mitigation in this repo |
| --- | --- |
| Credential phishing, adversary-in-the-middle (Evilginx-style) | FIDO2 / WHfB origin-bound credentials (CA002, CA003 later, CA008, CA011); passwords scrambled |
| MFA fatigue / push bombing | Push is not accepted for admins or privileged actions; number matching and app/location context on Authenticator |
| SIM swap / SMS interception | SMS and voice disabled in phase 2 |
| Legacy protocol password spray (IMAP, SMTP AUTH, EAS) | CA001 blocks legacy auth; SMTP AUTH disabled per mailbox |
| Device code phishing | CA005 blocks device code flow |
| Token theft from an unmanaged or infected device | CA004 compliant device incl. MDE risk score; CAE-capable clients; short sessions and no persistence on unmanaged platforms (CA011) |
| Leaked client secret in a repo, CI log or laptop | Secrets inventoried and replaced by certificates / managed identity / federation; tenant policy blocks new secrets; CA009/CA010 fence service principals by location and risk |
| Compromised session replaying to sensitive APIs | `acrs` authentication context step-up (CA008 + zta-gateway claims challenge) |
| Admin lockout by policy mistake | Two break-glass accounts, cloud-only, FIDO2 keys in safes, excluded from all policies, alerted on sign-in |

## Out of scope for this iteration
- Physical theft of an unlocked device (mitigated by lock timers and BitLocker only).
- Supply-chain compromise of Microsoft Authenticator or platform authenticators.
- Non-Entra legacy on-prem systems that cannot speak SAML/OIDC; these go behind Entra Private Access or Cloudflare Access with Entra as IdP (see `03-asset-access.md`).

# Rollout runbook

Every step is reversible. Report-only first, enforce one policy at a time, and never before the break-glass accounts exist.

## Phase 0: safety net (day 0)
- [ ] `entra/config.json` created from the example, `tenantId` filled.
- [ ] `New-BreakGlassAccounts.ps1 -Domain <tenant>.onmicrosoft.com`; passwords and group id recorded offline; group id in `config.json`.
- [ ] Two FIDO2 keys registered on each break-glass account; keys in two separate safes.
- [ ] Alert on break-glass sign-in. Log Analytics / Sentinel KQL:
  ```kusto
  SigninLogs
  | where UserPrincipalName startswith "bg-"
  | project TimeGenerated, UserPrincipalName, IPAddress, ResultType, AppDisplayName
  ```
  and on credential additions to service principals:
  ```kusto
  AuditLogs
  | where OperationName in ("Add service principal credentials", "Update application – Certificates and secrets management")
  | project TimeGenerated, InitiatedBy, TargetResources
  ```
- [ ] Inventory: `Get-PasswordlessReadiness.ps1`, `Audit-ServicePrincipalCredentials.ps1`, `Audit-ServiceAccountUsers.ps1`.

## Phase 1: methods and registration (week 1)
- [ ] `Deploy-AuthMethods.ps1 -Phase 1`
- [ ] TAP for each user, passkeys and security keys registered, Authenticator phone sign-in enabled on phones.
- [ ] `Deploy-Intune.ps1`; laptop Entra-joined and compliant; Windows Hello set up.
- [ ] `Deploy-ConditionalAccess.ps1` (report-only). Watch report-only results daily.

## Phase 2: enforce identity policies (week 2)
Order and what to verify after each:
| Day | Enforce | Verify |
| --- | --- | --- |
| 1 | `CA001,CA005` | No legitimate legacy client broke; sign-in logs show no `Block` on real users |
| 2 | `CA002` | Admin sign-ins show `fido`/`hwk`; PIM activations prompt for passkey |
| 3 | `CA003` | All users sign in with passkey or phone sign-in; zero password-only successes |
| 4 | `CA008` | `/api/privileged` and PIM step-up work end to end |
| 5 | `CA011,CA012` | Kali browser session prompts every 4 h; mobile Outlook works inside work profile |
| 6 | `Deploy-AuthMethods.ps1 -Phase 2`, `Set-UnknownPassword.ps1` for READY users | Readiness report shows no weak methods |

## Phase 3: device trust (week 3)
- [ ] Phone enrolled, compliant. `CA004` enforced. Test: mark the laptop non-compliant (temporarily disable BitLocker on a VM) and confirm access is cut and restored.
- [ ] Risk policies `CA006,CA007` if P2 is licensed.

## Phase 4: workloads (weeks 3-4)
- [ ] Every `Secret` row from the inventory migrated (managed identity > federation > certificate). `-RemoveSecrets` executed.
- [ ] `Set-AppManagementPolicy.ps1`.
- [ ] `New-NamedLocation.ps1`, then `CA009,CA010` if Workload ID Premium is licensed.
- [ ] Robot user accounts disabled.

## Phase 5: email and personal accounts
- [ ] Exchange: SMTP AUTH / IMAP / POP / EAS disabled per mailbox (see `02-email-passwordless.md`).
- [ ] Gmail: passkeys, skip-password, Advanced Protection, SMS removed, app passwords revoked.

## Phase 6: close the loop (week 5+)
- [ ] CA003 upgraded to phishing-resistant strength when readiness shows 100 % `PhishingResistant`.
- [ ] Access reviews scheduled for admin roles and service principals (quarterly).
- [ ] Break-glass test sign-in once per quarter (expect and acknowledge the alert).

## Rollback
- Any policy: `Deploy-ConditionalAccess.ps1 -Mode Disable -Only CAxxx` (or `-Mode ReportOnly`).
- All policies: `Deploy-ConditionalAccess.ps1 -Mode Disable`.
- Locked out: sign in with a break-glass account (FIDO2 key or the offline password), disable the offending policy in the portal, then fix and redeploy.
- Auth methods: re-enable a method by editing the JSON `state` and rerunning `Deploy-AuthMethods.ps1`.
- Compliance: unassign in Intune or set `actionType` to `notification` temporarily.

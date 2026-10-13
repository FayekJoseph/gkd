# 4. Service account hardening: no stored passwords

## Order of preference for any non-human identity
1. **Managed identity** (Azure or Arc-enabled server): nothing to store or rotate.
2. **Workload identity federation**: GitHub Actions, GitLab, Kubernetes, other clouds exchange their own OIDC token for an Entra token. `New-FederatedCredential.ps1` + `federated-credentials/github-actions.json`.
3. **Service principal with certificate** in Key Vault or TPM: `Convert-SecretToCertificate.ps1`, code in `zta-gateway/src/client-assertion.js`.
4. **Never**: client secrets, user accounts with "password never expires", shared mailboxes with passwords, passwords in `.env` files.

## Runbook
1. **Inventory**
   - `Audit-ServicePrincipalCredentials.ps1` lists every secret and certificate, expiry and owners. Every `Secret` row is a work item.
   - `Audit-ServiceAccountUsers.ps1` finds human accounts used as robots (name patterns, no MFA, non-interactive sign-ins only, non-expiring password).
   - Search the estate for secrets: `gitleaks detect` on all repos, `grep -r "client_secret\|ClientSecret" /etc /opt ~`.
2. **Replace**
   - Azure-hosted workload -> enable system-assigned managed identity, grant role, delete app secret.
   - CI pipeline -> federated credential; workflow uses `azure/login@v2` with `client-id`, `tenant-id`, `subscription-id` and `permissions: id-token: write`; no secret in GitHub.
   - Everything else -> `Convert-SecretToCertificate.ps1 -AppId <id> -KeyVaultName <kv>`; switch the code to `acquireTokenWithCertificate`; rerun with `-RemoveSecrets`.
   - Robot user accounts -> create an app registration or managed identity with the same permissions, then disable the user. Shared mailboxes: convert to shared mailbox type (no sign-in) and grant delegated access.
3. **Prevent regressions**
   - `Set-AppManagementPolicy.ps1` blocks new secrets tenant-wide and caps lifetimes (secrets 90 d, certificates 365 d).
   - CA009 / CA010 block service principals from unknown IPs and when ID Protection flags them.
   - Alert when `Add service principal credentials` audit events occur (KQL in the runbook).
   - Quarterly access review on service principals holding privileged roles.

## Windows and Linux service accounts (outside Entra)
- **Windows services / scheduled tasks:** group Managed Service Accounts (gMSA) on the domain, or virtual accounts (`NT SERVICE\name`) on standalone hosts; never a domain user with a stored password.
- **Linux automation (Kali, jump hosts):** SSH keys only, with FIDO2-backed keys where the tool supports it: `ssh-keygen -t ed25519-sk -O resident -O verify-required`. Disable password auth: `PasswordAuthentication no`, `KbdInteractiveAuthentication no`. Use certificate SSH (short-lived certs from a CA) for fleet access.
- **Scripts calling Graph from Kali:** run them under a service principal certificate stored in a file with `0600` perms and full-disk encryption, or better, from an Arc-enabled host with a managed identity.

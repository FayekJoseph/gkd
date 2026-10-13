# 3. Asset access: Conditional Access, certificate-based APIs, managed identities

## Classify every asset into one of four lanes
| Lane | Examples | Control |
| --- | --- | --- |
| **A. Entra-federated SaaS** | Microsoft 365, Azure portal, GitHub Enterprise SSO, Linear/Notion/Canva via Entra SAML/OIDC app | Conditional Access applies automatically (CA002/CA003/CA004/CA008) |
| **B. SaaS with native passkeys but no SSO** | GitHub personal, Google, Cloudflare, domain registrar | Register passkey + security key, delete password where the vendor allows, remove SMS |
| **C. Legacy / on-prem web and RDP/SSH** | NAS, camera NVR, building automation HMI, jump host | Publish through Entra Private Access (Global Secure Access) or Entra Application Proxy with pre-authentication; the app itself never sees the internet. CA policies then apply to the tunnel. Cloudflare Access with Entra as IdP is the vendor-neutral alternative |
| **D. Machine-to-machine APIs** | Your own APIs, Graph automation, Azure resources | Certificate client assertions or managed identity; never secrets (see below) |

## Tagging privileged actions with authentication context `c1`
- **PIM:** Role settings > Activation > "On activation, require Microsoft Entra Conditional Access authentication context" = c1.
- **Admin portals:** CA008 already covers them through `c1`; additionally scope a CA policy to the "Microsoft Admin Portals" app if you want every visit gated.
- **SharePoint/OneDrive sites:** `Set-SPOSite -Identity <url> -ConditionalAccessPolicy AuthenticationContext -AuthenticationContextName "Privileged actions"`.
- **Your APIs:** zta-gateway returns the claims challenge until the token carries `acrs: ["c1"]`.

## API pattern (zta-gateway)
```
client --Bearer token--> API
API: verifyEntraToken()  signature (JWKS), iss, aud, exp/nbf, tid
     evaluateAccess()    amr must include fido|hwk (users) / azpacr == 2 (apps)
     /api/privileged     acrs must include c1, else 401 + WWW-Authenticate claims="..."
client: MSAL acquireToken({ claims }) -> Entra runs CA008 -> passkey step-up -> new token with acrs c1
```
API app registration needs optional claims `amr`, `acrs`, `xms_cc` on the access token (Token configuration blade or manifest `optionalClaims.accessToken`). Declare `xms_cc: ["cp1"]` in clients to get Continuous Access Evaluation.

## Certificate-based authentication for workloads
- Certificate in **Azure Key Vault** (non-exportable) when the workload can reach Key Vault with a managed identity; otherwise a PFX in the OS certificate store / TPM, never a file in a repo.
- `Convert-SecretToCertificate.ps1` adds the public key to the app registration.
- Code: `acquireTokenWithCertificate()` builds the PS256 client assertion (`x5t#S256` header, 5-minute lifetime) and posts `client_credentials` with `client_assertion`. Lifetime cap of 365 days is enforced tenant-wide by the app management policy.
- Entra multi-factor **certificate-based authentication for users** is also phishing-resistant (`hwk` in `amr`) if you later issue smart cards; not needed with passkeys.

## Managed identities
- Anything that runs on Azure (VM, Functions, Container Apps, Arc-enabled on-prem server) gets a managed identity; `acquireManagedIdentityToken()` picks the right local endpoint (IMDS, App Service, Arc). No credential exists to leak.
- Arc-enable the on-prem jump host or automation server so on-prem scripts can also use a managed identity (`azcmagent connect`).
- Grant Azure RBAC and Graph app roles to the managed identity's service principal; review quarterly with access reviews.
- Managed identities are not covered by CA009/CA010; fence them with Azure RBAC scope and network rules instead.

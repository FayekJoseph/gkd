# 2. Email without passwords

## Outlook / Exchange Online (Entra accounts)
Nothing extra is needed once pillar 1 is enforced: Outlook desktop, Outlook mobile and OWA use modern auth through the Web Account Manager (Windows) or the Authenticator/Company Portal broker (Android), so Windows Hello or the passkey is the credential. Close the side doors:

1. **Legacy protocols off.** CA001 blocks them at the identity layer. In Exchange Online also run:
   ```powershell
   Connect-ExchangeOnline
   Get-CASMailbox -ResultSize Unlimited | Set-CASMailbox -SmtpClientAuthenticationDisabled $true -PopEnabled $false -ImapEnabled $false -ActiveSyncEnabled $false
   Set-TransportConfig -SmtpClientAuthenticationDisabled $true
   ```
   Devices that need to send mail (scanners, controllers) use Microsoft Graph `sendMail` with a certificate credential, or a dedicated relay connector restricted by IP.
2. **Outlook on Android** needs the Authenticator app installed as broker for passkeys; Intune app protection (CA012) keeps mail data inside the work profile.
3. **Third-party mail clients** must support OAuth 2.0 with Entra (Thunderbird does). Anything that only supports passwords stays blocked.
4. **Mailbox-level check:** `Get-CASMailbox | ft Name,SmtpClientAuthenticationDisabled,ImapEnabled,PopEnabled` should be all `True/False/False`.

## Gmail (personal Google account)
Google supports passkeys and a passwordless "skip password when possible" mode. Do this on the Fold 7 first, then the laptop:

1. **Passkeys** at <https://myaccount.google.com/signinoptions/passkeys>: create one on the Fold (Google Password Manager, synced), one on the Alienware (Windows Hello), and register both YubiKeys as security keys.
2. **Turn on "Skip password when possible"** at <https://myaccount.google.com/signinoptions/passkeys>. Google then asks for the passkey first and only falls back to the password when no passkey is available.
3. **Enroll in Advanced Protection** at <https://myaccount.google.com/advanced-protection>. Requires two passkeys/security keys. Effects: password-only sign-in is refused, unverified third-party apps lose Gmail access, account recovery becomes strict. This is the closest thing Google has to Conditional Access for a personal account.
4. **Remove phone-based 2SV** (SMS and voice) under 2-Step Verification once passkeys work; keep Google Prompt only as a last resort or remove it too.
5. **Revoke app passwords and IMAP clients** at <https://myaccount.google.com/apppasswords> and Gmail settings > Forwarding and POP/IMAP > disable IMAP if you only use the Gmail app and web.
6. **Recovery:** print backup codes, store with the spare YubiKey. Set the recovery email to your Entra mailbox (which is itself passwordless) rather than another password-based account.

## Google Workspace (if any business domain is on Workspace instead of Microsoft 365)
Admin console > Security > Authentication > 2-Step Verification: enforce, "Only security key" (passkeys count), no trusted devices. Security > Access and data control > Less secure apps: disable. Context-Aware Access with device policy is the Workspace equivalent of CA004. Alternatively federate Workspace to Entra (SAML) so the Entra policies apply.

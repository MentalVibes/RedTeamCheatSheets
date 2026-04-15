# Passive Reconnaissance — NoVanity CheatSheets

> **☕ Found this useful?** Support the project:
> **[Buy Me a Coffee](https://www.buymeacoffee.com/NoVanity)** ·
> **ETH:** `0x3844c08bb832b086d00dbbfec128cb31bdcca838`


---

## 0 — PASSIVE RECON METHODOLOGY

```
SYSTEMATIC WORKFLOW (minimal or zero target interaction):
NOTE: Most techniques below are purely passive (query third-party databases,
search engines, public records). A few are marked ⚠ LOW-TOUCH ACTIVE where
they make indirect contact with cloud providers or download public files
from the target. These are clearly labeled throughout the document.

PHASE 1: ORGANIZATIONAL INTELLIGENCE
├── Corporate structure (subsidiaries, acquisitions, partners)
├── Employee enumeration (names, roles, emails, social media)
├── Technology stack identification (job postings, GitHub, DNS)
├── Financial/legal records (SEC filings, contracts, M&A)
└── Physical locations (offices, data centers, remote sites)

PHASE 2: DIGITAL INFRASTRUCTURE MAPPING
├── Domain & subdomain enumeration (CT logs, passive DNS, archives)
├── IP range & ASN identification (BGP, WHOIS, routing)
├── IPv6 address space enumeration (AAAA records, addressing patterns)
├── Certificate analysis (SANs, issuers, internal names)
├── Cloud asset discovery (S3, Blob, GCS via passive search)
├── Email infrastructure (MX, SPF, DKIM, DMARC analysis)
├── CDN / WAF / hosting provider identification
├── Mobile application analysis (APK/IPA decompilation, hardcoded secrets)
└── IoT/OT/SCADA exposure (Shodan ICS queries, protocol identification)

PHASE 3: VULNERABILITY INTELLIGENCE
├── Credential exposure (breach databases, paste sites, dark web)
├── Code repository leaks (GitHub, GitLab, Bitbucket secrets)
├── Document metadata extraction (usernames, software versions)
├── Client-side JavaScript supply chain analysis (CSP, GA IDs, SRI)
├── Previous security incidents (news, breach notifications)
└── Threat intelligence (known APT targeting, industry threats)

PHASE 4: RELATIONSHIP & PATTERN ANALYSIS
├── Social graph mapping (Maltego, SpiderFoot — entity relationships)
├── Employee behavioral profiling (posting patterns, travel, conferences)
├── Satellite/geospatial monitoring (facility changes, executive travel)
└── Supply chain trust relationship mapping (vendors, MSPs, SaaS)

PHASE 5: ATTACK SURFACE COMPILATION
├── Merge all data sources → unified target profile
├── Identify high-value targets (IT admins, execs, developers)
├── Map external attack surface (services, apps, cloud)
├── Prioritize initial access vectors
└── Plan active recon and engagement approach

OPSEC FOR PASSIVE RECON:
  INFRASTRUCTURE COMPARTMENTALIZATION (four-layer model):
  - Layer 1: Personal devices — NEVER used for operations
  - Layer 2: Dedicated research VMs (Whonix/Tails on isolated hosts)
  - Layer 3: Ephemeral cloud "research stations" (spin up per engagement
    via Terraform/Ansible, destroy after use)
  - Layer 4: Air-gapped analysis workstations for sensitive data processing
  - Each engagement: separate API keys, different VPN exits, separate
    browser profiles — all destroyable/recreatable via Infrastructure-as-Code

  NETWORK ANONYMIZATION:
  - Use commercial VPN or Tor for web searches
  - Route API calls through rotating residential proxies (not datacenter IPs)
  - Use DNS-over-HTTPS (DoH) for all research DNS queries
  - Verify kill-switch, test for DNS/WebRTC leaks before every session
  - TLS Client Hello fingerprinting (JA3/JA4 hashes) can identify your
    OS/browser — use managed attribution browsers (e.g., Authentic8 Silo)
    to normalize fingerprints across all operators

  BROWSER FINGERPRINTING:
  - Screen resolution, installed fonts, timezone, WebGL renderer, canvas
    fingerprint, and AudioContext fingerprint survive VPN/Tor/proxy chains
  - Each engagement requires a FRESH browser profile with randomized
    fingerprint parameters, or a managed attribution platform
  - Never use the same browser profile for target research and intel platforms

  API KEY ATTRIBUTION:
  - Every Shodan, Censys, VirusTotal, Hunter.io, SecurityTrails API query
    is logged with API key, timestamp, and query content
  - VirusTotal Intelligence lets premium subscribers see who searched for
    specific IoCs — your research activity may be visible to the target
  - Shodan Monitor can alert targets when queries hit their infrastructure
  - Use DISPOSABLE API keys registered with non-attributable emails and
    prepaid payment — separate from any organizational accounts
  - Self-hosted alternatives (local passive DNS DBs) eliminate this risk

  TOOL FINGERPRINTING:
  - Recon tools have identifiable behavioral signatures (sequential subdomain
    queries across multiple providers within seconds, default User-Agent strings)
  - httpx and nuclei have well-known default User-Agent strings
  - Always set custom User-Agent strings mimicking common browsers
  - Use -silent flags, implement random delays between queries:
    sleep $((RANDOM % 300))  # random jitter between tool runs
  - Prefer web interfaces for manual lookups over CLI tools when possible

  TIMESTAMP CORRELATION:
  - Consistent research times expose timezone and work schedule
  - Burst queries across Shodan, Censys, CT logs within minutes create
    temporal correlation even with different API keys
  - Spread reconnaissance across multiple days with randomized scheduling
  - Avoid researching targets during YOUR normal business hours

  COMMERCIAL THREAT INTEL PLATFORM RISKS:
  - If using Recorded Future, Mandiant, CrowdStrike Falcon Intel — enterprise
    accounts are tied to your organization
  - If target is also a customer of the same platform, "who's interested"
    features may reveal your reconnaissance activity
  - Use non-attributable accounts, access via managed attribution browsers
  - Prefer self-hosted alternatives: MISP, OpenCTI, Hunchly

  SOCK PUPPET ACCOUNTS:
  - Use aged, realistic sock puppet accounts for social media
  - Rotate VPN endpoints per platform to avoid IP-based correlation
  - LinkedIn shows profile viewers — use private/anonymous browsing mode

  HARD RULES:
  - Do NOT log in to any target-owned service
  - Do NOT connect to any target IP address
  - Do NOT send any email to target addresses
  - Search engines, CT logs, WHOIS, and Shodan query publicly indexed data
    (generally considered lawful in most jurisdictions, but verify local laws)
  - Document everything with timestamps for operational reporting
```

---

## 1 — DOMAIN & DNS INTELLIGENCE

```bash
# ═══════════════════════════════════════════════════════════
# PASSIVE SUBDOMAIN ENUMERATION
# ═══════════════════════════════════════════════════════════
# These tools query public data sources — NO packets sent to target:
subfinder -d target.com -all -silent -o subfinder.txt
# Additional subfinder flags for advanced use:
#   -cs (collect sources per subdomain), -oJ (JSON output),
#   -recursive (recursive subdomain enum), -proxy (route through proxy)
#
# ⚠ AMASS v5 BREAKING CHANGE: amass v5+ rewrote the workflow entirely.
# The old "amass enum -passive -d target.com -o amass.txt" syntax still
# executes but results are stored in an OAM graph database, NOT stdout.
# Two-step process required in v5:
amass enum -passive -d target.com
amass subs -names -d target.com > amass.txt
# NOTE: v5 removed the intel, viz, track, and db subcommands from v3.x.
#   If running amass v3.x (legacy), the old one-liner still works.
#
assetfinder --subs-only target.com > assetfinder.txt
# ⚠ assetfinder is UNMAINTAINED — several upstream APIs it queries
#   (Spyse, ThreatCrowd, BufferOverrun) are dead. Declining reliability.
#   Still useful but cross-validate with other tools.
findomain -t target.com -q > findomain.txt
# Additional findomain flags: --enable-dot (DNS-over-TLS), -r (resolved only)
# Combine and deduplicate:
cat subfinder.txt amass.txt assetfinder.txt findomain.txt | sort -u > all_subdomains.txt
# Count: wc -l all_subdomains.txt
#
# Data sources queried by these tools include:
# Certificate Transparency logs, VirusTotal, SecurityTrails, Shodan,
# Censys, DNSDumpster, HackerTarget, AlienVault OTX, Wayback Machine,
# Common Crawl, RapidDNS, and many more
# ⚠ DEAD SOURCES (remove from provider configs to avoid timeout delays):
#   BufferOver (tls.bufferover.run / dns.bufferover.run) — down since late 2024
#   Riddler.io — domain expired February 2025, service defunct

# ═══════════════════════════════════════════════════════════
# CERTIFICATE TRANSPARENCY (CT) LOGS
# ═══════════════════════════════════════════════════════════
# CT logs record every TLS certificate issued — reveals subdomains, internal names
# crt.sh (most popular CT search):
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
# Wildcard search (finds *.target.com, *.dev.target.com, etc.):
curl -s "https://crt.sh/?q=%25.%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
# CertSpotter:
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true" | jq -r '.[].dns_names[]' | sort -u
# Google Certificate Transparency search:
# https://transparencyreport.google.com/https/certificates
#
# CT logs reveal: internal hostnames (mail-internal.target.com, vpn-dc2.target.com),
# development/staging environments, acquisition domains, partner integrations
# OPSEC: CT log queries go to third-party services (crt.sh, CertSpotter), not to target.
#   Target never sees these queries, but the CT log service may log your IP/queries.

# ═══════════════════════════════════════════════════════════
# DNS RECORD ANALYSIS (querying public DNS — not target's DNS server)
# ═══════════════════════════════════════════════════════════
# Use public resolvers (8.8.8.8, 1.1.1.1) — NOT target's nameservers:
# NOTE: dig ANY is unreliable — RFC 8482 allows servers to minimize
# ANY responses (returning a subset of RRsets or a synthetic HINFO record).
# RFC 8482 does NOT explicitly authorize REFUSED/NXDOMAIN, but the practical
# effect is the same: ANY queries return incomplete data.
# Always use explicit record type queries instead:
# CAVEAT: Public resolvers may query target's authoritative DNS to resolve
# your request (if not cached). This is indirect contact — the target sees
# a query from Google/Cloudflare's resolver IP, not yours. Minimal risk but
# not truly zero-interaction with target infrastructure.
dig @8.8.8.8 target.com A +short              # IP address(es)
dig @8.8.8.8 target.com MX +short             # Mail servers → reveals email provider
dig @8.8.8.8 target.com TXT +short            # SPF, DKIM, DMARC, verification records
dig @8.8.8.8 target.com NS +short             # Nameservers → reveals DNS hosting
dig @8.8.8.8 target.com SOA +short            # Start of authority
dig @8.8.8.8 target.com AAAA +short           # IPv6 addresses
dig @8.8.8.8 target.com CNAME +short          # Aliases → reveals CDN/cloud hosting
dig @8.8.8.8 _dmarc.target.com TXT            # DMARC policy → email security posture
dig @8.8.8.8 _mta-sts.target.com TXT          # MTA-STS → email transport security
# SPF record analysis (reveals authorized email senders):
dig @8.8.8.8 target.com TXT | grep -i spf
# SPF includes reveal: include:_spf.google.com (Google Workspace),
#   include:spf.protection.outlook.com (Microsoft 365),
#   include:sendgrid.net, include:amazonses.com, etc.
# DKIM selector discovery:
dig @8.8.8.8 google._domainkey.target.com TXT  # Google DKIM
dig @8.8.8.8 selector1._domainkey.target.com TXT  # Microsoft 365 DKIM
# Reverse DNS on discovered IPs:
dig @8.8.8.8 -x <IP> +short
#
# DNS-OVER-HTTPS (DoH) OPERATIONAL NOTES:
# Use DoH for your OWN research queries to prevent ISP-level observation:
curl -s -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=target.com&type=A"
curl -s -H "accept: application/dns-json" "https://dns.google/resolve?name=target.com&type=MX"
# DoH encrypts traffic between you and the resolver, hiding your research
# from local network observers. However, the resolver-to-authoritative
# boundary remains unencrypted (where passive DNS services like Farsight
# DNSDB collect data).
#
# DEFENSIVE IMPLICATION: If the target organization uses DoH-enabled browsers,
# their employee DNS queries won't be visible to traditional passive DNS
# monitoring at the network perimeter — this creates blind spots that may
# benefit the operator during later phases.

# ═══════════════════════════════════════════════════════════
# PASSIVE DNS DATABASES
# ═══════════════════════════════════════════════════════════
# Historical DNS — see what IPs a domain resolved to over time:
# SecurityTrails: https://securitytrails.com/domain/target.com/dns
# ViewDNS: https://viewdns.info/dnsrecord/?domain=target.com
# VirusTotal: https://www.virustotal.com/gui/domain/target.com/relations
# Microsoft Defender Threat Intelligence (MDTI, formerly RiskIQ/PassiveTotal):
#   https://ti.defender.microsoft.com/
#   Free tier (limited) and premium ($3,900/month). community.riskiq.com
#   now redirects to MDTI. Provides passive DNS, WHOIS, host pairs, components.
# DNSHistory: https://dnshistory.org/ (⚠ intermittent — "returning from long absence")
# Rapid7 Forward DNS (FDNS): https://opendata.rapid7.com/
#   ⚠ FREE ACCESS ENDED February 2022. Now requires Rapid7 customer account,
#   formal academic research application (research@rapid7.com), or commercial license.
#
# Passive DNS reveals: infrastructure changes, hosting migrations,
# previous IPs (may still be reachable), shared hosting relationships,
# CDN usage patterns, and historical misconfigurations

# ═══════════════════════════════════════════════════════════
# DNS-BASED INFRASTRUCTURE IDENTIFICATION
# ═══════════════════════════════════════════════════════════
# Identify hosting/CDN from DNS:
# CNAME → *.cloudfront.net = AWS CloudFront
# CNAME → *.azurewebsites.net = Azure App Service
# CNAME → *.herokuapp.com = Heroku
# CNAME → *.cloudflare.com = Cloudflare (also check NS records)
# NS → *.awsdns = AWS Route53
# NS → *.cloudflare.com = Cloudflare DNS
# NS → *.azure-dns.com = Azure DNS
# MX → *.google.com = Google Workspace
# MX → *.outlook.com = Microsoft 365
# MX → *.pphosted.com = Proofpoint email gateway
# MX → *.mimecast.com = Mimecast email gateway
# These reveal: cloud provider, email platform, email security vendor, CDN
```

---

## 2 — IP, NETWORK & ASN INTELLIGENCE

```bash
# ═══════════════════════════════════════════════════════════
# ASN & IP RANGE DISCOVERY
# ═══════════════════════════════════════════════════════════
# Find target's ASN (Autonomous System Number):
# ⚠ BGPView API (api.bgpview.io) SHUT DOWN permanently November 26, 2025.
#   Use bgp.tools (recommended by BGPView), IPinfo, or HE BGP Toolkit instead.
#
# bgp.tools (web interface — no public REST API, use for manual lookups):
# https://bgp.tools/search?q=Target+Corp
# https://bgp.tools/as/12345  (ASN details + prefixes)
#
# IPinfo ASN lookup (API available):
curl -s "https://ipinfo.io/AS12345/json" | jq '.prefixes[].netblock'
# Or by IP → ASN (unauthenticated legacy endpoint only):
curl -s "https://ipinfo.io/<IP>/json" | jq '.org'
# NOTE: .org field (e.g., "AS15169 Google LLC") only appears on the
#   unauthenticated/free legacy endpoint. Paid API uses .asn object instead.
#   New API at api.ipinfo.io uses .as/.asn/.as_name fields — no .org at all.
#
# RIPE RIPEstat (comprehensive, free API — best programmatic replacement):
# Searchcomplete (find ASNs by name — exact JSON path may vary, test empirically):
curl -s "https://stat.ripe.net/data/searchcomplete/data.json?resource=Target+Corp" | jq '.data'
# Find all IP prefixes announced by ASN:
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS12345" | jq '.data.prefixes[].prefix'
# ASN overview:
curl -s "https://stat.ripe.net/data/as-overview/data.json?resource=AS12345" | jq '.data'
#
# RADB/IRR query (still works, unchanged):
whois -h whois.radb.net -- '-i origin AS12345' | grep route
# Hurricane Electric BGP Toolkit: https://bgp.he.net/AS12345
#
# Large orgs may have multiple ASNs — check all:
# Use RIPE RIPEstat or bgp.tools search to find related ASNs
curl -s "https://stat.ripe.net/data/searchcomplete/data.json?resource=Target" | jq '.data'
#
# BGP / ROUTING INTELLIGENCE:
# Monitor target prefix announcements to map upstream providers, peering,
# CDN relationships, and infrastructure migrations:
# RIPE RIS Live (real-time BGP stream via WebSocket from 25+ global collectors):
#   https://ris-live.ripe.net/ — subscribe to target prefix updates
# BGPalerter: https://github.com/nttgin/BGPalerter — detect hijacks/anomalies
# CAIDA BGPStream: programmatic access to historical BGP data
# bgp.tools historical view: shows prefix announcement changes over time

# ═══════════════════════════════════════════════════════════
# WHOIS & REGISTRATION DATA
# ═══════════════════════════════════════════════════════════
whois target.com
whois <IP_address>
# Extract: registrant org, admin/tech contacts, nameservers, registration dates, registrar
# NOTE: Many registrations now use WHOIS privacy (GDPR). Check historical WHOIS:
# DomainTools: https://whois.domaintools.com/target.com (historical records)
# WhoisXMLAPI: https://www.whoisxmlapi.com/
#
# Reverse WHOIS (find other domains by same registrant):
# DomainTools Reverse Whois: https://reversewhois.domaintools.com/
curl "https://api.whoxy.com/?key=API_KEY&reverse=whois&name=John+Smith"
# Also supports: &email=, &company=, &keyword= (one identifier required)
curl "https://api.whoxy.com/?key=API_KEY&reverse=whois&company=Target+Corp"
# Reveals: other domains owned by same entity, shadow IT, forgotten assets

# ═══════════════════════════════════════════════════════════
# SHODAN (Searches pre-indexed data — zero target interaction)
# ═══════════════════════════════════════════════════════════
# Organization search:
shodan search "org:Target Corp"
shodan search 'org:"Target Corp" port:443'
# Certificate-based discovery:
shodan search "ssl.cert.subject.cn:target.com"
shodan search 'ssl:"target.com"'
# Hostname search:
shodan search "hostname:target.com"
# Service-specific:
shodan search 'org:"Target Corp" port:3389'              # RDP
shodan search 'org:"Target Corp" port:22'                 # SSH
shodan search 'org:"Target Corp" port:8443'               # Management interfaces
shodan search 'org:"Target Corp" "Server: Apache"'        # Apache servers
shodan search 'org:"Target Corp" product:"OpenSSH"'       # SSH version
shodan search 'org:"Target Corp" vuln:CVE-2024-3400'      # Specific CVE
# ⚠ NOTE: vuln: filter requires Small Business API subscription or academic
#   account (.edu email = free upgrade). Free/basic Membership cannot use it.
#   tag: filter (e.g., tag:honeypot) requires Corporate plan only.
# Shodan CLI (host details):
shodan host <IP>
# Shodan Facets (aggregate analysis):
shodan stats --facets port 'org:"Target Corp"'
shodan stats --facets product 'org:"Target Corp"'
#
# Shodan alternatives:
# Censys: https://search.censys.io/ (different scan perspective)
# FOFA: https://en.fofa.info/ (Chinese scanner, broader Asia coverage)
# ZoomEye: https://www.zoomeye.org/ (Chinese scanner)
# Netlas: https://netlas.io/ (newer, good API)
# GreyNoise: https://viz.greynoise.io/ (identifies scanners vs legitimate traffic)

# ═══════════════════════════════════════════════════════════
# INTERNET ARCHIVE & HISTORICAL DATA
# ═══════════════════════════════════════════════════════════
# Wayback Machine (historical snapshots of target's web presence):
waybackurls target.com | sort -u > wayback_urls.txt
# Filter for high-value files:
cat wayback_urls.txt | grep -iE "\.(php|asp|aspx|jsp|env|json|xml|conf|bak|sql|zip|tar|gz|log|txt|csv)$"
# Filter for interesting paths:
cat wayback_urls.txt | grep -iE "(admin|api|config|upload|debug|test|staging|dev|internal|backup|secret|token|password|private|dashboard|portal)"
# gau (Get All URLs — combines Wayback, Common Crawl, OTX, URLScan):
gau target.com --threads 5 | sort -u > gau_urls.txt
# Wayback Machine direct access:
# https://web.archive.org/web/*/target.com/*
# Look for: old login pages, removed content, exposed configs, API docs
```

---

## 3 — CERTIFICATE & TLS INTELLIGENCE

```bash
# ═══════════════════════════════════════════════════════════
# CERTIFICATE TRANSPARENCY DEEP DIVE
# ═══════════════════════════════════════════════════════════
# Find ALL certificates ever issued for target domain:
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > ct_subdomains.txt
# Count unique subdomains:
wc -l ct_subdomains.txt
# Find certificates with specific keywords:
curl -s "https://crt.sh/?q=%25internal%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
curl -s "https://crt.sh/?q=%25vpn%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
curl -s "https://crt.sh/?q=%25dev%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
#
# Certificate details reveal:
# - Internal hostnames (dc01.corp.target.com, mail-internal.target.com)
# - Development/staging environments (dev.target.com, staging-api.target.com)
# - Cloud infrastructure (target-prod.eastus.cloudapp.azure.com)
# - Acquired companies (acquired-company.target.com)
# - Partner integrations (partner-api.target.com)
# - Geographic distribution (eu.target.com, ap.target.com)

# ═══════════════════════════════════════════════════════════
# FAVICON HASH DISCOVERY (Shodan)
# ═══════════════════════════════════════════════════════════
# ⚠ NOTE: Fetching favicon.ico contacts the target directly.
# This is LOW-TOUCH active recon, not purely passive.
# Alternative: check if Shodan already has the favicon hash for the target IP.
#
# Calculate favicon hash → find all servers running same application:
# IMPORTANT: Shodan hashes the BASE64-ENCODED favicon (with newlines every
# 76 chars), NOT the raw file. Hashing raw bytes produces wrong results.
python3 -c "
import requests, mmh3, codecs
r = requests.get('https://target.com/favicon.ico')
favicon = codecs.encode(r.content, 'base64')
hash = mmh3.hash(favicon)
print(f'Favicon hash: {hash}')
print(f'Shodan query: http.favicon.hash:{hash}')
"
# ZoomEye also supports the same mmh3 algorithm via iconhash: filter
# Search Shodan with hash → finds all instances of same app (including shadow IT):
shodan search "http.favicon.hash:<HASH>"
# Useful for: finding forgotten instances, dev/staging servers, same vendor across clients

# ═══════════════════════════════════════════════════════════
# PASSIVE TLS CONFIGURATION ANALYSIS
# ═══════════════════════════════════════════════════════════
# Shodan and Censys index full TLS handshake data — far beyond what CT logs
# or JARM hashes provide. This reveals security posture and software versions
# without sending a single packet to the target.
#
# Protocol version analysis (reveals legacy/vulnerable TLS support):
shodan search 'org:"Target Corp" ssl.version:sslv2'         # SSLv2 (critical vuln)
shodan search 'org:"Target Corp" ssl.version:sslv3'         # SSLv3 (POODLE)
shodan search 'org:"Target Corp" ssl.version:tlsv1'         # TLS 1.0 (PCI non-compliant)
shodan search 'org:"Target Corp" ssl.version:tlsv1.1'       # TLS 1.1 (deprecated)
# Censys equivalents:
# services.tls.version_selected: "TLSv1" AND autonomous_system.name: "Target Corp"
#
# Weak cipher analysis:
shodan search 'org:"Target Corp" ssl.cipher.name:"RC4"'     # RC4 (broken)
shodan search 'org:"Target Corp" ssl.cipher.name:"DES"'     # DES/3DES (weak)
shodan search 'org:"Target Corp" ssl.cipher.name:"NULL"'    # NULL cipher (no encryption)
# DH parameter weakness (Logjam attack):
shodan search 'org:"Target Corp" ssl.dhparams.bits:1024'    # Weak DH params
shodan search 'org:"Target Corp" ssl.dhparams.bits:512'     # Export-grade DH
#
# Expired/self-signed certificate detection:
shodan search 'org:"Target Corp" ssl.cert.expired:true'     # Expired certs
shodan search 'org:"Target Corp" ssl.cert.issuer.cn:"Target"'  # Self-signed
#
# Software fingerprinting from cipher suite ordering:
# Apache, Nginx, IIS each negotiate cipher suites in distinct orders.
# Same JARM hash + same cipher preference = same software/config.
# Cluster related hosts across domains via JARM:
shodan search 'ssl.jarm:<TARGET_JARM_HASH>'
# Censys: services.tls.certificates.leaf.issuer.common_name
#
# This analysis is DISTINCT from CT log analysis (which provides only certificate
# metadata) — TLS config analysis reveals connection parameters, cipher
# negotiation, protocol support, and key exchange strength.
```

---

## 4 — EMAIL & PERSONNEL INTELLIGENCE

```bash
# ═══════════════════════════════════════════════════════════
# EMAIL ADDRESS HARVESTING
# ═══════════════════════════════════════════════════════════
# theHarvester (aggregates multiple sources):
theHarvester -d target.com -b all -l 500
# ⚠ As of v4.10+, Bing and Shodan modules were removed from -b all.
#   40+ sources remain. For Shodan data, use Shodan CLI/API directly.
# Sources queried include: google, linkedin, crtsh, dnsdumpster, certspotter,
#   virustotal, hackertarget, rapiddns, etc.
#
# Hunter.io (email finder — requires API key):
# https://hunter.io/domain-search → enter target.com
# Returns: verified email addresses, email format, confidence scores, sources
curl -s "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY" | jq '.data.emails[].value'
#
# Phonebook.cz (⚠ NO LONGER FREE — requires paid Intelligence X subscription):
# https://phonebook.cz/ → search target.com → type: email
# 268B+ records but restricted to paid users due to abuse
#
# Snov.io: https://snov.io/email-finder → domain search
# ⚠ Clearbit Connect was DISCONTINUED April 30, 2025 (HubSpot acquisition).
#   Replacement is Breeze Intelligence (paid, HubSpot credits system).
#   Alternative free enrichment: Apollo.io free tier, RocketReach limited free lookups

# ═══════════════════════════════════════════════════════════
# EMAIL FORMAT DISCOVERY
# ═══════════════════════════════════════════════════════════
# Common patterns: first.last@, flast@, firstl@, first_last@, first@
# Discover format from known emails (Hunter.io shows most common format)
# Verify: if you find john.smith@target.com → format is likely first.last@
# Once format is known → generate full email list from employee names

# ═══════════════════════════════════════════════════════════
# EMPLOYEE ENUMERATION
# ═══════════════════════════════════════════════════════════
# LinkedIn (primary source — use sock puppet account):
# Manual: Company page → People tab → filter by role/location/keyword
# linkedin2username (automated):
python3 linkedin2username.py -c "Target Corp" -n "target.com"
# NOTE: -c value must be the company NAME from the LinkedIn URL slug
#   (e.g., "target-corp" from linkedin.com/company/target-corp), not a numeric ID.
#   Requires valid LinkedIn session cookie.
# CrossLinked (no API needed — scrapes search engines):
# Modern install: pip3 install crosslinked → invoke as: crosslinked
# Legacy: python3 crosslinked.py -f '{first}.{last}@target.com' "Target Corp"
crosslinked -f '{first}.{last}@target.com' "Target Corp"
#
# Prioritize targets for phishing:
# TIER 1: IT admins, sysadmins, DevOps, security engineers (privileged access)
# TIER 2: Executives, C-suite (high-value data, often bypass security controls)
# TIER 3: New employees (less trained, eager to comply with requests)
# TIER 4: HR, finance, legal (access to sensitive data, used to receiving attachments)
# TIER 5: Developers (code access, CI/CD access, may have cloud credentials)
#
# Build org chart:
# Map reporting structure, identify key decision makers
# Note: who controls IT budget (security tool purchases = defense intel)
# Note: who manages cloud infrastructure (cloud creds = high value)
# Note: who has VPN/remote access admin rights

# ═══════════════════════════════════════════════════════════
# SOCIAL MEDIA OSINT
# ═══════════════════════════════════════════════════════════
# Twitter/X:
# Search: from:@target_corp, "target.com", "works at Target Corp"
# Employee posts may reveal: tech stack, internal projects, frustrations, events
#
# LinkedIn:
# Job postings → tech stack, security tools, compliance requirements
# Employee profiles → technologies they use, certifications, previous employers
# Company page → recent news, employee count, locations
#
# GitHub (organizational):
# https://github.com/target-org → public repos, members, activity
# Employee personal repos may contain: work-related code, credentials, internal docs
#
# Instagram / Facebook:
# Employee posts: badge photos (badge format, access levels), office photos
#   (network equipment visible, whiteboard contents, screen contents)
# Company events: conference badges, presentation slides
#
# Reddit / Forums:
# Employees asking technical questions (reveals tech stack, problems)
# Glassdoor reviews (reveal internal tools, culture, security posture)
#
# OPSEC: Use sock puppet accounts. Never use personal accounts.
#   LinkedIn shows profile viewers — use private/anonymous browsing mode
#   Rotate VPN endpoints to avoid IP-based correlation

# ═══════════════════════════════════════════════════════════
# EMAIL HEADER ANALYSIS FROM PUBLIC ARCHIVES
# ═══════════════════════════════════════════════════════════
# Email headers in public archives leak internal infrastructure topology.
# This is DISTINCT from email address harvesting — targets mail server
# hostnames, internal IPs, MTA software, and routing hops.
#
# Sources for public email headers:
# - Mailing list archives: MARC (marc.info), Mailman/Pipermail, Google Groups
# - Bug trackers: Bugzilla, JIRA public instances, GitHub Issues (email notifications)
# - Public support forums where staff reply via email
# - Bounce messages / NDRs posted publicly
#
# What headers reveal:
# - X-Originating-IP: internal IP of the sending workstation
# - Received: hop chains showing internal mail server hostnames and IPs
#   (e.g., "Received: from mail-internal.corp.target.com [10.1.2.3]")
# - X-Mailer / User-Agent: email client software and version
# - MTA software versions (Postfix, Exchange, etc.) in Received headers
# - X-MS-Exchange-Organization-*: Exchange-specific internal routing data
# - Message-ID hostname: often reveals internal mail server FQDN
#
# Google dork for mailing list archives:
# site:marc.info "target.com"
# site:groups.google.com "target.com"
# site:lists.* "target.com"
#
# CAVEAT: Cloud email services (O365, Gmail) increasingly mask originating
# IPs and internal routing. Most valuable against orgs with on-premises
# mail infrastructure or hybrid deployments.
```

---

## 5 — CODE REPOSITORY & TECHNICAL LEAK INTELLIGENCE

```bash
# ═══════════════════════════════════════════════════════════
# GITHUB / GITLAB / BITBUCKET OSINT
# ═══════════════════════════════════════════════════════════
# Manual GitHub search (powerful dork operators):
# Search: "target.com" password
# Search: "target.com" api_key OR secret OR token
# Search: "target.com" AWS_ACCESS_KEY OR AKIA
# Search: "target.com" jdbc: OR connectionString
# Search: org:target-org filename:.env
# Search: org:target-org filename:id_rsa
# Search: org:target-org filename:credentials
# Search: org:target-org filename:wp-config.php
# Search: org:target-org extension:pem private
# Search: org:target-org extension:sql password
#
# Automated secret scanning:
trufflehog git https://github.com/target-org --results=verified --json
# trufflehog can also scan entire GitHub orgs:
trufflehog github --org=target-org --results=verified --json
# NOTE: Older versions used --only-verified; current versions use --results=verified
#
# gitleaks (v8.19+): `gitleaks detect` is deprecated → use `gitleaks git`
# ⚠ CRITICAL: gitleaks only scans LOCAL repositories, NOT remote URLs.
#   You must clone first, then scan:
git clone https://github.com/target-org/repo.git /tmp/repo
gitleaks git /tmp/repo -v --report-path=gitleaks.json
# For local directories: gitleaks directory /path/to/code
#
# Betterleaks (launched Feb 2026 by gitleaks creator as successor):
# Uses BPE tokenization instead of Shannon entropy for better detection.
# Very new (v1.1.0, March 2026) — no independent benchmarks yet.
# https://github.com/betterleaks/betterleaks
#
# GitDorker — ⚠ UNMAINTAINED since ~2021, broken by GitHub API changes.
# ALTERNATIVES for GitHub dorking:
#   - trufflehog github --org=target-org (built-in org scanning)
#   - GitHub native advanced code search (github.com/search?type=code)
#   - techgaun/github-dorks (maintained alternative)
# Legacy syntax (may not work): python3 GitDorker.py -tf TOKEN -org target-org -d dorks/alldorksv3
#
# Look for:
# - Hardcoded credentials (API keys, database passwords, cloud tokens)
# - Internal infrastructure details (IP addresses, hostnames, network ranges)
# - CI/CD configurations (.github/workflows, Jenkinsfile, .gitlab-ci.yml)
# - Terraform/CloudFormation (infrastructure-as-code with embedded secrets)
# - Docker configurations (Dockerfile, docker-compose.yml with passwords)
# - Private keys (SSH, TLS, code signing)
# - Internal documentation accidentally pushed to public repos
#
# Git commit history (secrets in old commits even if removed from HEAD):
# trufflehog scans entire git history by default — finds removed secrets

# ═══════════════════════════════════════════════════════════
# DOCUMENT METADATA EXTRACTION
# ═══════════════════════════════════════════════════════════
# ⚠ NOTE: Downloading documents from target.com is LOW-TOUCH ACTIVE recon
# (direct HTTP requests to target). Passive alternative: use Google cache
# or Wayback Machine to retrieve cached copies without contacting target.
#
# Download public documents from target website (touches target):
wget -r -l 1 -A pdf,doc,docx,xls,xlsx,ppt,pptx -nd -P ./docs/ https://target.com/
# Passive alternative — download from Google cache/Wayback:
# waybackurls target.com | grep -iE "\.(pdf|docx|xlsx)" | head -20 | xargs -I {} wget "{}"
# Or use Google to find documents:
# site:target.com filetype:pdf
# site:target.com filetype:docx
# site:target.com filetype:xlsx
#
# Extract metadata with exiftool:
exiftool -r -csv ./docs/ > metadata.csv
# Key metadata fields:
exiftool -Author -Creator -Producer -LastModifiedBy -Company -Software ./docs/*.pdf
# Look for: internal usernames (Author field), Active Directory usernames,
#   software versions (reveals patch level), internal file paths,
#   printer names (reveals office locations), GPS coordinates (mobile photos)
#
# FOCA (Windows — automated metadata extraction + network inference):
# Extracts metadata + infers internal network structure from document properties
#
# Metagoofil (⚠ touches target — downloads documents directly):
# ⚠ Use the MAINTAINED FORK: opsdisk/metagoofil (v1.4+)
#   Original laramies version is abandoned with broken syntax.
# CORRECTED SYNTAX (-l and -o flags DO NOT EXIST in maintained fork):
#   -n (number of search results, replaces old -l)
#   -e (delay between downloads in seconds, default 30.0)
#   -w (enable file downloading — boolean toggle, NOT delay)
#   -f (save discovered URLs/links to a text file, NOT downloaded files)
python3 metagoofil.py -d target.com -t pdf,doc,docx,xls,xlsx,ppt,pptx -n 100 -w -e 7
# NOTE: Maintained fork removed metadata analysis — use exiftool separately:
exiftool -r -csv ./docs/ > metadata.csv

# ═══════════════════════════════════════════════════════════
# API SURFACE DISCOVERY (beyond code repos)
# ═══════════════════════════════════════════════════════════
# Three high-value vectors for discovering API endpoints passively:
#
# 1. POSTMAN PUBLIC WORKSPACES (massive leak vector):
# Developers accidentally publish API collections with live credentials.
# CloudSEK found 30,000+ public workspaces leaking keys in 2024;
# RedHunt Labs found 84,260 leaked secrets across 530K+ requests.
# Search: https://www.postman.com/search?q=target.com&type=all
# Automated extraction:
#   postmaniac — OSINT tool to extract creds/tokens from Postman public workspaces
#   https://github.com/boringthegod/postmaniac
#   postmaniac -w "target.com"
#
# 2. SWAGGER / OPENAPI FILES (cached in search engines):
# Google dorks for exposed API documentation:
# site:target.com inurl:"/swagger.json"
# site:target.com inurl:"/openapi.json"
# site:target.com intitle:"Swagger UI"
# site:target.com inurl:"/api-docs"
# Wayback Machine: waybackurls target.com | grep -iE "(swagger|openapi|api-docs)"
# Exposed Swagger files reveal: every endpoint, parameter, data type,
#   authentication scheme, and sometimes example values with real data.
#
# 3. GRAPHQL INTROSPECTION (indexed by Shodan):
# GraphQL endpoints with introspection enabled expose the entire data model:
shodan search 'http.html:"graphql" http.html:"playground" hostname:target.com'
shodan search 'http.html:"graphiql" hostname:target.com'
# Also check: /graphql, /graphql/playground, /graphql/console on cached pages
# Introspection reveals: all types, queries, mutations, fields — the complete
#   data schema. Often left enabled in production by mistake.
```

---

## 6 — CREDENTIAL & BREACH INTELLIGENCE

```bash
# ═══════════════════════════════════════════════════════════
# BREACH DATABASE SEARCHES
# ═══════════════════════════════════════════════════════════
# HaveIBeenPwned (check if target emails appear in breaches):
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/user@target.com" \
  -H "hibp-api-key: YOUR_KEY" -H "User-Agent: operator"
# Check entire domain (requires domain verification or enterprise subscription):
# https://haveibeenpwned.com/DomainSearch
#
# DeHashed (search by domain, email, username, IP, name):
# https://dehashed.com/search?query=target.com
# Returns: email, username, password (hashed/plain), name, database source
#
# LeakCheck: https://leakcheck.io/
# Snusbase: https://snusbase.com/
# IntelX (Intelligence X): https://intelx.io/?s=target.com
# LeakPeek: https://leakpeek.com/
#
# IMPORTANT: Breach data often contains:
# - Plaintext or hashed passwords (crack offline → spray against target)
# - Password patterns (users reuse patterns: Company2023!, Season+Year, etc.)
# - Personal emails (find corporate email from personal breach data)
# - Phone numbers (for vishing/smishing campaigns)
# - Physical addresses (for physical access operations)

# ═══════════════════════════════════════════════════════════
# DARK WEB & UNDERGROUND INTELLIGENCE
# ═══════════════════════════════════════════════════════════
# Tor hidden services / dark web markets:
# - Search for target company data on leak sites (ransomware group blogs)
# - Check initial access brokers (IABs) selling access to target
# - Monitor paste sites for leaked credentials
#   - Pastebin: site:pastebin.com "target.com"
#   - GitHub Gists: search "target.com" password
#   - JustPaste.it, PrivateBin, etc.
#
# Telegram channels (increasingly used for data trading):
# Search: "target.com" OR "Target Corp" in known leak channels
#
# NOTE: Dark web research requires dedicated infrastructure (Tor, separate VM)
# OPSEC: Never use operational infrastructure for dark web access
#   Use a completely separate identity and connection chain

# ═══════════════════════════════════════════════════════════
# GOOGLE DORKING FOR LEAKS
# ═══════════════════════════════════════════════════════════
site:target.com filetype:env                    # .env files with secrets
site:target.com filetype:sql                    # SQL dumps
site:target.com filetype:log                    # Log files
site:target.com filetype:bak                    # Backup files
site:target.com filetype:conf                   # Config files
site:target.com filetype:xml password           # XML configs with passwords
site:target.com intitle:"index of"              # Directory listings
site:target.com inurl:admin                     # Admin panels
site:target.com inurl:login                     # Login pages
site:target.com inurl:api                       # API endpoints
site:target.com "password" OR "secret" OR "api_key"  # Exposed credentials
site:target.com ext:php inurl:config            # PHP config files
site:pastebin.com "target.com"                  # Paste site leaks
site:trello.com "target.com"                    # Trello boards (often public)
site:*.atlassian.net "target.com"               # Jira/Confluence (public instances)
inurl:target.com filetype:pdf confidential      # Confidential documents
#
# Google Hacking Database (GHDB): https://www.exploit-db.com/google-hacking-database
# DorkSearch: https://dorksearch.com/
```

---

## 7 — CLOUD & INFRASTRUCTURE PASSIVE RECON

```bash
# ═══════════════════════════════════════════════════════════
# CLOUD PROVIDER IDENTIFICATION (from DNS/headers/certificates)
# ═══════════════════════════════════════════════════════════
# Check DNS records for cloud indicators (see Section 1 for full list):
dig @8.8.8.8 target.com CNAME +short
dig @8.8.8.8 target.com NS +short
dig @8.8.8.8 target.com MX +short
# Common indicators:
# AWS: CNAME → *.amazonaws.com, *.cloudfront.net, *.elb.amazonaws.com
# Azure: CNAME → *.azurewebsites.net, *.azure.com, *.cloudapp.azure.com
# GCP: CNAME → *.googleapis.com, *.appspot.com, *.run.app
# Cloudflare: NS → *.ns.cloudflare.com

# ═══════════════════════════════════════════════════════════
# CLOUD ASSET DISCOVERY
# ═══════════════════════════════════════════════════════════
# cloud_enum (⚠ LOW-TOUCH ACTIVE — performs DNS lookups and HTTP checks
# against cloud provider endpoints, not target infrastructure directly):
# ⚠ cloud_enum is effectively DEPRECATED by its author — consider migrating
#   to Nuclei templates for cloud enumeration.
# CORRECTED SYNTAX: -l flag does NOT exist. Use -kf/--keyfile for keyword files:
python3 cloud_enum.py -k target -k "target corp"
# With keyword file:
python3 cloud_enum.py -kf keywords.txt
# Output defaults to stdout; redirect as needed: ... > cloud_results.txt
# S3 bucket name guessing via Shodan/Censys (no direct S3 access):
shodan search 'http.title:"target" "ListBucketResult"'
# Azure tenant verification:
curl -s "https://login.microsoftonline.com/target.com/.well-known/openid-configuration" 2>/dev/null | jq '.token_endpoint' 2>/dev/null && echo "Azure AD tenant exists"
# Or check GECOS:
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com&json=1" | jq '.NameSpaceType'
# "Managed" = cloud-only Azure AD, "Federated" = hybrid with on-prem ADFS/federation
#
# ADVANCED AZURE AD / ENTRA ID RECON (unauthenticated):
# AADInternals Invoke-AADIntReconAsOutsider (PowerShell):
#   Reveals: tenant name/ID, all verified domains, federation type,
#   SSO configuration, ADFS server FQDNs — from a single unauthenticated call.
#   Install-Module AADInternals; Invoke-AADIntReconAsOutsider -Domain target.com
#
# GetCredentialType endpoint (user enumeration):
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"Username":"user@target.com"}' | jq '.IfExistsResult'
# 0 = user exists, 1 = user does not exist, 5 = exists but different IdP, 6 = exists
# ⚠ CRITICAL CAVEAT: IfExistsResult is ONLY RELIABLE when the target tenant
#   has Seamless SSO enabled. WITHOUT Seamless SSO, the endpoint returns 0
#   for ALL queries regardless of whether the user exists (false positives).
#   Verify SSO status first via Invoke-AADIntReconAsOutsider.
# Rate limiting: ThrottleStatus field (0=ok, 1=throttled). Tools like AZexec
#   implement 50-150ms adaptive delays to avoid triggering it.
# Microsoft patched the Autodiscover SOAP endpoint (MC1081538, mid-2025),
#   breaking several domain enumeration tools. GetCredentialType still works
#   but Microsoft continues to tighten these endpoints.
#
# MicroBurst Invoke-EnumerateAzureSubDomains (discovers Azure service subdomains):
#   Checks: blob storage, web apps, databases, key vaults, and more
#   https://github.com/NetSPI/MicroBurst
#
# ROADtools, GraphRunner, BloodHound (Azure AD attack paths) — post-auth tools
#   for the next phase, but reference here for planning
#
# M365 / GOOGLE WORKSPACE CONFIGURATION LEAKAGE:
# Google Workspace — public Groups reveal org structure:
#   site:groups.google.com "@target.com"
# Externally shared Google Docs:
#   site:docs.google.com "target.com" OR "Target Corp"
#   site:drive.google.com "target.com"
# Google People API (check if Google profile exists):
#   https://people.googleapis.com/v1/people:searchContacts (requires OAuth)
#   Alternative: Google Contacts name resolution via Hangouts/Chat
#
# CLOUD-SPECIFIC URL PATTERNS (for passive DNS / CT log enumeration):
# AWS:
#   Lambda Function URLs: *.lambda-url.<region>.on.aws (NOT in CT logs — AWS
#     uses wildcard certs. Discover via passive DNS or GitHub code search.)
#   API Gateway: <id>.execute-api.<region>.amazonaws.com
#   S3: <bucket>.s3.amazonaws.com or <bucket>.s3.<region>.amazonaws.com
#   CloudFront: <dist>.cloudfront.net
#   Elastic Beanstalk: <env>.<region>.elasticbeanstalk.com
# GCP:
#   App Engine: <project>.appspot.com
#   Cloud Storage: storage.googleapis.com/<bucket>
#   Firebase: <project>.firebaseio.com (check for public read access!)
#   Cloud Run: <service>-<hash>-<region>.a.run.app
#   Cloud Functions: <region>-<project>.cloudfunctions.net
# Azure (beyond those already listed):
#   Key Vault: <vault>.vault.azure.net
#   Azure SQL: <server>.database.windows.net
#   Cosmos DB: <account>.documents.azure.com
#   Service Bus: <namespace>.servicebus.windows.net

# ═══════════════════════════════════════════════════════════
# WAF / CDN / SECURITY VENDOR DETECTION
# ═══════════════════════════════════════════════════════════
# Identify WAF from Shodan/Censys headers (no direct target interaction):
shodan search 'hostname:target.com' --fields http.headers
# Common WAF indicators in headers:
# Cloudflare: cf-ray header, server: cloudflare
# AWS WAF: x-amzn-requestid, x-amz-cf-id
# Akamai: x-akamai-transformed, akamai-origin-hop
# Imperva/Incapsula: x-cdn (Incapsula), visid_incap
# F5 BIG-IP: server: BigIP, BIGipServer cookie
# Palo Alto: server: PanOS
# Fortinet: server: FortiWeb
#
# CDN detection (reveals origin IP is likely different from CDN edge):
# If Cloudflare detected: try to find origin IP via:
#   - Historical DNS (SecurityTrails — check before Cloudflare adoption)
#   - CT logs (cert may have been issued for origin IP)
#   - Email headers (MX may point to origin, not CDN)
#   - Subdomains not behind CDN (ftp.target.com, mail.target.com)
#   - Censys search for target's TLS cert on non-Cloudflare IPs

# ═══════════════════════════════════════════════════════════
# VPN / REMOTE ACCESS APPLIANCE FINGERPRINTING
# ═══════════════════════════════════════════════════════════
# Identify VPN concentrator type from Shodan/Censys (no target contact):
# Palo Alto GlobalProtect:
shodan search 'org:"Target Corp" http.html:"GlobalProtect Portal"'
# Fortinet FortiGate SSL VPN:
shodan search 'org:"Target Corp" http.html:"top.location=/remote/login"'
# NOTE: Bishop Fox used Last-Modified headers to determine 69% of FortiGate
#   firewalls were unpatched for CVE-2023-27997. Check Last-Modified dates
#   against patch release dates to estimate patch level.
# Cisco AnyConnect / ASA:
shodan search 'org:"Target Corp" http.html:"webvpn"'
shodan search 'org:"Target Corp" "Set-Cookie: webvpn"'
# Pulse Secure / Ivanti Connect Secure:
shodan search 'org:"Target Corp" http.html:"/dana/"'
shodan search 'org:"Target Corp" http.html:"/dana-na/"'
# Citrix NetScaler Gateway:
shodan search 'org:"Target Corp" http.html:"Citrix Gateway"'
shodan search 'org:"Target Corp" http.html:"/vpn/index.html"'
# SonicWall:
shodan search 'org:"Target Corp" http.html:"SonicWall"'
#
# Why VPN fingerprinting matters:
# - Identifies specific CVEs to prioritize (VPN appliances are top initial access vectors)
# - Version/patch estimation from Last-Modified and server headers
# - MFA implementation inference (some VPNs reveal MFA provider in login page)
# - Capacity estimation from concurrent session limits in banners

# ═══════════════════════════════════════════════════════════
# EMAIL SECURITY POSTURE ASSESSMENT
# ═══════════════════════════════════════════════════════════
# Determine email defenses from public DNS records:
dig @8.8.8.8 target.com MX +short
# Proofpoint: *.pphosted.com → enterprise email gateway
# Mimecast: *.mimecast.com → enterprise email gateway
# Barracuda: *.barracudanetworks.com → email security
# Microsoft EOP: *.mail.protection.outlook.com → native M365 protection
# Google: *.google.com, *.googlemail.com → Google Workspace
#
# DMARC policy reveals enforcement level:
dig @8.8.8.8 _dmarc.target.com TXT
# p=none → no enforcement (email spoofing possible)
# p=quarantine → suspicious emails quarantined
# p=reject → strict (spoofing blocked)
# No DMARC record → domain spoofing more likely to succeed, but not guaranteed
#   (M365 and other providers may still flag spoofed mail via other heuristics)
#
# This intelligence directly informs phishing approach:
# p=reject + Proofpoint → difficult to spoof; use lookalike domain or compromise
# p=none + no gateway → domain spoofing may work directly
```

---

## 8 — TECHNOLOGY & SUPPLY CHAIN PROFILING

```bash
# ═══════════════════════════════════════════════════════════
# TECHNOLOGY STACK IDENTIFICATION
# ═══════════════════════════════════════════════════════════
# Combine intelligence from multiple passive sources:
# 1. DNS records: mail provider, CDN, DNS hosting, cloud platform
# 2. Job postings: required technologies, security tools, compliance
# 3. GitHub repos: languages, frameworks, libraries, CI/CD tools
# 4. Conference talks: employees presenting on technologies they use
# 5. LinkedIn profiles: technologies listed in skills/experience
# 6. Shodan/Censys: server headers, service versions, TLS configs
# 7. Wappalyzer/BuiltWith: web technology fingerprinting
#
# BuiltWith (web technology profiling):
# https://builtwith.com/target.com → CMS, analytics, frameworks, CDN, hosting
# Wappalyzer: https://www.wappalyzer.com/lookup/target.com
# Netcraft: https://sitereport.netcraft.com/?url=target.com
#
# ADVANCED PASSIVE WEB FINGERPRINTING (no direct target interaction):
# JARM fingerprinting — TLS implementation clustering:
#   JARM hashes identify unique TLS server configurations. Same JARM hash
#   across different IPs = same software/config = related infrastructure.
#   Use Shodan's ssl.jarm filter to find all hosts matching target's JARM.
#   shodan search "ssl.jarm:<TARGET_JARM_HASH>"
#
# httpx (ProjectDiscovery) — combines multiple fingerprinting in one pass:
#   httpx -l subdomains.txt -tech-detect -favicon -jarm -status-code -title
#   Outputs: technology stack, favicon hash, JARM hash, status per host
#
# HTTP header analysis from Shodan (no target contact):
#   Server headers, X-Powered-By, X-AspNet-Version reveal exact software versions
#   shodan search 'hostname:target.com' --fields http.headers,http.server

# ═══════════════════════════════════════════════════════════
# JOB POSTING ANALYSIS (extremely valuable)
# ═══════════════════════════════════════════════════════════
# LinkedIn Jobs / Indeed / Glassdoor → search "Target Corp"
# Technology clues:
#   "Experience with AWS, Terraform, Kubernetes" → cloud-native, IaC
#   "CrowdStrike admin experience" → EDR vendor identified
#   "Splunk engineer" → SIEM vendor identified
#   "Palo Alto firewall management" → perimeter vendor identified
#   "Active Directory / Entra ID hybrid" → identity infrastructure
#   "HIPAA compliance" → healthcare data present
#   "PCI-DSS" → payment card data present
#   "SOC 2 Type II" → security audit maturity
# Defensive stack identification directly informs:
#   - Which payloads need to evade which EDR
#   - Whether SIEM correlation is likely
#   - What network segmentation to expect
#   - What compliance data is present (exfil priority)

# ═══════════════════════════════════════════════════════════
# SUPPLY CHAIN & THIRD-PARTY MAPPING
# ═══════════════════════════════════════════════════════════
# Identify vendors and partners:
# - SPF includes (dig TXT) → third-party email senders (marketing, CRM)
# - TLS certificate SANs → partner domains, integrations
# - Privacy policy → lists of data processors and third parties
# - Press releases → vendor announcements, partnerships
# - SEC filings → material contracts, technology vendors
# - DNS CNAME chains → SaaS providers (Salesforce, HubSpot, Zendesk)
# - Acquisitions → legacy domains with potentially weaker security
#
# Why this matters: trusted third parties are potential pivot points
#   MSP compromise → direct access to target
#   SaaS compromise → data access without touching target infrastructure
#   Vendor VPN → network-level access through established trust

# ═══════════════════════════════════════════════════════════
# CLIENT-SIDE JAVASCRIPT SUPPLY CHAIN ANALYSIS
# ═══════════════════════════════════════════════════════════
# Auditing a target's client-side JavaScript reveals their entire
# third-party ecosystem without touching the target directly (use cached
# versions from Wayback Machine or Shodan HTTP response bodies):
#
# What JS analysis reveals:
# - Analytics services (Google Analytics, Mixpanel, Amplitude)
# - CDN libraries and versions (jQuery, React — reveals patch level)
# - Error tracking (Sentry DSN → project names, internal structure)
# - Customer support widgets (Intercom, Zendesk, Drift)
# - Search providers (Algolia app IDs)
# - Payment processors (Stripe publishable keys)
# - A/B testing (Optimizely, LaunchDarkly)
#
# Content Security Policy (CSP) headers effectively document the complete
# JavaScript supply chain in a single HTTP response:
shodan search 'hostname:target.com' --fields http.headers | grep -i content-security-policy
# The CSP connect-src, script-src, and frame-src directives list every
# approved third-party domain — a complete map of external dependencies.
#
# Google Analytics ID reverse-lookup:
# Find the GA tracking ID (UA-XXXXXX or G-XXXXXX) from cached JS,
# then use BuiltWith to find ALL other domains sharing the same GA ID.
# This maps subsidiary companies and shadow domains.
#
# Subresource Integrity (SRI) tag check:
# If target does NOT use integrity= attributes on <script> tags,
# supply-chain JavaScript attacks (CDN compromise, dependency confusion)
# are viable vectors.
#
# JavaScript source maps (.js.map files):
# If present, these can reverse-engineer the original source code,
# revealing internal API endpoints, variable names, and business logic.
# Check: https://web.archive.org/web/*/target.com/*.js.map
```

---

## 9 — FINANCIAL, LEGAL & ORGANIZATIONAL INTELLIGENCE

```bash
# ═══════════════════════════════════════════════════════════
# CORPORATE STRUCTURE & FINANCIAL DATA
# ═══════════════════════════════════════════════════════════
# SEC EDGAR (US public companies):
# Modern API (preferred — CGI endpoint is legacy and may be deprecated):
# Full-text search: https://efts.sec.gov/LATEST/search-index?q=target&dateRange=custom&startdt=2024-01-01
# Company filings by CIK: https://data.sec.gov/submissions/CIK##########.json (no auth)
# XBRL API: https://data.sec.gov/api/xbrl/companyfacts/CIK##########.json
# Legacy (still works but outdated):
# https://www.sec.gov/cgi-bin/browse-edgar?company=target&CIK=&type=10-K&dateb=&owner=include&count=10
# 10-K annual reports → revenue, subsidiaries, risk factors, technology spend
# 10-Q quarterly reports → recent changes, acquisitions
# 8-K current reports → material events (breaches, acquisitions, exec changes)
# DEF 14A proxy statements → executive compensation, board members
#
# OpenCorporates: https://opencorporates.com/companies?q=target
# Company House (UK): https://find-and-update.company-information.service.gov.uk/
# D&B (Dun & Bradstreet): corporate hierarchy, subsidiaries
# Crunchbase: https://www.crunchbase.com/ → funding, acquisitions, investors
#
# Why this matters for operations:
# - Subsidiaries may have weaker security but network connectivity to parent
# - Recent acquisitions → systems not yet integrated, different security stack
# - Funding stage → security maturity (seed-stage = minimal security)
# - Revenue → likely security budget (rough: 5-15% of IT budget)

# ═══════════════════════════════════════════════════════════
# LEGAL & REGULATORY INTELLIGENCE
# ═══════════════════════════════════════════════════════════
# Previous breach disclosures:
# Search: "target.com" breach OR "data breach" OR "security incident"
# HHS breach portal (healthcare): https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf
# State AG breach reports (US): varies by state
# GDPR Article 33/34 breach notifications (EU)
#
# Regulatory filings reveal data types held:
# HIPAA → health data (PHI)
# PCI-DSS → payment card data
# SOX → financial reporting data
# FERPA → education records
# ITAR → defense/military technical data
# FedRAMP → federal government data
#
# Court records (PACER for US federal courts):
# Previous lawsuits → may reveal security failures, vendor relationships

# ═══════════════════════════════════════════════════════════
# GOVERNMENT PROCUREMENT & CONTRACT DATABASES
# ═══════════════════════════════════════════════════════════
# For targets that are government contractors or vendors — reveals technology
# purchases, organizational relationships, and facility info unavailable
# through any technical recon method.
#
# SAM.gov (absorbed FPDS.gov Feb 2026 — single source for US federal contracts):
# https://sam.gov/search/ → Entity search by company name
# Reveals: CAGE codes, NAICS codes, DUNS numbers, physical addresses,
#   executive names, small business certifications, exclusion records
# Contract search reveals: specific products purchased ("Palo Alto Networks
#   PA-5260 deployment"), dollar values, subcontractor hierarchies,
#   period of performance, contracting officer names
#
# USASpending.gov (federal spending transparency):
# https://www.usaspending.gov/ → search by recipient name
# API: https://api.usaspending.gov/ (free, no auth)
# Reveals: total contract values, awarding agencies, subawards
#
# GSA Open APIs: https://open.gsa.gov/api/
# SAM Entity Management API for programmatic access
#
# Why this matters operationally:
# - Specific technology products procured = confirmed tech stack
# - Subcontractor relationships = supply chain attack vectors
# - Facility addresses in contracts = physical locations
# - Key personnel names = phishing targets
# - Security clearance requirements = data sensitivity level

# ═══════════════════════════════════════════════════════════
# PATENT & INTELLECTUAL PROPERTY DATABASES
# ═══════════════════════════════════════════════════════════
# For large technology companies and defense contractors:
# USPTO: https://patft.uspto.gov/ or https://patents.google.com/
# EPO (European): https://worldwide.espacenet.com/
# Reveals: inventor names (employees), internal project codenames,
#   technical architecture descriptions, partner company co-filings
# CAVEAT: 12-18 month publication delay — historical, not current intel
```

---

## 10 — THREAT INTELLIGENCE

```bash
# ═══════════════════════════════════════════════════════════
# INDUSTRY-SPECIFIC THREAT LANDSCAPE
# ═══════════════════════════════════════════════════════════
# Identify which APT groups target this industry:
# MITRE ATT&CK Groups: https://attack.mitre.org/groups/
# Mandiant APT tracker: https://www.mandiant.com/resources/apt-groups
# CrowdStrike adversary list: https://www.crowdstrike.com/adversaries/
# Microsoft threat actor naming: https://learn.microsoft.com/en-us/security/intelligence/microsoft-threat-actor-naming
#
# CISA alerts for target's sector:
# https://www.cisa.gov/news-events/cybersecurity-advisories
# Filter by: sector (Healthcare, Energy, Financial, Government, etc.)
#
# If target is in critical infrastructure:
# Check CISA ICS advisories: https://www.cisa.gov/news-events/ics-advisories
# Check ENISA threat landscape reports (EU)
# Check NCSC advisories (UK)

# ═══════════════════════════════════════════════════════════
# PREVIOUS INCIDENT RESEARCH
# ═══════════════════════════════════════════════════════════
# Search for previous security incidents involving target:
# Google: "target.com" "security incident" OR "data breach" OR "ransomware"
# Twitter/X: "target.com" breach OR hack OR compromised
# Ransomware leak sites: check if target appears on any group's blog
#   Active groups (verify current status — groups frequently rebrand/disband):
#   Lockbit (⚠ Operation Cronos Feb 2024 seized 34 servers, ID'd leader
#     Dmitry Khoroshev, OFAC sanctioned. Resurgent as LockBit 5.0 since
#     Sep 2025 but at significantly diminished capacity), CL0P, Akira,
#   Play, Black Basta, RansomHub, etc.
#   ⚠ ALPHV/BlackCat conducted an exit scam in March 2024 and is NO LONGER
#   OPERATIONAL. After FBI/DOJ disrupted their infra (Dec 2023) and they
#   attacked Change Healthcare (largest US healthcare breach, 100M+ affected),
#   they kept the $22M ransom, cut off affiliates, and disappeared.
#   US State Department offered $10M reward for identification of leaders.
#   NOTE: Operators have a history of rebranding (DarkSide → BlackMatter →
#   BlackCat) and may resurface under a new name.
# VirusTotal: search for target domain → check associated malware samples
# AlienVault OTX: https://otx.alienvault.com/ → search target domain/IP
#
# Why this matters:
# - Previous incident → likely added specific defenses (but may have gaps elsewhere)
# - Known compromised by specific APT → their tools/implants may still be present
# - Ransomware victim → may have paid, may have rebuilt, security posture changed
```

---

## 11 — PHYSICAL & WIRELESS PRE-ATTACK INTELLIGENCE

```bash
# ═══════════════════════════════════════════════════════════
# PHYSICAL LOCATION INTELLIGENCE
# ═══════════════════════════════════════════════════════════
# Google Maps / Street View:
# - Office entrances, loading docks, parking areas
# - Badge reader locations, camera positions
# - Nearby businesses (coffee shops for WiFi proximity ops)
# - Building security (guards, turnstiles, mantrap)
# - Dumpster locations (dumpster diving feasibility)
# - Smoking areas (tailgating + social engineering opportunity)
#
# Satellite imagery: Google Earth Pro (free), Maxar, Planet
# - Roof access, HVAC equipment (physical intrusion routes)
# - Telecom equipment (antenna, satellite dishes → comms infrastructure)
# - Construction/renovation (temporary security gaps)
#
# Corporate office addresses:
# SEC filings, company website, Google Maps, LinkedIn
# Data center locations: check hosting provider, peering databases

# ═══════════════════════════════════════════════════════════
# WIRELESS PRE-ATTACK INTELLIGENCE
# ═══════════════════════════════════════════════════════════
# WiGLE (Wireless Geographic Logging Engine):
# https://wigle.net/ → search by address or coordinates
# Reveals: SSID names, encryption types, BSSID (MAC), first/last seen
# Corporate SSIDs often follow patterns: Target-Corp, Target-Guest, Target-IoT
# SSID names reveal: network segmentation approach, guest network existence,
#   IoT/OT network presence, and wireless vendor (from BSSID OUI)
#
# WiGLE API:
curl -s "https://api.wigle.net/api/v2/network/search?ssid=Target" \
  -H "Authorization: Basic <BASE64_CREDS>"
#
# This intelligence informs wireless attacks (see Wireless cheat sheet):
# - Known SSIDs → evil twin setup
# - Encryption type → attack vector (WPA2-PSK vs WPA2-Enterprise)
# - Guest network → potential pivot point
```

---

## 12 — MOBILE APPLICATION RECON

```bash
# ═══════════════════════════════════════════════════════════
# MOBILE APP REVERSE ENGINEERING (entirely passive)
# ═══════════════════════════════════════════════════════════
# Mobile apps routinely contain hardcoded API keys, backend URLs,
# Firebase configs, OAuth secrets, and GraphQL schemas — all extractable
# without touching target infrastructure. Download APKs from third-party
# mirrors (APKMirror, apkpure), analyze entirely offline.
#
# Android APK analysis:
# JADX — decompiles APK/DEX to readable Java source:
jadx -d output_dir target-app.apk
grep -rn "api\|key\|secret\|token\|password\|firebase\|endpoint" output_dir/
# Look for: BuildConfig files, strings.xml, hardcoded URLs, API keys
#
# apktool — decodes resources and produces Smali bytecode:
apktool d target-app.apk -o apktool_output/
# Check: res/values/strings.xml, assets/, AndroidManifest.xml (permissions,
#   exported activities/services, intent filters, backup allowance)
#
# MobSF (Mobile Security Framework) — automated static analysis:
# Analyzes both Android and iOS apps. Extracts endpoints, keys, permissions.
# https://github.com/MobSF/Mobile-Security-Framework-MobSF
#
# iOS IPA analysis:
# class-dump — extract Objective-C class declarations
# Hopper Disassembler — interactive disassembly and decompilation
# For Swift apps: use swift-demangle on extracted symbols
#
# What mobile app analysis reveals:
# - Backend API endpoints (often different from web — may be less hardened)
# - Firebase/Firestore database URLs (check for public read access)
# - AWS Cognito pool IDs, S3 bucket names
# - Google Maps API keys (often unrestricted — abuse for billing)
# - OAuth client IDs and redirect URIs
# - GraphQL schemas (reveals entire data model)
# - Push notification service configs (FCM, APNs)
# - Certificate pinning implementation (informs MitM approach)
# - Hardcoded test/debug credentials
#
# This technique routinely yields MORE actionable intelligence than
# weeks of traditional domain enumeration.
```

---

## 13 — IoT / OT / SCADA PASSIVE RECON

```bash
# ═══════════════════════════════════════════════════════════
# INDUSTRIAL CONTROL SYSTEMS (ICS) PASSIVE DISCOVERY
# ═══════════════════════════════════════════════════════════
# For critical infrastructure targets — all via Shodan/Censys (no target contact):
#
# Protocol-specific Shodan dorks:
shodan search 'org:"Target Corp" port:502'         # Modbus (PLC communication)
shodan search 'org:"Target Corp" port:47808'       # BACnet (building automation)
shodan search 'org:"Target Corp" port:20000'       # DNP3 (power/water SCADA)
shodan search 'org:"Target Corp" port:102'         # Siemens S7/S7comm
shodan search 'org:"Target Corp" port:44818'       # EtherNet/IP (Rockwell/AB)
shodan search 'org:"Target Corp" port:1911'        # Fox (Niagara Framework/Tridium)
shodan search 'org:"Target Corp" port:4840'        # OPC-UA
shodan search 'org:"Target Corp" port:2404'        # IEC 60870-5-104 (power grid)
#
# Shodan ICS Radar (3D visualization of global ICS devices):
# https://ics-radar.shodan.io/
#
# Cross-reference results with NVD for automated vulnerability assessment:
# Example: if Siemens S7-300 found → check CVE-2019-13945, CVE-2021-40365
#
# Censys ICS-specific queries:
# https://search.censys.io/ → services.service_name: "MODBUS"
# https://search.censys.io/ → services.service_name: "BACNET"
#
# OT-specific intelligence from job postings:
# "Allen-Bradley" / "Rockwell" → ControlLogix/CompactLogix PLCs
# "Siemens TIA Portal" → Siemens S7-1500/1200
# "Wonderware" / "AVEVA" → SCADA/HMI platform
# "OSIsoft PI" / "AVEVA PI" → historian (data exfil gold mine)
# "Honeywell Experion" → DCS platform
```

---

## 14 — IPv6 PASSIVE RECON

```bash
# ═══════════════════════════════════════════════════════════
# IPv6 RECONNAISSANCE (different methodology required)
# ═══════════════════════════════════════════════════════════
# The 2^128 address space makes brute-force scanning impossible.
# IPv6 recon requires targeted enumeration approaches:
#
# 1. AAAA records for known hostnames:
cat all_subdomains.txt | while read sub; do
  dig @8.8.8.8 "$sub" AAAA +short
done > ipv6_addresses.txt
#
# 2. Reverse PTR lookups in ip6.arpa zones:
#    (only works if target has configured reverse DNS)
dig -x <IPv6_ADDRESS> +short
#
# 3. CT logs — check SANs for IPv6 addresses:
#    Some certificates include IPv6 addresses directly in SANs
#
# 4. Analyze addressing patterns (reveals allocation scheme):
#    SLAAC with EUI-64 → MAC address embedded (first 3 octets = OUI = vendor)
#    Predictable low-byte schemes: ::1, ::2, ::3 (sequential server allocation)
#    Privacy extensions (RFC 4941) → randomized interface IDs
#    /64 subnets with sequential allocation reveal network size
#
# 5. Shodan IPv6 scanning:
shodan search 'org:"Target Corp" has_ipv6:true'
# Censys also indexes IPv6 hosts
#
# Why IPv6 matters:
# Many organizations have IPv6 enabled by default on modern OSes WITHOUT
# realizing it — creating an entirely unmapped attack surface. IPv6 hosts
# may lack firewall rules that exist for IPv4, and dual-stack configurations
# frequently have policy gaps between v4 and v6 rule sets.
#
# THC-IPv6 Toolkit: passive_discovery6 for network segment discovery
# (⚠ requires local network access — for later active phase)
```

---

## 15 — SOCIAL GRAPH ANALYSIS & LINK ANALYSIS

```bash
# ═══════════════════════════════════════════════════════════
# ENTITY RELATIONSHIP MAPPING
# ═══════════════════════════════════════════════════════════
# Link analysis tools connect data points across sources into
# actionable relationship graphs:
#
# Maltego (industry standard — 100+ data transforms):
# - Maps relationships between domains, IPs, emails, people, companies
# - Transforms: DNS, WHOIS, social media, breach data, CT logs
# - Community Edition (free, limited) and Commercial ($999/yr)
# - Best for: visual attack surface mapping, connection discovery
#
# SpiderFoot (open-source automated OSINT):
# - 200+ modules, self-hosted, web UI
# - Automates the entire passive recon workflow
# - https://github.com/smicallef/spiderfoot
# - Run: spiderfoot -s target.com -t all
#
# Lampyre (affordable Maltego alternative):
# - Focus on Russian/CIS sources + global OSINT
# - Better for investigating specific individuals
#
# Gephi (open-source graph visualization):
# - Import data from other tools, visualize relationship networks
# - Useful for large-scale social graph analysis
#
# ADVANCED SOCIAL MEDIA ANALYSIS:
# Cross-platform username correlation:
#   - Sherlock: sherlock username → checks 400+ sites
#   - WhatsMyName: https://whatsmyname.app/
#   - Maigret: comprehensive username enumeration
#
# Follower network mapping:
#   Map who follows/interacts with target employees across platforms.
#   Identify influence clusters, trusted contacts, and potential
#   pretexting relationships for social engineering.
#
# Temporal posting pattern analysis:
#   - Analyze post timestamps → determine work hours, timezone, travel
#   - Activity gaps may indicate vacations (reduced security attention)
#   - Conference attendance (employees distracted, using hotel WiFi)
```

---

## 16 — SATELLITE, RF & OPEN-SOURCE SIGINT

```bash
# ═══════════════════════════════════════════════════════════
# OPEN-SOURCE IMAGERY & GEOSPATIAL INTELLIGENCE
# ═══════════════════════════════════════════════════════════
# Beyond Google Earth/Street View — advanced sources:
#
# Copernicus/Sentinel-2 (free, 10m resolution, 5-day revisit):
# https://browser.dataspace.copernicus.eu/
# - Monitor facility construction, expansion, changes over time
# - Detect new buildings, parking lot activity patterns
#
# Planet Labs (daily 3-5m coverage, requires account):
# https://www.planet.com/
# - Higher resolution, daily cadence for change detection
#
# ADS-B Exchange (aircraft tracking):
# https://globe.adsbexchange.com/
# - Track corporate aircraft (tail numbers from FAA registry)
# - Map executive travel patterns, identify facility locations
# - Detect unusual flight patterns (emergency, secret meetings)
#
# MarineTraffic (vessel tracking):
# https://www.marinetraffic.com/
# - Track shipping for supply chain intelligence
#
# KiwiSDR Network (500+ public radio receivers worldwide):
# http://kiwisdr.com/public/
# - Remote radio monitoring without equipment
# - Monitor target's radio frequency environment remotely
# - Identify wireless communications patterns near facility
#
# These sources support:
# - Physical facility monitoring and change detection
# - Executive travel pattern analysis
# - Supply chain and logistics tracking
# - Pre-operational site survey without physical presence
```

---

## 17 — TARGET PROFILE COMPILATION

```
DELIVERABLE: PASSIVE RECON REPORT

SECTION 1: ORGANIZATIONAL OVERVIEW
  □ Company name, industry, revenue, employee count
  □ Subsidiaries, acquisitions, partners
  □ Key personnel (IT admins, executives, developers)
  □ Physical locations (HQ, branches, data centers)
  □ Regulatory environment (HIPAA, PCI, SOX, etc.)
  □ Government contracts and procurement data (if applicable)
  □ Patent filings and named inventors (large tech/defense targets)

SECTION 2: DIGITAL INFRASTRUCTURE
  □ All discovered domains and subdomains (with IP resolution)
  □ IP ranges and ASN(s) — including IPv6 addressing scheme
  □ Cloud provider(s) and identified cloud assets (per-provider URL patterns)
  □ Email platform and email security vendor
  □ CDN / WAF vendor
  □ DNS hosting provider
  □ Web technology stack (CMS, frameworks, server software)
  □ Identified security tools (EDR, SIEM, email gateway)
  □ VPN / remote access appliance type and version (from Shodan fingerprinting)
  □ TLS security posture (protocol versions, cipher suites, cert validity)
  □ Internal mail server hostnames/IPs (from public email header analysis)
  □ M365 / Entra ID / Google Workspace configuration details

SECTION 3: ATTACK SURFACE
  □ External services identified (from Shodan/Censys)
  □ VPN / remote access solutions (with specific product + version)
  □ Exposed management interfaces
  □ Development / staging environments
  □ API endpoints (from code repos, Postman workspaces, Swagger files, GraphQL)
  □ Legacy / acquired systems
  □ Client-side JavaScript supply chain (CSP analysis, SRI status, GA IDs)

SECTION 4: CREDENTIAL INTELLIGENCE
  □ Email addresses and format
  □ Breach exposure (which databases, when, what data)
  □ Credential patterns observed
  □ Code repository secrets found
  □ Postman public workspace secrets

SECTION 5: MOBILE & APPLICATION INTELLIGENCE
  □ Mobile apps identified (Android/iOS) and versions
  □ API endpoints extracted from mobile app analysis
  □ Hardcoded keys/secrets from app decompilation
  □ Firebase/cloud service configurations
  □ Certificate pinning implementation status

SECTION 6: OT / ICS EXPOSURE (if applicable)
  □ Industrial protocols exposed (Modbus, BACnet, S7, DNP3)
  □ PLC/HMI/SCADA vendors identified
  □ Historian systems (OSIsoft PI, AVEVA)
  □ Known ICS CVEs affecting discovered systems

SECTION 7: IPv6 ATTACK SURFACE
  □ IPv6 addresses discovered (AAAA records)
  □ IPv6 addressing scheme (SLAAC/EUI-64 vs privacy extensions)
  □ Dual-stack policy gap assessment

SECTION 8: THREAT CONTEXT
  □ Previous security incidents
  □ Industry-specific threat actors
  □ Known CVEs affecting identified technology stack
  □ Ransomware group targeting of sector

SECTION 9: RECOMMENDED INITIAL ACCESS APPROACH
  □ Priority vector selection (based on findings)
  □ Target selection (which employees to phish)
  □ Infrastructure requirements (domains, certs, C2)
  □ Active recon priorities (what to scan first)
```

---

## 18 — TOOL QUICK REFERENCE

```
SUBDOMAIN / DNS:
  subfinder                    Passive subdomain enumeration (50+ sources)
  amass v5 (passive mode)      Comprehensive DNS enumeration (two-step: enum + subs)
  assetfinder                  Quick subdomain discovery (⚠ unmaintained, declining reliability)
  findomain                    Fast subdomain enumeration (supports DoT)
  crt.sh / CertSpotter         Certificate Transparency log search
  dnsx                         Fast DNS resolution (pairs with subfinder)
  SecurityTrails               Historical DNS + WHOIS intelligence (API)
  httpx                        HTTP probing + tech detect + favicon hash + JARM

IP / NETWORK:
  Shodan                       Internet-wide service scanning database
  Censys                       Internet-wide scanning (different perspective)
  FOFA / ZoomEye               Chinese internet scanning databases
  bgp.tools                    BGP/ASN/prefix lookup (⚠ BGPView DEAD since Nov 2025)
  RIPE RIPEstat                ASN/prefix/routing intelligence (best free API)
  IPinfo                       IP → ASN lookup (API available)
  whois                        Domain and IP registration data
  Whoxy / DomainTools          Reverse WHOIS lookups
  BGPalerter                   BGP hijack/anomaly detection

WEB ARCHIVE / URLS:
  waybackurls                  Wayback Machine URL extraction
  gau (Get All URLs)           Combines Wayback, CommonCrawl, OTX, URLScan (github.com/lc/gau)
  Wayback Machine              Historical web snapshots

EMAIL / PERSONNEL:
  theHarvester                 Multi-source email and subdomain harvester
  Hunter.io                    Email discovery and verification (API)
  linkedin2username            LinkedIn employee → email generation
  CrossLinked                  LinkedIn scraping via search engines (pip3 install crosslinked)
  Phonebook.cz                 Email/domain search (⚠ NOW PAID — requires IntelX subscription)

CREDENTIAL / BREACH:
  HaveIBeenPwned               Breach database search (API v3, 963+ breaches)
  DeHashed                     Breach data search (email, username, IP)
  IntelX (Intelligence X)      Dark web and breach intelligence
  LeakCheck / Snusbase         Breach database search

CODE REPOSITORY / API SURFACE:
  trufflehog                   Git secret scanning (full history, verified results)
  gitleaks / Betterleaks       Git secret scanning (⚠ local repos only, not remote URLs)
  GitHub Advanced Search        Native code search at github.com/search (⚠ cs.github.com is DEAD)
  postmaniac                   Postman public workspace secret extraction

DOCUMENT / METADATA:
  exiftool                     Metadata extraction (PDF, Office, images)
  metagoofil (opsdisk fork)    Automated document download (⚠ -n not -l, -w enables download, -e sets delay)
  FOCA                         Windows metadata extraction + analysis

CLOUD:
  cloud_enum                   Multi-cloud asset enumeration (⚠ deprecated, migrate to Nuclei)
  AADInternals                 Azure AD / Entra ID unauthenticated reconnaissance
  MicroBurst                   Azure subdomain enumeration (NetSPI)
  S3Scanner                    AWS S3 bucket finder
  Nuclei (cloud templates)     Modern cloud asset enumeration (replacement for cloud_enum)

MOBILE APP:
  JADX                         APK/DEX → Java decompiler
  apktool                      APK resource decoder + Smali disassembler
  MobSF                        Automated mobile app static analysis (Android + iOS)
  class-dump                   iOS Objective-C class extraction

SOCIAL GRAPH / LINK ANALYSIS:
  Maltego                      Entity relationship mapping (100+ transforms)
  SpiderFoot                   Automated OSINT (200+ modules, self-hosted)
  Sherlock / Maigret           Cross-platform username enumeration
  Gephi                        Open-source graph visualization

INFRASTRUCTURE:
  BuiltWith                    Web technology profiling
  Wappalyzer                   Technology fingerprinting
  Netcraft                     Site report and technology detection
  WiGLE                        Wireless network geographic database
  MDTI (ex-RiskIQ)             Microsoft Defender Threat Intelligence (passive DNS, WHOIS)

GOVERNMENT / PROCUREMENT:
  SAM.gov                      US federal contracts, CAGE codes, entity data (absorbed FPDS.gov)
  USASpending.gov              Federal spending transparency (free API)
  USPTO / Google Patents        Patent filings — inventor names, technical architecture

GEOSPATIAL / RF:
  Copernicus/Sentinel-2        Free 10m satellite imagery (5-day revisit)
  ADS-B Exchange               Aircraft tracking
  KiwiSDR Network              Remote radio monitoring (500+ public receivers)

METHODOLOGY REFERENCES:
  MITRE ATT&CK TA0043           https://attack.mitre.org/tactics/TA0043/
  OSINT Framework                https://osintframework.com/
  OSINT Techniques (book)        https://inteltechniques.com/
  IntelTechniques Tools          https://inteltechniques.com/tools/
  Recon-ng (framework)           https://github.com/lanmaster53/recon-ng
  SpiderFoot (automated OSINT)   https://github.com/smicallef/spiderfoot
```

---

*Mapped to: MITRE ATT&CK TA0043 (Reconnaissance — passive collection) · T1589.001 (Gather Victim Identity: Credentials) · T1589.002 (Gather Victim Identity: Email Addresses) · T1589.003 (Gather Victim Identity: Employee Names) · T1590.001 (Gather Victim Network: Domain Properties) · T1590.002 (Gather Victim Network: DNS) · T1590.003 (Gather Victim Network: Network Trust Dependencies) · T1590.004 (Gather Victim Network: Network Topology) · T1590.005 (Gather Victim Network: IP Addresses) · T1590.006 (Gather Victim Network: Network Security Appliances) · T1591.001 (Gather Victim Org: Determine Physical Locations) · T1591.002 (Gather Victim Org: Business Relationships) · T1591.003 (Gather Victim Org: Identify Business Tempo) · T1591.004 (Gather Victim Org: Identify Roles) · T1592.001 (Gather Victim Host: Hardware) · T1592.002 (Gather Victim Host: Software) · T1592.003 (Gather Victim Host: Firmware) · T1592.004 (Gather Victim Host: Client Configurations) · T1593.001 (Search Open Websites: Social Media) · T1593.002 (Search Open Websites: Search Engines) · T1593.003 (Search Open Websites: Code Repositories) · T1594 (Search Victim-Owned Websites) · T1596.001 (Search Open Technical Databases: DNS/Passive DNS) · T1596.002 (Search Open Technical Databases: WHOIS) · T1596.003 (Search Open Technical Databases: Digital Certificates) · T1596.004 (Search Open Technical Databases: CDNs) · T1596.005 (Search Open Technical Databases: Scan Databases) · T1597.001 (Search Closed Sources: Threat Intel Vendors) · T1597.002 (Search Closed Sources: Purchase Technical Data)*
  
  
***Valid as of 24 March 2026***
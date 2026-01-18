# Personal OPSEC Checklist

## Overview

Quick reference for individual operators to audit personal OPSEC hygiene before operations.

**Usage**: Run through this checklist BEFORE any operational activity.

---

## 🌐 Browser & Network

### WebRTC Leak Check
- [ ] WebRTC disabled in browser settings
- [ ] Test at: `https://browserleaks.com/webrtc`
- [ ] Verify no local IP addresses leak

### Browser Fingerprinting
- [ ] Using Tor Browser (recommended) OR hardened Firefox
- [ ] Canvas fingerprinting protection enabled
- [ ] Font fingerprinting minimized (default fonts only)

### DNS Leaks
- [ ] DNS over HTTPS (DoH) enabled OR using VPN DNS
- [ ] Test at: `https://dnsleaktest.com`
- [ ] Verify DNS queries go through VPN/Tor

### Network Configuration
- [ ] VPN/Tor connection verified active
- [ ] Kill switch enabled (blocks traffic if VPN drops)
- [ ] No IPv6 leaks (IPv6 disabled OR tunneled through VPN)

---

## 💻 System Configuration

### Timezone & Locale
- [ ] System timezone set to UTC (not local timezone)
- [ ] Language/locale set to en-US (avoid cultural leaks)
- [ ] Keyboard layout randomized if possible

###File Metadata
- [ ] EXIF stripping enabled for images
- [ ] Document metadata scrubbing before uploads
- [ ] Avoid uploading files created on personal system

### Filesystem Security
- [ ] Full disk encryption enabled
- [ ] Secure delete tools configured (`shred`, `srm`)
- [ ] Temporary files regularly cleared

---

## 👤 Identity Separation

### Operational Identity
- [ ] Separate browser for operations vs. personal use
- [ ] Never log into personal accounts from operational browser
- [ ] No browser sync enabled (bookmarks, history)

### Account Isolation
- [ ] Operational email separate from personal
- [ ] Different passwords for each operation
- [ ] No password reuse across identities

### Social Media
- [ ] No operational activity on personal social accounts
- [ ] No conference photos with visible badges
- [ ] No location tagging on any posts

---

## 🔍 OSINT Self-Check

### GitHub/Code Repositories
- [ ] Check commit times don't correlate with personal accounts
- [ ] Verify no real email addresses in git history
- [ ] Code style distinct from personal projects

### Public Presence
- [ ] Google yourself (operational identity) → should find nothing
- [ ] Search for username across platforms → no linkage
- [ ] WHOIS lookup on domains → privacy protection enabled

### Photo Safety
- [ ] Strip EXIF from all photos before posting
- [ ] No identifiable backgrounds in photos
- [ ] No reflections showing monitors/workspace

---

## ⏰ Temporal OPSEC

### Activity Timing
- [ ] Randomize operational hours (±4 hour jitter minimum)
- [ ] No consistent day-of-week patterns
- [ ] Avoid activity during local nighttime (timezone leak)

### Behavioral Entropy
- [ ] Session durations randomized (2-8 hours, not fixed)
- [ ] Update intervals random (not every Tuesday)
- [ ] No correlating timing with personal GitHub commits

---

## 📱 Mobile Security

### Cellular Data
- [ ] Phone in airplane mode OR left at home
- [ ] No operational activity over cellular network
- [ ] IMSI catcher awareness (high-risk areas)

### Location Services
- [ ] GPS disabled
- [ ] Wi-Fi location scanning disabled
- [ ] No check-ins or location sharing

---

## 🔬 Forensics Mitigation

### Active Session
- [ ] RAM will be wiped on unexpected shutdown
- [ ] Encrypted swap/pagefile
- [ ] Live persistence minimized (RAM-based OS preferred)

### Post-Operation
- [ ] Browser history cleared (or using Tor Browser)
- [ ] Temporary files wiped securely
- [ ] USB devices sanitized if used

---

## 🎯 Pre-Operation Final Checks

**Run this 5-minute checklist immediately before operational activity:**

1. ✅ VPN/Tor connected and verified
2. ✅ WebRTC leak test passed
3. ✅ DNS leak test passed
4. ✅ Timezone set to UTC
5. ✅ Operational browser (not personal)
6. ✅ No personal accounts logged in
7. ✅ Phone in airplane mode / left elsewhere
8. ✅ Workspace has no identifiable items in view

**If ANY check fails → STOP. Do not proceed until fixed.**

---

## 📊 Risk Assessment

### Quick Risk Score

Calculate your current OPSEC risk:

- **Browser fingerprint unique?** +20 points
- **WebRTC leaking IP?** +30 points (CRITICAL)
- **DNS leaking location?** +25 points
- **Same timing as personal accounts?** +15 points
- **Photos with EXIF data posted?** +20 points
- **Personal and operational accounts linked?** +50 points (CRITICAL)

**Score < 20**: Acceptable risk (Tier 2 adversary)  
**Score 20-50**: HIGH RISK (vulnerable to Tier 3)  
**Score > 50**: CRITICAL RISK (immediate attribution likely)

---

## 🛠️ Recommended Tools

### Browser Security
- **Tor Browser** (best overall OPSEC)
- **Firefox** + `privacy.resistFingerprinting=true`
- **uBlock Origin** (WebRTC leak protection)

### Metadata Scrubbing
- **exiftool** (EXIF removal)
- **mat2** (Metadata Anonymization Toolkit)
- **qpdf** (PDF metadata scrubbing)

### Secure Deletion
- **shred** (Linux)
- **srm** (macOS)
- **cipher /w** (Windows)

### Testing Sites
- `https://browserleaks.com` (comprehensive fingerprint test)
- `https://dnsleaktest.com` (DNS leak check)
- `https://ipleak.net` (WebRTC leak check)

---

## 🚨 Red Flags (Immediate Action Required)

If you observe ANY of these, STOP operations immediately:

- ❌ WebRTC leaking real IP
- ❌ DNS queries going to local ISP
- ❌ Personal and operational accounts accessed from same browser
- ❌ Conference badge photo posted publicly
- ❌ Operational timing matches personal GitHub commits (>0.7 correlation)
- ❌ EXIF data in uploaded photos
- ❌ Same password across operations

---

## 📝 Monthly Review

**Every 30 days, audit:**

1. Google yourself → verify no new linkages
2. Check GitHub commit times → no pattern correlation
3. Review social media → no operational leaks
4. Test browser fingerprint → has it changed?
5. Verify VPN provider hasn't logged you
6. Check for new OPSEC techniques/threats

---

*知己知彼，百战不殆*

"Know yourself and know your enemy."

**The checklist knows you. Use it before every operation.**

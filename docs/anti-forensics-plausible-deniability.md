# Anti-Forensics & Plausible Deniability

## Overview

Anti-forensics aims to prevent, delay, or obfuscate forensic investigation. **Plausible deniability** ensures that even if devices are seized, operational data cannot be conclusively attributed.

**Threat Model:** Physical device seizure, forensic memory analysis, coerced decryption (legal or extrajudicial)

---

## I. Hidden Operating Systems

### Concept: HiddenVM Architecture

**Principle:** Run persistent operational VMs within an amnesic (non-persistent) host OS.

**Architecture:**
```
Tails (Amnesic Host)
  └── VirtualBox
      └── Persistent VM (stored in VeraCrypt hidden volume)
          └── Operational Tools + Data
```

**Workflow:**
1. Boot Tails (leaves no trace on disk)
2. Mount VeraCrypt hidden volume from USB
3. Start VirtualBox VM from hidden volume
4. Operate within VM (all state persists in hidden volume)
5. Shutdown: VM state saved to hidden volume, Tails RAM wiped

**Plausible Deniability:**
- Tails boot: "I was just browsing securely"
- VeraCrypt outer volume: "Just encrypted backups"
- Hidden volume: Cannot be proven to exist

**Implementation:**

```bash
# Create VeraCrypt hidden volume
veracrypt --text --create /dev/sdb1

Choose:
- Outer volume: Regular encrypted files (decoy data)
- Hidden volume: Operational VM disk images

# Mount hidden volume in Tails
sudo cryptsetup luksOpen /dev/sdb1 outer_volume
# Enter outer password → shows decoy files

# Mount hidden volume (different password)
veracrypt --text --mount /dev/sdb1 /mnt/hidden
# Enter hidden password → shows VMs

# Run VirtualBox VM from hidden volume
VBoxManage startvm "OperationalVM" --type headless
```

**Security Considerations:**
- Hidden volume must never be written to while outer volume is mounted (data corruption risk)
- VeraCrypt hidden volumes have no header (truly undetectable)
- Adversary cannot prove hidden volume exists (unless passphrase extracted under duress)

---

## II. Amnesic Operating Systems

### Tails (The Amnesic Incognito Live System)

**Principal Characteristics:**
- Boots from USB, runs entirely in RAM
- All network traffic routed through Tor
- No persistent storage unless explicitly configured
- Leaves no trace on host computer

**Operational Use:**
```
Use Case: High-risk operations where forensic traces must not exist

Workflow:
1. Boot Tails from USB
2. Perform operational activity
3. Shutdown → RAM wiped, no disk traces

Forensics gain: Zero persistent traces on host machine
```

**Persistent Volume (Optional):**
```bash
# Create encrypted persistent volume on Tails USB
tails-persistence-setup

Store on persistent volume:
- PGP keys
- SSH keys
- Browser bookmarks
- Configuration files

DO NOT STORE:
- Operational data (use hidden volumes)
- Logs
- Temporary files
```

**Anti-Forensics Value:** Even if computer is seized, Tails leaves no recoverable evidence.

---

## III. RAM-Only Operations

### Concept: No Disk Persistence

**Principle:** All operational data exists only in volatile memory (RAM).

**Implementation:**

**tmpfs (RAM Filesystem):**
```bash
# Create RAM-only workspace
sudo mount -t tmpfs -o size=4G tmpfs /mnt/ramdisk

# Work in ramdisk
cd /mnt/ramdisk
# All files here exist only in RAM

# On shutdown/power loss → all data vanishes
```

**Operational Procedure:**
```
1. Boot system (encrypted disk)
2. Mount RAM-only workspace
3. Decrypt operational data from air-gapped USB into ramdisk
4. Operate (all changes in RAM)
5. Save critical data back to air-gapped USB (encrypted)
6. Reboot → RAM wiped, all traces gone
```

**Emergency Wipe:**
```bash
# Panic button script
#!/bin/bash
sync
echo 3 > /proc/sys/vm/drop_caches
dd if=/dev/urandom of=/dev/mem count=1024
poweroff -f
```

**Limitations:** Cold boot attacks can recover RAM data within ~60 seconds of power loss.

---

## IV. Plausible Deniability Techniques

### Deniable Encryption

**VeraCrypt Hidden Volumes:**
- Outer volume contains plausible decoy data
- Hidden volume contains operational data
- **No way to prove** hidden volume exists (no header, no signature)

**Steganography:**
```bash
# Hide encrypted data in innocent-looking image
steghide embed -cf cover_image.jpg -ef secret_data.txt.gpg

# Adversary sees: Vacation photo
# Reality: Contains encrypted operational data
```

**Deniable File Systems:**
- `shufflecake` (Linux) - Multiple hidden volumes per device
- `TrueCrypt` hidden OS (deprecated but concept valid)

---

### Coercion-Resistant Designs

**Duress Passwords:**
```
Normal Password → Decrypts operational data
Duress Password → Decrypts decoy data + wipes hidden volume

Implementation:
- LUKS with multiple key slots
- Normal key slot → real data
- Duress key slot → triggers secure wipe + shows decoy
```

**Dead Man's Switch:**
```python
#!/usr/bin/env python3
# Check-in required every 24 hours or encrypted volumes auto-wipe

import time
import os

CHECKIN_FILE = "/var/run/deadman_checkin"
TIMEOUT = 86400  # 24 hours

while True:
    if os.path.exists(CHECKIN_FILE):
        last_checkin = os.path.getmtime(CHECKIN_FILE)
        if time.time() - last_checkin > TIMEOUT:
            # No check-in in 24h → wipe
            os.system("cryptsetup luksErase /dev/sda")
            os.system("dd if=/dev/urandom of=/dev/sda bs=1M count=100")
            break
    time.sleep(60)
```

---

## V. Forensic Artifact Elimination

### Memory Forensics Countermeasures

**Cold Boot Attack Mitigation:**
```
Problem: RAM retains data for 60+ seconds after power loss
Attacker can freeze RAM, extract to forensic workstation

Countermeasures:
1. RAM encryption (experimental, performance overhead)
2. Immediate power-off procedures (no graceful shutdown)
3. Emergency RAM fill with garbage data:

# Rapid RAM fill on panic
while true; do
    dd if=/dev/urandom of=/dev/shm/fill bs=1M
done &
```

**TRESOR/Loop-Amnesia:**
- Store encryption keys in CPU registers only (not RAM)
- Keys never written to memory → cold boot attack ineffective
- Requires kernel module support

---

### Swap/Hibernation Disable

**Threat:** Swap files contain cleartext from encrypted volumes

**Mitigation:**
```bash
# Disable swap entirely
swapoff -a
rm /swap.img
# Comment out swap in /etc/fstab

# Encrypted swap (if swap required)
cryptsetup open --type plain /dev/sda2 swap
mkswap /dev/mapper/swap
swapon /dev/mapper/swap

# Hibernation: DISABLE (writes RAM to disk unencrypted)
systemctl mask hibernate.target
```

---

### Browser Private Data Elimination

**Problem:** Even "private browsing" leaves traces

**SQLite Forensics:**
```bash
# Firefox places.sqlite contains history despite "deletion"
strings ~/.mozilla/firefox/*.default/places.sqlite | grep -i "operational"

# Complete removal
rm -rf ~/.mozilla/firefox/*.default/*.sqlite
sqlite3 places.sqlite "VACUUM;"
```

**Prefetch/Thumbnail Cache:**
```bash
# Windows Prefetch (execution history)
# Location: C:\Windows\Prefetch
# Shows: Programs executed, timestamps

# Linux thumbnail cache
rm -rf ~/.cache/thumbnails/*

# macOS Recent Items
rm ~/Library/Preferences/com.apple.recentitems.plist
```

---

## VI. Anti-Analysis Techniques

### Anti-Debugging

**Detection Methods:**
```c
// ptrace self-attachment (prevents debugger)
#include <sys/ptrace.h>

if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
    printf("Debugger detected. Exiting.\n");
    exit(1);
}

// Timing checks (debugger slows execution)
clock_t start = clock();
// Critical code
clock_t end = clock();
if ((end - start) > THRESHOLD) {
    // Debugger suspected
    secure_wipe();
    exit(1);
}
```

**VM Detection:**
```python
import os

# Check for VM artifacts
vm_indicators = [
    "/sys/class/dmi/id/product_name",  # "VirtualBox", "VMware"
    "/proc/scsi/scsi",  # VBOX HARDDISK, VMware Virtual
]

def is_vm():
    for path in vm_indicators:
        if os.path.exists(path):
            with open(path) as f:
                if any(vm in f.read() for vm in ["VirtualBox", "VMware", "QEMU"]):
                    return True
    return False

if is_vm():
    print("VM detected. Not executing.")
    exit(0)
```

**Purpose:** If operational tool is run in forensic sandbox, it detects and doesn't execute.

---

### Code Obfuscation

**Binary Packing:**
```bash
# UPX packing (makes static analysis harder)
upx --best malware.exe

# Custom packer (encrypt + decrypt at runtime)
```

**String Obfuscation:**
```python
# Bad: Strings visible in binary
password = "my_password"

# Good: XOR encrypted strings
enc_password = bytes([ord(c) ^ 0x42 for c in "my_password"])
password = bytes([c ^ 0x42 for c in enc_password]).decode()
```

**Purpose:** Delays forensic analysis, increases investigation cost.

---

## VII. Network Anti-Forensics

### Traffic Obfuscation

**Protocol Masquerading:**
```
Tor over HTTPS:
- Tor traffic looks like HTTPS
- Deep packet inspection harder

obfs4 bridges:
- Tor traffic looks random
- Statistical analysis defeated
```

**Timing Channel Evasion:**
```python
import random
import time

def send_packet(data):
    # Random delay (defeats timing analysis)
    time.sleep(random.uniform(0.1, 2.0))
    send(data)
```

**Decoy Traffic:**
```bash
# Generate cover traffic while operational traffic flows
while true; do
    curl -s https://news.ycombinator.com > /dev/null
    sleep $(( RANDOM % 60 ))
done &
```

---

## VIII. Physical Anti-Forensics

### Secure Hardware Destruction

**SSD/HDD Destruction:**
```
Physical Methods:
1. Degaussing (HDDs only, not SSDs)
2. Shredding (industrial shredder)
3. Incineration (>1000°C for 30+ minutes)
4. Acid bath (sulfuric acid dissolves chips)

Magnetic storage: 7+ overwrite passes (DOD 5220.22-M)
Flash storage: Physical destruction ONLY (firmware hides blocks)
```

**Emergency Thermite:**
```
Composition: Aluminum powder + Iron oxide (rust)
Ignition: Magnesium ribbon
Result: 2500°C molten metal, destroys all electronics

WARNING: Extremely dangerous. For illustrative purposes only.
```

**Operational Procedure:**
- Devices should be easily accessible for rapid destruction
- Pre-stage destruction materials
- Practice destruction procedure under time pressure

---

## IX. Operational Tradecraft

### Anti-Forensics Standard Operating Procedure (SOP)

**Pre-Operation:**
1. Boot amnesic OS (Tails)
2. Mount hidden volume (VeraCrypt)
3. Work in RAM-only environment
4. Enable panic button (hardware or software)

**During Operation:**
1. No disk writes except to hidden volume
2. Clear browser data every 30 minutes
3. Randomized timing (anti-correlation)

**Post-Operation:**
1. Save critical data to air-gapped encrypted USB
2. Unmount all encrypted volumes
3. Reboot (wipes RAM, all traces)
4. If compromise suspected: Destroy hardware

**Emergency Procedure:**
1. Panic button pressed → Immediate RAM wipe
2. Power off within 5 seconds (prevent cold boot)
3. If seizure imminent: Physical destruction

---

## X. Conclusion

**Anti-Forensics Philosophy:**

> "Forensics is a race against time. Deny time, deny forensics."

**Key Principles:**
1. **Minimize Persistence:** RAM-only operations, amnesic OS
2. **Plausible Deniability:** Hidden volumes, deniable encryption
3. **Rapid Destruction:** Panic buttons, dead man's switches
4. **Anti-Analysis:** VM detection, anti-debugging, obfuscation

**Realistic Expectations:**
- Against local police: Anti-forensics highly effective
- Against nation-state with unlimited time/budget: Assume eventual compromise
- Goal: Increase cost of forensic analysis beyond operational value

---

*Кто владеет информацией, тот владеет миром*

"The adversary will analyze. Deny them the data."

**Operational Reminder:** Anti-forensics buys time, not immunity. Combine with OPSEC, compartmentalization, and rapid infrastructure burn.

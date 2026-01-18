# Infrastructure Stealth & Operational Camouflage

## Overview

Infrastructure stealth prevents adversary discovery and fingerprinting of operational servers, redirectors, and command-and-control (C2) infrastructure. The goal is **invisibility until active use**, then **rapid pivoting**.

**Threat Model:** Port scanners (Shodan, Censys), threat intelligence platforms (RiskIQ), passive DNS monitoring, SSL certificate transparency logs

---

## I. Stealth Redirectors

###Concept: Filter Traffic Before Backend Exposure

**Problem:** Backend infrastructure (C2, phishing servers) exposed to scanners → Discovered → Blocked/Attributed

**Solution:** Redirector filters traffic, only forwards legitimate operational traffic to backend.

**Architecture:**
```bash
Operator → [Redirector] → [Backend C2]
                ↓
Scanner → [Redirector] → [Fake Content / 404]
```

**Redirector decides:** Forward to backend OR serve decoy content

---

### Apache mod_rewrite Redirector

**Configuration:**
```apache
# /etc/apache2/sites-available/redirector.conf

<VirtualHost *:443>
    ServerName operational.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/cert.pem
    SSLCertificateKeyFile /etc/ssl/key.pem
    
    # Log everything for analysis
    CustomLog /var/log/apache2/redirector_access.log combined
    
    RewriteEngine On
    
    # Block common scanners by User-Agent
    RewriteCond %{HTTP_USER_AGENT} (nmap|masscan|zgrab|shodan|censys) [NC]
    RewriteRule ^ - [F,L]
    
    # Only allow specific source IPs (operational VPN exit nodes)
    RewriteCond %{REMOTE_ADDR} !^203\.0\.113\.(10|11|12)$
    RewriteRule ^ - [F,L]
    
    # Require specific HTTP header (operational client sends)
    RewriteCond %{HTTP:X-Operational-Key} !^correct_secret_key$
    RewriteRule ^ - [F,L]
    
    # Valid traffic → Proxy to backend C2
    ProxyPass / https://backend-c2.internal:443/
    ProxyPassReverse / https://backend-c2.internal:443/
</VirtualHost>
```

**OPSEC Benefits:**
- Scanners get 403 Forbidden (or fake content)
- Backend C2 never directly exposed
- Redirector is disposable (low value if discovered)

---

### Nginx Redirector (Advanced Filtering)

```nginx
# /etc/nginx/sites-available/redirector

server {
    listen 443 ssl;
    server_name operational.example.com;
    
    ssl_certificate /etc/ssl/cert.pem;
    ssl_certificate_key /etc/ssl/key.pem;
    
    # Logging
    access_log /var/log/nginx/redirector_access.log;
    
    # Default: Return 404 for unmatched traffic
    location / {
        return 404;
    }
    
    # Operational endpoint (requires auth header)
    location /operational_endpoint {
        # Check for secret header
        if ($http_x_operational_key != "correct_secret_key") {
            return 403;
        }
        
        # IP whitelisting (operational VPN range)
        allow 203.0.113.0/24;
        deny all;
        
        # Time-based access (only during operational hours)
        set $hour $time_iso8601;
        if ($hour !~ "T(18|19|20|21|22|23|00|01)") {
            return 403;
        }
        
        # Proxy to backend
        proxy_pass https://backend-c2.internal;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Advanced Features:**
- Time-based access (reject requests outside operational hours)
- JA3 TLS fingerprint filtering (only allow known clients)
- Geographic filtering (reject connections from unexpected countries)

---

### BounceBack-Style Intelligent Filtering

**Concept:** Machine learning classifies traffic as "scanner" vs. "legitimate"

**Features:**
```python
import re
from datetime import datetime

def is_scanner(request):
    """Classify traffic as scanner vs. operational"""
    
    # User-Agent patterns
    scanner_agents = [
        r'nmap', r'masscan', r'zgrab', r'shodan', 
        r'censys', r'bot', r'crawler', r'scan'
    ]
    if any(re.search(pattern, request.user_agent, re.I) for pattern in scanner_agents):
        return True
    
    # Request patterns
    if request.path in ['/admin', '/.env', '/wp-admin', '/.git']:
        return True  # Generic scanner probes
    
    # Timing (scanners hit multiple pages rapidly)
    if request.requests_per_second > 10:
        return True
    
    # TLS fingerprint (JA3)
    if request.ja3_fingerprint not in known_operational_fingerprints:
        return True
    
    return False

# In request handler
if is_scanner(request):
    return fake_website_content()  # Serve decoy
else:
    proxy_to_backend(request)      # Forward to C2
```

---

## II. Domain Categorization Camouflage

### Threat: Domain Categorization Services

**Problem:** 
```
Services like Cisco Umbrella, Symantec Web Security categorize domains
- "Newly Registered" → Suspicious
- "Uncategorized" → Blocked by corporate firewalls
```

**Solution:** Age domains, seed with legitimate content

**Domain Aging Process:**
```
Timeline:
Month 0: Register domain (via privacy-protected WHOIS)
Month 1-6: Host legitimate-looking static website
           - Blog about innocuous topic
           - Link from social media (Twitter, LinkedIn)
           - Request categorization as "Technology" or "News"
Month 6: Reputation established, corporate filters allow
Month 7+: Use for operational purposes

Result: Domain appears established, not suspicious
```

**Content Seeding:**
```html
<!-- Legitimate-looking blog -->
<!DOCTYPE html>
<html>
<head><title>Tech News Blog</title></head>
<body>
    <h1>Latest Technology News</h1>
    <article>
        <h2>AI Trends in 2026</h2>
        <p>Discussion of legitimate AI topics...</p>
    </article>
    <!-- Appears as legitimate tech blog to categorization -->
</body>
</html>
```

**When operational:**
```
Operational path: /api/v2/update (undocumented, requires auth)
Decoy content: / (legitimate blog, publicly visible)

Scanners see: Legitimate tech blog
Operators access: Hidden API endpoint
```

---

## III. SSL/TLS Certificate OPSEC

### Threat: Certificate Transparency Logs

**Problem:** All SSL certificates logged in public CT logs (crt.sh, Censys)

**Attack:**
```
Adversary searches CT logs:
- "*.example.com" → Discovers all subdomains
- cert issued on 2026-01-15 → Temporal correlation with operation
```

**Mitigations:**

**1. Use Wildcard Certificates Sparingly**
```
Bad: *.operational-infrastructure.com
→ Reveals subdomain structure when cert logged

Better: Specific subdomain certificates
→ Each operational subdomain gets separate cert
→ Harder to link via CT logs
```

**2. Temporal Decorrelation**
```
Register domain: 2025-06-01
Issue SSL cert: 2025-06-05
Operation starts: 2026-01-15 (7+ months later)

→ CT log entry doesn't correlate with operation timing
```

**3. Let's Encrypt Rate Limiting Awareness**
```
Let's Encrypt allows 50 certs per domain per week

Operational pattern:
- Register 10 domains
- Issue 1 cert per domain per month
- Avoid batch issuance (signals large-scale operation)
```

---

## IV. Shodan/Censys Evasion

### Threat: Internet-Wide Scanning

**Shodan, Censys, Rapid7 scan entire IPv4 space monthly**

**Discoverable Artifacts:**
- Open ports (22/SSH, 443/HTTPS, 8080/HTTP-Proxy)
- SSL certificate CN/SAN
- HTTP headers (Server: Apache/2.4.41)
- Banner grabs (SSH version strings)

**Evasion Techniques:**

**1. Port Randomization**
```bash
# Don't use standard ports
Bad: Port 443 (HTTPS) → Shodan indexed
Good: Port 47293 (random high port) → Requires targeted scan

# Configure service on non-standard port
nginx listen 47293 ssl;
```

**2. Banner Scrubbing**
```nginx
# Remove "Server" header
server_tokens off;
more_clear_headers Server;

# Result:
# Before: Server: nginx/1.21.0
# After:  (no Server header)
```

**3. Require Auth Before Banner**
```apache
# SSH: Disable pre-auth banner
# /etc/ssh/sshd_config
DebianBanner no
VersionAddendum none

# HTTP: Return 403 for all unauthenticated requests
# (no info leakage until after auth)
```

---

## V. Operational Infrastructure Lifecycle

### Burn-Before-Discovery

**Principle:** Infrastructure lifespan < adversary discovery time

**Lifecycle:**
```
Phase 1: Deployment (Day 0)
- Spin up redirector + backend C2
- Configure stealth rules
- Test operational access

Phase 2: Active Use (Day 1-30)
- Operations conducted via redirector
- Monitor logs for scanner activity
- If scanner detected → Pivot immediately

Phase 3: Burn (Day 30 OR if compromised)
- Destroy infrastructure
- Rotate to new domains/IPs
- No reuse

Timeline: Maximum 30 days per infrastructure set
```

**Indicators of Compromise (IoC):**
```
Automated alerts:
- Shodan scan detected (specific User-Agent)
- More than 3 failed auth attempts
- Requests from unexpected geolocations
- Rapid sequential requests (automated scan)

Action: Immediate pivot to backup infrastructure
```

---

## VI. CDN & Reverse Proxy Camouflage

### CloudFlare as Operational Shield

**Concept:** CDN hides backend IP address

**Architecture:**
```
Operator → CloudFlare → Backend C2

Shodan scans CloudFlare IPs → Sees CloudFlare, not backend
Backend IP never exposed publicly
```

**Configuration:**
```
1. Register domain, point DNS to CloudFlare
2. Enable CloudFlare proxy (orange cloud)
3. Backend server allows only CloudFlare IP ranges:

# /etc/nginx/nginx.conf
set_real_ip_from 103.21.244.0/22;  # CloudFlare ranges
set_real_ip_from 103.22.200.0/22;
# ... all CloudFlare ranges
real_ip_header CF-Connecting-IP;

# Firewall: Block all non-CloudFlare
ufw deny from any
ufw allow from 103.21.244.0/22
# ... all CloudFlare ranges
```

**OPSEC Benefits:**
- Backend IP invisible to scanners
- DDoS protection
- SSL termination at CloudFlare (reduces backend attack surface)

**Risks:**
- CloudFlare can see all traffic (acceptable for operations post-TLS)
- CloudFlare complies with law enforcement (use for low/medium risk only)

---

## VII. Decoy Infrastructure

### Honeypots & Deception

**Concept:** Deploy fake infrastructure to waste adversary resources

**Honeypot C2:**
```
Deploy fake C2 server:
- Responds to scanner queries
- Logs all connection attempts
- Serves fake data to confuse threat intel

Purpose:
- Identify adversary IPs (who's scanning us?)
- Disinformation (fake malware samples)
- Threat intelligence gathering
```

**Operational vs. Decoy Ratio:**
```
1 Operational C2
+
9 Decoy C2s

Adversary must analyze all 10 → 90% wasted effort
```

---

## VIII. Operational Network Segmentation

### Air-Gap Critical Infrastructure

**Principle:** Backend C2 has NO direct internet access

**Architecture:**
```
Internet → Redirector (public) → DMZ
                ↓
           Firewall (one-way)
                ↓
        Backend C2 (air-gapped LAN)

Backend can only be reached via redirector
No direct inbound from internet
```

**Firewall Rules:**
```bash
# Redirector can initiate connections to backend
iptables -A FORWARD -s [REDIRECTOR_IP] -d [BACKEND_IP] -j ACCEPT

# Backend CANNOT initiate outbound (air-gap enforcement)
iptables -A OUTPUT -s [BACKEND_IP] -d ! [REDIRECTOR_IP] -j DROP
```

---

## IX. Monitoring & Attribution Resistance

### Log Analysis & Scanner Detection

**Automated Scanner Detection:**
```python
import re
from collections import Counter

def detect_scanners(access_log):
    """Analyze access logs for scanner patterns"""
    
    ips = Counter()
    for line in access_log:
        ip = extract_ip(line)
        ips[ip] += 1
    
    # Flag IPs with >100 requests/hour (scanner behavior)
    scanners = [ip for ip, count in ips.items() if count > 100]
    
    # Check User-Agents
    scanner_agents = [
        'nmap', 'masscan', 'zgrab', 'shodan', 'censys'
    ]
    
    for line in access_log:
        if any(agent in line.lower() for agent in scanner_agents):
            print(f"ALERT: Scanner detected: {line}")
```

**Automated Response:**
```bash
# If scanner detected → Block + Alert
if scanner_detected:
    ufw insert 1 deny from $SCANNER_IP
    telegram_notify("Scanner detected: $SCANNER_IP")
```

---

## X. Conclusion

**Infrastructure Stealth Principles:**

1. **Filter First:** Redirectors expose minimal surface
2. **Age Domains:** Newly registered = suspicious
3. **Scrub Banners:** No server version leakage
4. **Burn Fast:** 30-day maximum infrastructure lifespan
5. **CDN Shield:** Hide backend IPs
6. **Decoys:** Deploy 9 fakes per 1 real

**Realistic Expectations:**
- Against automated scanners (Shodan): Evasion highly effective with proper config
- Against targeted adversary: Stealth buys time, not invisibility
- Assume discovery within 30-60 days; plan for rapid pivoting

---

*Кто владеет информацией, тот владеет миром*

"The infrastructure is the target. Hide it until use, burn it after discovery."

**Operational Reminder:** Stealth is temporary. Rapid rotation > perfect hiding.

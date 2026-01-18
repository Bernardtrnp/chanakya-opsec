# Welcome to CHANAKYA

**CHANAKYA** is a research-grade framework for understanding how operational security fails through emergent signal correlation across abstraction layers.

> *知己知彼，百战不殆*  
> "Know yourself and know your enemy, and you will never be defeated in a hundred battles." — Sun Tzu

---

## What is CHANAKYA?

CHANAKYA is **not** an OPSEC checklist or compliance framework. It is a **multi-INT intelligence analysis platform** that models how weak signals combine across 15 dimensions to enable attribution.

### Core Principle

**OPSEC failures emerge from signal correlation, not checklist violations.**

---

## Framework Architecture

**15 Comprehensive OPSEC Dimensions:**

| Category | Layers | Purpose |
|----------|--------|---------|
| **Technical** | 6 layers | Browser, Userland, Kernel, DNS, Routing, Metadata |
| **Intelligence** | 6 layers | OSINT, SIGINT, GEOINT, HUMINT, Forensics, AI-Augmented |
| **Operational** | 3 layers | Anti-Forensics, Financial Privacy, Infrastructure Stealth |

---

## Quick Navigation

### 📚 Core Documentation
- [[Philosophy]] - Core principles & threat philosophy
- [[Threat Model]] - Adversary capabilities (Tier 0-3.5)
- [[OPSEC Failure Taxonomy]] - 50+ failure mode classification
- [[Signal Scoring Methodology]] - V×R×C quantitative formula

### 🌐 Technical Layers
- [[Browser OPSEC]] - WebRTC leaks, Canvas fingerprinting
- [[DNS Layer]] - Resolver correlation, sinkhole detection
- [[Routing Layer]] - BGP, AS-path analysis
- [[Metadata & Temporal]] - Activity timing, behavioral entropy

### 🔍 Intelligence Layers
- [[OSINT Correlation]] - GitHub mining, LinkedIn inference
- [[SIGINT Attribution]] - Traffic analysis, cellular tracking
- [[GEOINT Geospatial]] - Timezone triangulation, satellite imagery
- [[HUMINT Social Engineering]] - Behavioral profiling, conferences
- [[Forensics Attribution]] - EXIF, filesystem, memory analysis

### 🛡️ Advanced Operational
- [[Anti-Forensics]] - HiddenVM, amnesic OS, plausible deniability
- [[Financial Privacy]] - Monero, CoinJoin, blockchain analysis
- [[Infrastructure Stealth]] - Redirectors, Shodan evasion, domain aging

### 🤖 AI-Era Enhancements
- [[AI-Augmented Attribution]] - Graph ML, LSTMs, retrospective correlation
- [[Behavioral Entropy]] - Shannon entropy quantification
- [[Counter-AI OPSEC]] - Defensive techniques vs machine learning

### ⚙️ Framework & Tools
- [[Personal OPSEC Checklist]] - Military-grade operational manual
- [[Test Suite]] - Attribution scenarios & pre-operation audit
- [[Contributing Guide]] - Git workflow & development standards

---

## Target Audience

- **Intelligence Analysts** - All-source fusion & attribution
- **Red Team Operators** - Understanding infrastructure leakage
- **Security Researchers** - Attribution technique research
- **Military Cyber Operations** - Nation-state resistance

---

## Attribution Weight Formula

**AW = V × R × C**

- **V** = Visibility (0.0-1.0) - How observable is the signal?
- **R** = Retention (0.0-1.0) - How long is it logged/stored?
- **C** = Correlation (0.0-1.0) - How linkable to other signals?

**Risk Tiers:**
- **AW > 0.8:** CRITICAL (immediate attribution likely)
- **AW 0.5-0.8:** HIGH (attribution probable with analysis)
- **AW 0.3-0.5:** MEDIUM (requires cross-INT correlation)
- **AW < 0.3:** LOW (weak signal, difficult to attribute alone)

---

## Getting Started

1. **Understand the Philosophy** → Read [[Philosophy]]
2. **Model Your Threats** → Review [[Threat Model]]  
3. **Run Personal Audit** → `python tests/personal_opsec_audit.py`
4. **Analyze Attribution** → `python tests/test_attribution_scenarios.py`
5. **Explore Layers** → Navigate to specific INT discipline above

---

## Key Resources

- **Repository:** https://github.com/bb1nfosec/chanakya-opsec
- **Interactive Wiki:** https://bb1nfosec.github.io/chanakya-opsec/ (once Pages enabled)
- **License:** MIT (Research & Education Only)

---

## Contributing

See [[Contributing Guide]] for:
- Git workflow & branch conventions
- Documentation standards
- Pull request template
- Testing requirements

---

*Кто владеет информацией, тот владеет миром*  
"Who controls information, controls the world."

**CHANAKYA: Where signals converge, attribution emerges.**

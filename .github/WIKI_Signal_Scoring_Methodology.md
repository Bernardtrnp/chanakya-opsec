# Signal Scoring Methodology

## Overview

Quantitative framework for assessing attribution risk using the **V×R×C formula**.

**Attribution Weight (AW) = Visibility × Retention × Correlation**

This methodology enables objective, numeric risk assessment rather than qualitative "high/medium/low" classifications.

---

## Formula Components

### Visibility (V)

**Definition:** How observable/measurable is the signal to an adversary?

**Scale:** 0.0 (unobservable) → 1.0 (fully observable)

**Examples:**

| Signal | Visibility | Rationale |
|--------|-----------|-----------|
| Public GitHub commit | 1.0 | Fully public, indexed by search engines |
| VPN IP address | 0.9 | VPN provider logs, but not publicly visible |
| Encrypted traffic metadata | 0.7 | Volume/timing visible despite encryption |
| Private key material | 0.0 | Unobservable unless leaked |

**Assessment Questions:**
- Is this signal publicly accessible?
- Can passive network monitoring observe it?
- Is it logged by third parties (ISP, VPN, CDN)?

---

### Retention (R)

**Definition:** How long is the signal stored/logged?

**Scale:** 0.0 (ephemeral) → 1.0 (permanent)

**Examples:**

| Signal | Retention | Rationale |
|--------|-----------|-----------|
| GitHub commit history | 1.0 | Permanent, even after "deletion" (forks) |
| Passive DNS records | 1.0 | Archived indefinitely (Farsight, etc.) |
| VPN session logs | 0.5 | Varies by provider (14-90 days typical) |
| RAM-only data | 0.1 | Lost on reboot (unless cold boot attack) |

**Assessment Questions:**
- How long do logs persist?
- Is there historical data (passive DNS, Wayback Machine)?
- Can the signal be forensically recovered later?

---

### Correlation (C)

**Definition:** How linkable is this signal to other signals or identities?

**Scale:** 0.0 (isolated) → 1.0 (direct linkage)

**Examples:**

| Signal | Correlation | Rationale |
|--------|----------|-----------|
| Real IP leaked via WebRTC | 1.0 | Direct link to ISP subscriber |
| GitHub commit timing | 0.9 | High correlation with operational activity |
| TLS fingerprint | 0.7 | Can cluster infrastructure, not direct ID |
| Random timing jitter | 0.2 | Difficult to correlate across operations |

**Assessment Questions:**
- Does this signal directly identify an individual/entity?
- Can it be correlated with other signals (timing, location, style)?
- Is it unique enough to cluster operations?

---

## Attribution Weight Calculation

### Example 1: WebRTC IP Leak

```
Visibility (V) = 1.0  # Always leaks to JavaScript
Retention (R) = 0.9   # Logged by servers long-term
Correlation (C) = 1.0 # Direct ISP subscriber linkage

AW = 1.0 × 0.9 × 1.0 = 0.90 (CRITICAL)
```

**Risk:** Immediate attribution likely. Real IP bypasses VPN/Tor.

---

### Example 2: GitHub Commit Timing

```
Visibility (V) = 1.0  # Public GitHub API
Retention (R) = 1.0   # Permanent commit history
Correlation (C) = 0.85 # Temporal correlation with ops

AW = 1.0 × 1.0 × 0.85 = 0.85 (CRITICAL)
```

**Risk:** Timing patterns reveal timezone, operational hours, identity linkage.

---

### Example 3: Encrypted Traffic Volume

```
Visibility (V) = 0.7  # ISP can see metadata
Retention (R) = 0.8   # Netflow logs (90 days)
Correlation (C) = 0.6 # Volume patterns cluster operations

AW = 0.7 × 0.8 × 0.6 = 0.34 (MEDIUM)
```

**Risk:** Requires cross-layer correlation, but feasible with ML.

---

## Risk Tier Classification

| Attribution Weight | Risk Tier | Meaning |
|--------------------|-----------|---------|
| **0.8 - 1.0** | 🔴 CRITICAL | Immediate attribution likely with single signal |
| **0.5 - 0.8** | 🟠 HIGH | Attribution probable with basic analysis |
| **0.3 - 0.5** | 🟡 MEDIUM | Requires cross-INT fusion or ML clustering |
| **0.0 - 0.3** | 🟢 LOW | Weak signal, difficult to attribute alone |

---

## Multi-Layer Correlation

### Composite Attribution Weight

When **N signals** correlate:

**Composite AW = 1 - ∏(1 - AWᵢ)**

**Example:** 3 signals with AW = 0.5, 0.6, 0.4

```
Composite AW = 1 - [(1-0.5) × (1-0.6) × (1-0.4)]
             = 1 - [0.5 × 0.4 × 0.6]
             = 1 - 0.12
             = 0.88 (CRITICAL)
```

**Key Insight:** Multiple MEDIUM signals → CRITICAL when correlated.

---

## Temporal Degradation

**OPSEC degrades over time.**

Signals accumulate. Correlation improves. Attribution becomes easier.

### OPSEC Half-Life Model

**t½ = Time for AW to increase from 0.5 → 0.75**

**Factors affecting degradation:**
- New data sources (passive DNS archives expand)
- ML model improvements (better clustering)
- Legal access (law enforcement subpoenas VPN logs)
- Operational mistakes (reuse infrastructure, timing patterns)

**Example:**
- Year 0: DNS query (AW = 0.3, LOW)
- Year 3: Passive DNS archived, correlated with GitHub (AW = 0.7, HIGH)
- Year 5: AI model clusters all infrastructure (AW = 0.9, CRITICAL)

**Mitigation:** Burn infrastructure before t½. Avoid long-term operations.

---

## Practical Application

### Pre-Operation Checklist

For each signal you emit:
1. **Calculate V×R×C**
2. **If AW > 0.8:** STOP. Fix before proceeding.
3. **If AW 0.5-0.8:** Document risk, plan mitigation.
4. **If AW < 0.5:** Monitor over time (degradation risk).

### Example Audit: Operational Infrastructure

| Signal | V | R | C | AW | Risk | Mitigation |
|--------|---|---|---|----|----|-------------|
| Domain WHOIS | 0.9 | 1.0 | 0.8 | 0.72 | HIGH | Privacy WHOIS, offshore registrar |
| SSL Certificate (CT log) | 1.0 | 1.0 | 0.7 | 0.70 | HIGH | Delay issuance, temporal spacing |
| Server IP (Shodan scan) | 0.9 | 0.9 | 0.6 | 0.49 | MEDIUM | Redirector, CDN shield |
| GitHub commit time | 1.0 | 1.0 | 0.9 | 0.90 | **CRITICAL** | **Randomize timing ±6h** |

**Composite AW:** 0.98 (CRITICAL) - Multiple signals correlate.

**Action:** Fix GitHub timing before operation proceeds.

---

## Advanced: Bayesian Attribution Confidence

### Formula

**P(Attribution | Signals) = (P(Signals | Attribution) × P(Attribution)) / P(Signals)**

**Where:**
- **P(Attribution):** Prior probability (base rate of attribution)
- **P(Signals | Attribution):** Likelihood (how often these signals lead to attribution)
- **P(Signals):** Probability of observing these signals by chance

**Example:**
```
Prior: 1% chance adversary investigating you
Signals: GitHub timing (AW=0.9), WebRTC leak (AW=0.9), Passive DNS (AW=0.7)

Composite AW = 0.997 (near-certain correlation)

Posterior P(Attribution) ≈ 95%+ confidence
```

---

## References

- **Academic:** "Deanonymizing Tor via Machine Learning" (Ling et al., 2016)
- **Industry:** Chainalysis blockchain attribution methodology
- **MITRE:** ATT&CK Technique T1590 (Gather Victim Network Information)
- **NSA:** "SIGINT targeting methodologies" (Snowden documents)

---

**Related:**
- [[Philosophy]] - Why signal correlation matters
- [[AI-Augmented Attribution]] - How ML amplifies weak signals
- [[Behavioral Entropy]] - Quantifying unpredictability

---

*知己知彼，百战不殆*

"Quantify risk. Mitigate risk. Accept residual risk. Operate anyway."

# Data Protection Explorer

Interactive GRC single-page application for **technical data protection controls**. Covers DLP, encryption (at rest, in transit, in use), data classification, database security, backup & recovery, key management, data masking & tokenization, and secure disposal.

> **Scope distinction:** This repository covers *technical* data protection controls (encryption, DLP, key management, etc.). For *privacy and legal compliance* (consent management, data subject rights, breach notification obligations), see [dawuds/pdpa-my](https://github.com/dawuds/pdpa-my).

---

## Quick Start

Serve the directory with any static file server:

```bash
npx serve .
# or
python3 -m http.server 8000
```

Open `index.html` in a browser.

## Validation

```bash
node validate.js
```

---

## What This Repository Covers

| Layer | Content |
|---|---|
| **Controls** | 50 technical controls across 10 domains with framework mappings |
| **Domains** | Data Classification, Encryption (at rest / in transit / in use), DLP, Key Management, Backup & Recovery, Database Security, Data Masking & Tokenization, Secure Disposal |
| **Technologies** | 6 technology deep-dives (DLP, encryption, classification, key management, tokenization, backup & recovery) |
| **Sectors** | 3 sector-specific files (financial services, healthcare, government) |
| **Frameworks** | Multi-framework mapping across NIST, PCI DSS, ISO 27001, CSA CCM, BNM RMiT |
| **Cross-References** | Control-to-framework mappings, technology-to-control links |

---

## Frameworks Covered

- **NIST SP 800-53 Rev. 5** (SC/MP families)
- **NIST SP 800-171 Rev. 2** (CUI Protection)
- **PCI DSS v4.0** (Requirements 3, 4, 9, 12)
- **ISO 27001:2022 Annex A.8** (Technological Controls)
- **CSA CCM v4** (DSP, CEK domains)
- **BNM RMiT** (S10 — data security)

---

## Control Domains (10)

1. Data Classification
2. Encryption at Rest
3. Encryption in Transit
4. Encryption in Use
5. Data Loss Prevention
6. Key Management
7. Backup & Recovery
8. Database Security
9. Data Masking & Tokenization
10. Secure Disposal

---

## Technology Deep-Dives (6)

Each technology area includes architecture patterns, product categories, implementation guidance, and framework mappings:

- **DLP** — endpoint, network, and cloud DLP patterns
- **Encryption** — at rest, in transit, in use (including envelope encryption, TLS, and confidential computing)
- **Classification** — automated and manual data classification schemes
- **Key Management** — HSM, KMS, key lifecycle, rotation policies
- **Tokenization** — format-preserving tokenization, vaultless approaches, data masking
- **Backup & Recovery** — immutable backups, RTO/RPO planning, air-gapped strategies

---

## Sector-Specific Files (3)

- **Financial Services** — PCI DSS alignment, BNM RMiT data-at-rest requirements, transaction data protection
- **Healthcare** — Patient data encryption, medical device data flows, health record classification
- **Government** — Classified data handling, sovereign key management, cross-agency data sharing

---

## Related Repositories

| Repository | Relationship |
|---|---|
| [dawuds/pdpa-my](https://github.com/dawuds/pdpa-my) | Privacy & legal compliance (consent, data subject rights, breach notification) — complements this repo's technical controls |
| [dawuds/RMIT](https://github.com/dawuds/RMIT) | BNM RMiT — S10 data security requirements reference this repo's encryption and DLP controls |
| [dawuds/cloud-sec](https://github.com/dawuds/cloud-sec) | Cloud security — overlaps on cloud-native encryption, KMS, and DLP integration |

---

## License

CC-BY-4.0

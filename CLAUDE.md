# dataprotection — Data Protection Controls

## What This Is
Structured knowledge base for data protection: encryption, DLP, key management, classification, backup/recovery. SPA explorer with JSON data layers.

## Architecture
- **SPA**: `index.html` + `app.js` + `style.css` (vanilla JS, no build step)
- **Data**: JSON files across controls, cross-references, technologies, sectors, frameworks, threats, evidence, templates
- **Schema**: GRC Portfolio v2.0 Standardized Schema

## Key Data Files
- `controls/library.json` — 50 controls
- `controls/domain-index.json` — 10 domains
- `technologies/` — encryption.json, dlp.json, key-management.json, tokenization.json, classification.json, backup-recovery.json
- `sectors/` — financial-services.json, healthcare.json, government.json
- `threats/data-breach-vectors.json` — Data breach attack vectors

## Cross-References
- `cross-references/dp-to-pdpa.json` — Maps to PDPA data security requirements
- `cross-references/dp-to-nist-csf.json` — NIST CSF alignment
- `cross-references/dp-to-pci-dss.json` — PCI DSS data protection requirements

## Conventions
- Kebab-case slugs for all IDs
- Technology files detail implementation-specific controls (algorithm choices, key lengths, etc.)

## Important
- Encryption algorithm recommendations must be current — deprecated algorithms flagged
- Key management lifecycle: generation, distribution, storage, rotation, destruction
- DLP rules are environment-specific — templates need customization

## Validation
```bash
node validate.js
```

## Related Repos
- `pdpa-my/` — PDPA data security controls (Section 9, Security Principle)
- `nacsa/` — CoP 11.0 Data Security domain
- `pci-dss/` — PCI DSS protect-account-data requirements

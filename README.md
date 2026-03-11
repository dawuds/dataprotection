# Data Protection Explorer

Interactive GRC single-page application for technical data protection controls. Covers DLP, encryption (at rest, in transit, in use), data classification, database security, backup & recovery, key management, data masking & tokenization, and secure disposal.

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

## Frameworks Covered

- NIST SP 800-53 Rev. 5 (SC/MP families)
- NIST SP 800-171 Rev. 2 (CUI Protection)
- PCI DSS v4.0 (Requirements 3, 4, 9, 12)
- ISO 27001:2022 Annex A.8 (Technological Controls)
- CSA CCM v4 (DSP, CEK domains)
- BNM RMiT (S10 — data security)

## License

CC-BY-4.0

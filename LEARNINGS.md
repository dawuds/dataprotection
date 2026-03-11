# Learnings

## Architecture Decisions

- **10 domains, 50 controls**: Provides comprehensive coverage without being overwhelming. Each domain has 4-6 controls.
- **Single risk-management/index.json**: Consolidates methodology, matrix, and register in one file to simplify loading. The NIST repo splits these across multiple files but for a domain-specific SPA, one file is cleaner.
- **Framework data as separate files**: Each framework (NIST 800-53, PCI DSS, ISO 27001) loaded on demand to keep initial load fast.
- **Technology deep-dives**: Separated from controls to allow rich vendor/architecture content without bloating the control library.

## Data Quality Notes

- All framework control IDs are real (SC-12, A.8.24, PCI 3.5.1, etc.) but descriptions are paraphrased (sourceType: constructed-indicative)
- All breach incidents are real with verified details from public sources
- BNM RMiT section numbers (S10.xx) reference the actual document structure
- Malaysian government classification levels (RAHSIA, SULIT, etc.) follow the Official Secrets Act 1972

## Technical Notes

- app.js uses ES5-compatible syntax (var, function) for maximum browser compatibility
- No build step required — pure vanilla JS SPA
- Hash routing with #control/slug pattern for deep linking
- Sub-tab state managed via DOM class toggling (not hash) to avoid unnecessary re-renders

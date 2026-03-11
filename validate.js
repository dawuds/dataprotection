#!/usr/bin/env node
/* ============================================
   Data Protection Explorer — Validation Script
   Checks JSON validity and cross-reference integrity.
   ============================================ */

const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
let errors = 0;
let warnings = 0;
let filesChecked = 0;

function check(condition, msg) {
  if (!condition) {
    console.error('  ERROR: ' + msg);
    errors++;
  }
}

function warn(msg) {
  console.warn('  WARN: ' + msg);
  warnings++;
}

function loadJSON(relPath) {
  const fullPath = path.join(ROOT, relPath);
  try {
    const raw = fs.readFileSync(fullPath, 'utf8');
    filesChecked++;
    return JSON.parse(raw);
  } catch (e) {
    console.error('  ERROR: Failed to load/parse ' + relPath + ': ' + e.message);
    errors++;
    return null;
  }
}

console.log('=== Data Protection Explorer — Validation ===\n');

// 1. Core data files
console.log('[1] Checking core data files...');
const library = loadJSON('controls/library.json');
const domainIndex = loadJSON('controls/domain-index.json');
const evidence = loadJSON('evidence/index.json');
const artifacts = loadJSON('artifacts/inventory.json');
const fwIndex = loadJSON('frameworks/index.json');
const riskMgmt = loadJSON('risk-management/index.json');

check(library && library.controls, 'controls/library.json must have controls array');
check(domainIndex && domainIndex.domains, 'controls/domain-index.json must have domains array');
check(evidence && evidence.evidenceItems, 'evidence/index.json must have evidenceItems array');
check(artifacts && artifacts.artifacts, 'artifacts/inventory.json must have artifacts array');
check(fwIndex && fwIndex.frameworks, 'frameworks/index.json must have frameworks array');
check(riskMgmt && riskMgmt.register, 'risk-management/index.json must have register object');

// 2. Control library validation
if (library && library.controls) {
  console.log('\n[2] Validating control library (' + library.controls.length + ' controls)...');
  check(library.controls.length >= 45, 'Should have at least 45 controls, found ' + library.controls.length);

  const slugs = new Set();
  const domains = new Set();
  library.controls.forEach(function(ctrl) {
    check(ctrl.slug, 'Control missing slug');
    check(ctrl.name, 'Control ' + (ctrl.slug || '?') + ' missing name');
    check(ctrl.domain, 'Control ' + (ctrl.slug || '?') + ' missing domain');
    check(ctrl.description, 'Control ' + (ctrl.slug || '?') + ' missing description');
    check(ctrl.sourceType === 'constructed-indicative', 'Control ' + (ctrl.slug || '?') + ' should have sourceType "constructed-indicative"');
    check(ctrl.requirements, 'Control ' + (ctrl.slug || '?') + ' missing requirements');
    check(ctrl.keyActivities && ctrl.keyActivities.length > 0, 'Control ' + (ctrl.slug || '?') + ' missing keyActivities');
    check(ctrl.maturityLevels, 'Control ' + (ctrl.slug || '?') + ' missing maturityLevels');
    check(ctrl.frameworkMappings, 'Control ' + (ctrl.slug || '?') + ' missing frameworkMappings');

    if (ctrl.slug) {
      check(!slugs.has(ctrl.slug), 'Duplicate slug: ' + ctrl.slug);
      slugs.add(ctrl.slug);
    }
    if (ctrl.domain) domains.add(ctrl.domain);
  });

  check(domains.size === 10, 'Should have 10 domains, found ' + domains.size);
}

// 3. Domain index validation
if (domainIndex && domainIndex.domains) {
  console.log('\n[3] Validating domain index (' + domainIndex.domains.length + ' domains)...');
  check(domainIndex.domains.length === 10, 'Should have 10 domains');

  domainIndex.domains.forEach(function(dom) {
    check(dom.id, 'Domain missing id');
    check(dom.name, 'Domain ' + (dom.id || '?') + ' missing name');
    check(dom.description, 'Domain ' + (dom.id || '?') + ' missing description');
  });
}

// 4. Evidence validation
if (evidence && evidence.evidenceItems) {
  console.log('\n[4] Validating evidence items (' + evidence.evidenceItems.length + ' items)...');
  check(evidence.evidenceItems.length >= 50, 'Should have at least 50 evidence items, found ' + evidence.evidenceItems.length);

  evidence.evidenceItems.forEach(function(ev) {
    check(ev.id, 'Evidence item missing id');
    check(ev.name, 'Evidence ' + (ev.id || '?') + ' missing name');
    check(ev.controlSlugs && ev.controlSlugs.length > 0, 'Evidence ' + (ev.id || '?') + ' missing controlSlugs');
  });
}

// 5. Cross-reference validation
console.log('\n[5] Checking cross-reference files...');
var xrefFiles = ['dp-to-nist-csf.json', 'dp-to-iso27001.json', 'dp-to-pci-dss.json', 'dp-to-rmit.json', 'dp-to-pdpa.json'];
xrefFiles.forEach(function(f) {
  var data = loadJSON('cross-references/' + f);
  check(data && data.mappings, f + ' must have mappings array');
});

// 6. Framework detail files
console.log('\n[6] Checking framework detail files...');
if (fwIndex && fwIndex.frameworks) {
  fwIndex.frameworks.forEach(function(fw) {
    var data = loadJSON('frameworks/' + fw.dataFile);
    check(data !== null, 'Framework file ' + fw.dataFile + ' must be valid JSON');
  });
}

// 7. Technology files
console.log('\n[7] Checking technology files...');
var techFiles = ['dlp.json', 'encryption.json', 'key-management.json', 'tokenization.json', 'backup-recovery.json', 'classification.json'];
techFiles.forEach(function(f) {
  var data = loadJSON('technologies/' + f);
  check(data !== null, 'Technology file ' + f + ' must be valid JSON');
  if (data) {
    check(data.technology, f + ' must have technology field');
    check(data.sourceType === 'constructed-indicative', f + ' should have sourceType');
  }
});

// 8. Threat files
console.log('\n[8] Checking threat files...');
var vectors = loadJSON('threats/data-breach-vectors.json');
var incidents = loadJSON('threats/known-incidents.json');
check(vectors && vectors.vectors, 'data-breach-vectors.json must have vectors array');
check(incidents && incidents.incidents, 'known-incidents.json must have incidents array');
if (incidents && incidents.incidents) {
  check(incidents.incidents.length >= 8, 'Should have at least 8 real incidents');
  incidents.incidents.forEach(function(inc) {
    check(inc.year && inc.year >= 2010, 'Incident ' + (inc.name || '?') + ' should have valid year');
    check(inc.organization, 'Incident missing organization');
  });
}

// 9. Sector files
console.log('\n[9] Checking sector files...');
loadJSON('sectors/index.json');
loadJSON('sectors/financial-services.json');
loadJSON('sectors/healthcare.json');
loadJSON('sectors/government.json');

// 10. Template and artifact files
console.log('\n[10] Checking templates and artifacts...');
var templates = loadJSON('templates/index.json');
check(templates && templates.templates, 'templates/index.json must have templates array');

// 11. Risk management
if (riskMgmt && riskMgmt.register && riskMgmt.register.risks) {
  console.log('\n[11] Validating risk register (' + riskMgmt.register.risks.length + ' risks)...');
  check(riskMgmt.register.risks.length >= 15, 'Should have at least 15 risks, found ' + riskMgmt.register.risks.length);
  riskMgmt.register.risks.forEach(function(r) {
    check(r.id, 'Risk missing id');
    check(r.inherentRisk > 0, 'Risk ' + (r.id || '?') + ' must have positive inherentRisk');
    check(r.residualRisk > 0, 'Risk ' + (r.id || '?') + ' must have positive residualRisk');
    check(r.residualRisk <= r.inherentRisk, 'Risk ' + (r.id || '?') + ' residualRisk should be <= inherentRisk');
  });
}

// Summary
console.log('\n=== Validation Complete ===');
console.log('Files checked: ' + filesChecked);
console.log('Errors: ' + errors);
console.log('Warnings: ' + warnings);

if (errors > 0) {
  process.exit(1);
} else {
  console.log('\nAll checks passed!');
  process.exit(0);
}

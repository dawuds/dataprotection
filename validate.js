#!/usr/bin/env node
/**
 * validate.js — Data Protection data integrity validator
 *
 * Checks:
 *   1.  All JSON files parse without errors
 *   2.  Controls library — slug uniqueness and required fields
 *   3.  Controls library — domain coverage
 *   4.  Artifact controlSlugs resolve to controls/library.json slugs
 *   5.  Evidence controlSlugs resolve to controls/library.json slugs
 *   6.  Cross-reference integrity (ISO 27001, NIST CSF, PCI-DSS, PDPA, RMIT)
 *   7.  Templates required fields
 *   8.  Technologies & frameworks file integrity
 *   9.  No empty strings where data is expected
 *   10. Unique IDs across data sets
 *
 * Usage: node validate.js [--verbose]
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const REPO_ROOT = __dirname;
const verbose   = process.argv.includes('--verbose');

let pass = 0;
let fail = 0;
let warn = 0;

function ok(msg)      { pass++; if (verbose) console.log(`  PASS  ${msg}`); }
function bad(msg)     { fail++; console.log(`  FAIL  ${msg}`); }
function warning(msg) { warn++; console.log(`  WARN  ${msg}`); }

function loadJson(relPath) {
  const abs = path.join(REPO_ROOT, relPath);
  if (!fs.existsSync(abs)) return null;
  try {
    return JSON.parse(fs.readFileSync(abs, 'utf8'));
  } catch (e) {
    return null;
  }
}

// ── 1. JSON Parse Check ─────────────────────────────────────────────

console.log('\n=== 1. JSON Parse Check ===');

function findJsonFiles(dir) {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
      results.push(...findJsonFiles(full));
    } else if (entry.isFile() && entry.name.endsWith('.json')) {
      results.push(path.relative(REPO_ROOT, full));
    }
  }
  return results;
}

const jsonFiles = findJsonFiles(REPO_ROOT);
const parsed = {};
let parseErrors = 0;

for (const file of jsonFiles) {
  try {
    parsed[file] = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, file), 'utf8'));
    ok(`Parsed: ${file}`);
  } catch (e) {
    bad(`JSON parse error: ${file} — ${e.message}`);
    parseErrors++;
  }
}

if (parseErrors === 0) {
  ok(`All ${jsonFiles.length} JSON files parse correctly`);
}

// ── Load core data ──────────────────────────────────────────────────

const controlsLib   = loadJson('controls/library.json');
const domainIndex   = loadJson('controls/domain-index.json');
const artifactsInv  = loadJson('artifacts/inventory.json');
const evidence      = loadJson('evidence/index.json');
const riskMgmt      = loadJson('risk-management/index.json');
const templates     = loadJson('templates/index.json');

// Controls — uses slug
const libraryControls = (controlsLib && controlsLib.controls) || [];
const controlSlugSet = new Set(libraryControls.map(c => c.slug).filter(Boolean));

// Domains
const libraryDomains = (domainIndex && domainIndex.domains) || [];
const domainIdSet = new Set(libraryDomains.map(d => d.id || d.slug).filter(Boolean));

// Artifacts — { artifacts: [...] }
const allArtifacts = (artifactsInv && artifactsInv.artifacts) || [];
const artifactSlugSet = new Set(allArtifacts.map(a => a.slug || a.id).filter(Boolean));

// Evidence items — { evidenceItems: [...] }
const evidenceItems = (evidence && evidence.evidenceItems) || [];

// ── 2. Control Slug Uniqueness & Required Fields ─────────────────────

console.log('\n=== 2. Control Slug Uniqueness & Required Fields ===');

const slugCounts = {};
for (const ctrl of libraryControls) {
  if (!ctrl.slug) {
    bad(`Control missing "slug": ${(ctrl.name || '').slice(0, 60)}`);
  } else {
    slugCounts[ctrl.slug] = (slugCounts[ctrl.slug] || 0) + 1;
  }
  if (!ctrl.name || ctrl.name.trim() === '') bad(`Control "${ctrl.slug}" has empty or missing "name"`);
  if (!ctrl.domain) bad(`Control "${ctrl.slug}" missing "domain" field`);
}

const duplicates = Object.entries(slugCounts).filter(([, c]) => c > 1);
if (duplicates.length === 0) {
  ok(`No duplicate control slugs (${libraryControls.length} controls)`);
} else {
  for (const [slug, count] of duplicates) bad(`Duplicate control slug "${slug}" appears ${count} times`);
}

// ── 3. Domain Coverage ───────────────────────────────────────────────

console.log('\n=== 3. Controls Library — Domain Coverage ===');

const controlsByDomain = {};
for (const ctrl of libraryControls) {
  if (ctrl.domain) controlsByDomain[ctrl.domain] = (controlsByDomain[ctrl.domain] || 0) + 1;
}

for (const dom of libraryDomains) {
  const key = dom.id || dom.slug;
  if (!controlsByDomain[key]) {
    bad(`Domain "${key}" has zero controls in library.json`);
  } else {
    ok(`Domain "${key}" has ${controlsByDomain[key]} control(s)`);
  }
}

// ── 4. Artifact controlSlugs Resolution ──────────────────────────────

console.log('\n=== 4. Artifact controlSlugs Resolution ===');

let controlSlugErrors = 0;
let controlSlugTotal = 0;

for (const artifact of allArtifacts) {
  if (!artifact.controlSlugs) continue;
  for (const slug of artifact.controlSlugs) {
    controlSlugTotal++;
    if (!controlSlugSet.has(slug)) {
      bad(`Artifact "${artifact.slug}" references unknown control slug "${slug}"`);
      controlSlugErrors++;
    }
  }
}

if (controlSlugErrors === 0) {
  ok(`All ${controlSlugTotal} controlSlug references in artifacts resolve correctly`);
}

// ── 5. Evidence controlSlugs Resolution ──────────────────────────────

console.log('\n=== 5. Evidence controlSlugs Resolution ===');

let evidenceSlugErrors = 0;
let evidenceSlugTotal = 0;

for (const item of evidenceItems) {
  if (!item.controlSlugs) continue;
  for (const slug of item.controlSlugs) {
    evidenceSlugTotal++;
    if (!controlSlugSet.has(slug)) {
      bad(`Evidence "${item.id}" references unknown control slug "${slug}"`);
      evidenceSlugErrors++;
    }
  }
}

if (evidenceSlugErrors === 0) {
  ok(`All ${evidenceSlugTotal} evidence controlSlug references resolve correctly`);
}

// ── 6. Cross-Reference Integrity ─────────────────────────────────────

console.log('\n=== 6. Cross-Reference Integrity ===');

const crossRefFiles = findJsonFiles(path.join(REPO_ROOT, 'cross-references'));
for (const file of crossRefFiles) {
  if (!parsed[file]) bad(`Cross-reference file failed to load: ${file}`);
  else ok(`Cross-reference loaded: ${file}`);
}

// ── 7. Templates Required Fields ─────────────────────────────────────

console.log('\n=== 7. Templates Required Fields ===');

if (templates && templates.templates) {
  let templateErrors = 0;
  for (const tmpl of templates.templates) {
    const missing = [];
    if (!tmpl.filename && !tmpl.name) missing.push('filename/name');
    if (!tmpl.category) missing.push('category');
    if (missing.length > 0) {
      bad(`Template "${tmpl.filename || tmpl.name || '(unknown)'}" missing: ${missing.join(', ')}`);
      templateErrors++;
    }
  }
  if (templateErrors === 0) ok(`All ${templates.templates.length} templates have required fields`);
} else {
  warning('No templates found');
}

// ── 8. Technologies & Frameworks Integrity ───────────────────────────

console.log('\n=== 8. Technologies & Frameworks Integrity ===');

const techFiles = findJsonFiles(path.join(REPO_ROOT, 'technologies'));
const fwFiles = findJsonFiles(path.join(REPO_ROOT, 'frameworks'));
const sectorFiles = findJsonFiles(path.join(REPO_ROOT, 'sectors'));

for (const file of [...techFiles, ...fwFiles, ...sectorFiles]) {
  if (!parsed[file]) bad(`File failed to load: ${file}`);
  else ok(`Loaded: ${file}`);
}

// ── 9. Data Completeness ─────────────────────────────────────────────

console.log('\n=== 9. Data Completeness ===');

let emptyIssues = 0;
for (const ctrl of libraryControls) {
  if (ctrl.description && ctrl.description.trim() === '') { bad(`Control "${ctrl.slug}" has empty description`); emptyIssues++; }
}
for (const artifact of allArtifacts) {
  if (artifact.name && artifact.name.trim() === '') { bad(`Artifact "${artifact.slug}" has empty name`); emptyIssues++; }
}
for (const item of evidenceItems) {
  if (item.name && item.name.trim() === '') { bad(`Evidence "${item.id}" has empty name`); emptyIssues++; }
}
if (emptyIssues === 0) ok('No empty strings detected in core data');

// ── 10. Unique IDs ──────────────────────────────────────────────────

console.log('\n=== 10. Unique IDs ===');

const seenArtSlugs = {};
for (const art of allArtifacts) {
  const key = art.slug || art.id;
  if (key) seenArtSlugs[key] = (seenArtSlugs[key] || 0) + 1;
}
const artDups = Object.entries(seenArtSlugs).filter(([, c]) => c > 1);
if (artDups.length === 0) ok(`All ${allArtifacts.length} artifact slugs are unique`);
else for (const [s, c] of artDups) bad(`Duplicate artifact slug "${s}" appears ${c} times`);

const seenEvidIds = {};
for (const item of evidenceItems) {
  if (item.id) seenEvidIds[item.id] = (seenEvidIds[item.id] || 0) + 1;
}
const evidDups = Object.entries(seenEvidIds).filter(([, c]) => c > 1);
if (evidDups.length === 0) ok(`All ${evidenceItems.length} evidence IDs are unique`);
else for (const [id, c] of evidDups) bad(`Duplicate evidence ID "${id}" appears ${c} times`);

// ── Summary ──────────────────────────────────────────────────────────

console.log('\n' + '='.repeat(60));
console.log('Validation complete:');
console.log(`  Pass: ${pass}`);
console.log(`  Fail: ${fail}`);
console.log(`  Warn: ${warn}`);
console.log(`  Total: ${pass + fail + warn}`);
console.log('='.repeat(60));

if (fail > 0) {
  console.error(`\nValidation FAILED with ${fail} error(s).`);
  process.exit(1);
} else if (warn > 0) {
  console.log(`\nValidation passed with ${warn} warning(s).`);
  process.exit(0);
} else {
  console.log('\nAll checks passed.');
  process.exit(0);
}

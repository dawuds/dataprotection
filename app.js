/* ============================================
   Data Protection Explorer — Application
   GRC Presentation Standard v1.0
   ============================================ */

// ---- State ----
const state = {
  domains: null,
  controls: null,
  frameworks: null,
  evidence: null,
  artifacts: null,
  riskMgmt: null,
  technologies: {},
  threats: null,
  incidents: null,
  sectors: null,
  crossRefs: {},
  templates: null,
  route: { view: 'overview' },
  searchQuery: '',
};

// ---- Data Cache ----
const cache = new Map();

function renderFetchError(el, url, error) {
  el.innerHTML = '<div class="fetch-error">' +
    '<h2>Failed to load data</h2>' +
    '<p>Could not fetch <strong>' + escHtml(url) + '</strong></p>' +
    (error ? '<p class="error-detail">' + escHtml(String(error)) + '</p>' : '') +
    '<button onclick="location.reload()">Retry</button>' +
    '</div>';
}

async function fetchJSON(path) {
  if (cache.has(path)) return cache.get(path);
  try {
    const res = await fetch(path);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    cache.set(path, data);
    return data;
  } catch (e) {
    console.error('Failed to load ' + path + ':', e);
    return null;
  }
}

// ---- Router ----
function parseHash() {
  const hash = location.hash.slice(1);
  if (!hash || hash === 'overview') return { view: 'overview' };
  if (hash === 'framework') return { view: 'framework' };
  if (hash === 'controls') return { view: 'controls' };
  if (hash === 'risk') return { view: 'risk' };
  if (hash === 'technologies') return { view: 'technologies' };
  if (hash === 'reference') return { view: 'reference' };

  if (hash.startsWith('search/')) return { view: 'search', query: decodeURIComponent(hash.slice(7)) };
  if (hash.startsWith('risk/')) return { view: 'risk', sub: hash.slice(5) };
  if (hash.startsWith('technologies/')) return { view: 'technologies', sub: hash.slice(13) };
  if (hash.startsWith('reference/')) return { view: 'reference', sub: decodeURIComponent(hash.slice(10)) };
  if (hash.startsWith('control/')) return { view: 'control', slug: hash.slice(8) };
  if (hash.startsWith('framework/')) return { view: 'framework', sub: hash.slice(10) };

  return { view: 'overview' };
}

function navigate(hash) {
  location.hash = '#' + hash;
}

// ---- Nav Management ----
function updateNav() {
  var raw = location.hash.slice(1) || 'overview';
  var view = raw.split('/')[0];
  document.querySelectorAll('.nav-link').forEach(function(el) {
    var v = el.dataset.view;
    el.classList.toggle('active', v === view ||
      (v === 'controls' && view === 'control'));
  });
}

// ---- Helpers ----
function escHtml(str) {
  var div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function getDomainColor(domainId) {
  return 'var(--dom-' + domainId + ')';
}

function getDomainBg(domainId) {
  return 'var(--dom-' + domainId + '-bg)';
}

function getControl(slug) {
  if (!state.controls) return null;
  return state.controls.find(function(c) { return c.slug === slug; });
}

function getControlsByDomain(domainId) {
  if (!state.controls) return [];
  return state.controls.filter(function(c) { return c.domain === domainId; });
}

function getDomain(domainId) {
  if (!state.domains) return null;
  return state.domains.find(function(d) { return d.id === domainId; });
}

// ---- Render Helpers ----
function renderBreadcrumbs(items) {
  return '<nav class="breadcrumbs">' + items.map(function(item, i) {
    if (i === items.length - 1) return '<span class="current">' + escHtml(item.label) + '</span>';
    return '<a href="#' + (item.hash || '') + '">' + escHtml(item.label) + '</a><span class="sep">/</span>';
  }).join('') + '</nav>';
}

function renderLoading() {
  return '<div class="loading"><div class="spinner"></div><span>Loading data...</span></div>';
}

function renderError(message, detail) {
  return '<div class="error-state">' +
    '<h2>Failed to load data</h2>' +
    '<p class="error-message">' + escHtml(detail || message) + '</p>' +
    '<button onclick="location.reload()">Retry</button>' +
    '</div>';
}

// ---- View: Overview ----
function renderOverview() {
  var totalControls = state.controls.length;
  var domainCount = state.domains.length;
  var evidenceCount = state.evidence ? state.evidence.evidenceItems.length : 0;
  var artifactCount = state.artifacts ? state.artifacts.artifacts.length : 0;

  return '<div class="stats-banner">' +
    '<div class="stat-card"><div class="stat-value">' + domainCount + '</div><div class="stat-label">Domains</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + totalControls + '</div><div class="stat-label">Controls</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + evidenceCount + '</div><div class="stat-label">Evidence Items</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + artifactCount + '</div><div class="stat-label">Artifacts</div></div>' +
    '<div class="stat-card"><div class="stat-value">4</div><div class="stat-label">Frameworks</div></div>' +
    '</div>' +
    '<div class="control-grid">' +
    state.domains.map(function(dom) {
      var controls = getControlsByDomain(dom.id);
      return '<div class="control-card dom-' + dom.id + '" onclick="navigate(\'controls\')">' +
        '<div class="control-card-header">' +
        '<span class="control-card-code">' + dom.id + '</span>' +
        '<span class="badge" style="background:' + getDomainBg(dom.id) + ';color:' + getDomainColor(dom.id) + '">' + controls.length + ' controls</span>' +
        '</div>' +
        '<h3 class="control-card-title">' + escHtml(dom.name) + '</h3>' +
        '<p class="control-card-desc">' + escHtml(dom.description) + '</p>' +
        '</div>';
    }).join('') +
    '</div>' +
    '<div style="margin-top:2rem; display:flex; gap:1.5rem; flex-wrap:wrap">' +
    '<a href="#framework" style="font-size:0.875rem">Browse Framework Mappings &rarr;</a>' +
    '<a href="#controls" style="font-size:0.875rem">Browse Controls Library &rarr;</a>' +
    '<a href="#risk" style="font-size:0.875rem">Risk Management &rarr;</a>' +
    '<a href="#technologies" style="font-size:0.875rem">Technology Deep-Dives &rarr;</a>' +
    '</div>';
}

// ---- View: Framework ----
function renderFramework(sub) {
  if (!state.frameworks) return renderError('Framework data not loaded');

  var fwList = state.frameworks.frameworks;
  var subTabs = ['nist-800-53-sc', 'nist-800-171', 'pci-dss-data', 'iso27001-a8'];
  var currentSub = sub && subTabs.indexOf(sub) >= 0 ? sub : 'nist-800-53-sc';

  var tabsHtml = '<div class="sub-tabs">' +
    fwList.map(function(fw) {
      return '<button class="sub-tab' + (currentSub === fw.id ? ' active' : '') + '" data-sub="' + fw.id + '">' + escHtml(fw.name) + '</button>';
    }).join('') +
    '</div>';

  var panelsHtml = fwList.map(function(fw) {
    var active = currentSub === fw.id ? ' active' : '';
    var content = renderFrameworkPanel(fw);
    return '<div class="sub-panel' + active + '" data-subpanel="' + fw.id + '">' + content + '</div>';
  }).join('');

  return '<h2 style="font-size:var(--font-size-xl);font-weight:700;margin-bottom:0.5rem">Framework Browser</h2>' +
    '<p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:1rem">Browse data protection requirements from NIST, PCI DSS, and ISO 27001 frameworks.</p>' +
    tabsHtml + panelsHtml;
}

function renderFrameworkPanel(fw) {
  var data = cache.get('frameworks/' + fw.dataFile);
  if (!data) return '<div class="loading"><span>Loading ' + escHtml(fw.name) + '...</span></div>';

  // NIST 800-53 SC
  if (fw.id === 'nist-800-53-sc') {
    var html = '<h3 style="margin-bottom:0.75rem">' + escHtml(data.familyName) + ' (' + data.family + ')</h3>';
    html += '<div class="accordion">';
    html += '<div class="accordion-item"><button class="accordion-trigger" data-accordion>' +
      '<span class="accordion-trigger-left"><span class="cat-id" style="background:var(--dom-EITR-bg);color:var(--dom-EITR)">SC</span><span>System & Communications Protection (' + data.controls.length + ')</span></span>' +
      '<span class="chevron">\u25B6</span></button>' +
      '<div class="accordion-content"><ul class="sub-list">' +
      data.controls.map(function(c) {
        return '<li><div class="sub-link"><span class="sub-id">' + escHtml(c.id) + '</span><span class="sub-desc"><strong>' + escHtml(c.title) + '</strong> — ' + escHtml(c.description) + '</span></div></li>';
      }).join('') + '</ul></div></div>';
    if (data.mpFamily) {
      html += '<div class="accordion-item"><button class="accordion-trigger" data-accordion>' +
        '<span class="accordion-trigger-left"><span class="cat-id" style="background:var(--dom-SDSP-bg);color:var(--dom-SDSP)">MP</span><span>' + escHtml(data.mpFamily.familyName) + ' (' + data.mpFamily.controls.length + ')</span></span>' +
        '<span class="chevron">\u25B6</span></button>' +
        '<div class="accordion-content"><ul class="sub-list">' +
        data.mpFamily.controls.map(function(c) {
          return '<li><div class="sub-link"><span class="sub-id">' + escHtml(c.id) + '</span><span class="sub-desc"><strong>' + escHtml(c.title) + '</strong> — ' + escHtml(c.description) + '</span></div></li>';
        }).join('') + '</ul></div></div>';
    }
    html += '</div>';
    return html;
  }

  // NIST 800-171
  if (fw.id === 'nist-800-171') {
    var html = '<h3 style="margin-bottom:0.75rem">CUI Protection Requirements</h3>';
    html += '<div class="accordion">';
    data.families.forEach(function(fam) {
      html += '<div class="accordion-item"><button class="accordion-trigger" data-accordion>' +
        '<span class="accordion-trigger-left"><span class="cat-id" style="background:var(--dom-EART-bg);color:var(--dom-EART)">' + escHtml(fam.id) + '</span><span>' + escHtml(fam.name) + ' (' + fam.requirements.length + ')</span></span>' +
        '<span class="chevron">\u25B6</span></button>' +
        '<div class="accordion-content"><ul class="sub-list">' +
        fam.requirements.map(function(r) {
          return '<li><div class="sub-link"><span class="sub-id">' + escHtml(r.id) + '</span><span class="sub-desc"><strong>' + escHtml(r.title) + '</strong> — ' + escHtml(r.description) + '</span></div></li>';
        }).join('') + '</ul></div></div>';
    });
    html += '</div>';
    return html;
  }

  // PCI DSS
  if (fw.id === 'pci-dss-data') {
    var html = '<h3 style="margin-bottom:0.75rem">PCI DSS Data Protection Requirements</h3>';
    html += '<div class="accordion">';
    data.requirements.forEach(function(req) {
      html += '<div class="accordion-item"><button class="accordion-trigger" data-accordion>' +
        '<span class="accordion-trigger-left"><span class="cat-id" style="background:var(--dom-DLPS-bg);color:var(--dom-DLPS)">' + escHtml(req.id.replace('Requirement ', 'Req ')) + '</span><span>' + escHtml(req.title) + ' (' + req.controls.length + ')</span></span>' +
        '<span class="chevron">\u25B6</span></button>' +
        '<div class="accordion-content"><ul class="sub-list">' +
        req.controls.map(function(c) {
          return '<li><div class="sub-link"><span class="sub-id">' + escHtml(c.id) + '</span><span class="sub-desc"><strong>' + escHtml(c.title) + '</strong> — ' + escHtml(c.description) + '</span></div></li>';
        }).join('') + '</ul></div></div>';
    });
    html += '</div>';
    return html;
  }

  // ISO 27001 A.8
  if (fw.id === 'iso27001-a8') {
    var html = '<h3 style="margin-bottom:0.75rem">' + escHtml(data.title) + '</h3>';
    html += '<ul class="sub-list">';
    data.controls.forEach(function(c) {
      html += '<li><div class="sub-link"><span class="sub-id">' + escHtml(c.id) + '</span><span class="sub-desc"><strong>' + escHtml(c.title) + '</strong> — ' + escHtml(c.description) + '</span></div></li>';
    });
    html += '</ul>';
    return html;
  }

  return '<p>Framework data format not recognized.</p>';
}

// ---- View: Controls ----
function renderControls() {
  var totalControls = state.controls.length;

  return '<div class="page-title">Controls & Implementation Library</div>' +
    '<div class="page-sub">' + totalControls + ' controls across ' + state.domains.length + ' domains</div>' +
    '<div class="accordion">' +
    state.domains.map(function(dom) {
      var controls = getControlsByDomain(dom.id);
      return '<div class="accordion-item">' +
        '<button class="accordion-trigger" data-accordion>' +
        '<span class="accordion-trigger-left">' +
        '<span class="cat-id" style="background:' + getDomainBg(dom.id) + ';color:' + getDomainColor(dom.id) + '">' + dom.id + '</span>' +
        '<span>' + escHtml(dom.name) + '</span>' +
        '<span style="color:var(--text-muted);font-weight:400;font-size:0.8125rem">(' + controls.length + ')</span>' +
        '</span>' +
        '<span class="chevron">\u25B6</span>' +
        '</button>' +
        '<div class="accordion-content">' +
        '<p style="font-size:0.8125rem;color:var(--text-secondary);margin-bottom:0.75rem">' + escHtml(dom.description) + '</p>' +
        '<ul class="clause-list">' +
        controls.map(function(ctrl) {
          return '<li><a class="clause-link" href="#control/' + ctrl.slug + '">' +
            '<span class="clause-id">' + ctrl.slug.toUpperCase() + '</span>' +
            '<span class="clause-title">' + escHtml(ctrl.name) + '</span>' +
            '</a></li>';
        }).join('') +
        '</ul></div></div>';
    }).join('') +
    '</div>';
}

// ---- View: Control Detail ----
function renderControlDetail(slug) {
  var ctrl = getControl(slug);
  if (!ctrl) return renderError('Control not found', 'No control with slug "' + slug + '" exists.');

  var dom = getDomain(ctrl.domain);
  var domName = dom ? dom.name : ctrl.domain;

  // Requirements
  var reqHtml = '';
  if (ctrl.requirements) {
    var r = ctrl.requirements;
    reqHtml = '<section class="detail-section">' +
      '<h2 class="detail-section-title">Requirements</h2>' +
      '<div class="requirements-grid">' +
      '<div class="requirement-block requirement-legal"><div class="requirement-block-label">Legal / Regulatory</div><ul>' +
      (r.legal && r.legal.length ? r.legal.map(function(l) { return '<li>' + escHtml(l) + '</li>'; }).join('') : '<li>See framework mappings below</li>') +
      '</ul></div>' +
      '<div class="requirement-block requirement-technical"><div class="requirement-block-label">Technical</div><ul>' +
      (r.technical && r.technical.length ? r.technical.map(function(t) { return '<li>' + escHtml(t) + '</li>'; }).join('') : '<li>See key activities below</li>') +
      '</ul></div>' +
      '<div class="requirement-block requirement-governance"><div class="requirement-block-label">Governance</div><ul>' +
      (r.governance && r.governance.length ? r.governance.map(function(g) { return '<li>' + escHtml(g) + '</li>'; }).join('') : '<li>See implementation guidance</li>') +
      '</ul></div>' +
      '</div></section>';
  }

  // Key Activities
  var actHtml = '';
  if (ctrl.keyActivities && ctrl.keyActivities.length) {
    actHtml = '<section class="detail-section">' +
      '<h2 class="detail-section-title">Key Activities</h2>' +
      '<div style="overflow-x:auto"><table class="data-table"><thead><tr><th>Activity</th><th>Owner</th><th>Frequency</th><th>Priority</th></tr></thead><tbody>' +
      ctrl.keyActivities.map(function(a) {
        return '<tr><td>' + escHtml(a.activity) + '</td>' +
          '<td style="white-space:nowrap">' + escHtml(a.owner) + '</td>' +
          '<td style="white-space:nowrap">' + escHtml(a.frequency) + '</td>' +
          '<td><span class="badge ' + (a.priority === 'High' ? 'badge-mandatory' : 'badge-category') + '">' + escHtml(a.priority) + '</span></td></tr>';
      }).join('') +
      '</tbody></table></div></section>';
  }

  // Maturity
  var matHtml = '';
  if (ctrl.maturityLevels) {
    var m = ctrl.maturityLevels;
    matHtml = '<section class="detail-section">' +
      '<h2 class="detail-section-title">Maturity Levels</h2>' +
      '<div class="maturity-grid">' +
      '<div class="maturity-card maturity-basic"><div class="maturity-label">Basic</div><p>' + escHtml(m.basic.description) + '</p></div>' +
      '<div class="maturity-card maturity-mature"><div class="maturity-label">Mature</div><p>' + escHtml(m.mature.description) + '</p></div>' +
      '<div class="maturity-card maturity-advanced"><div class="maturity-label">Advanced</div><p>' + escHtml(m.advanced.description) + '</p></div>' +
      '</div></section>';
  }

  // Audit Package (evidence + artifacts)
  var linkedEvidence = [];
  if (state.evidence && state.evidence.evidenceItems) {
    linkedEvidence = state.evidence.evidenceItems.filter(function(ev) {
      return ev.controlSlugs && ev.controlSlugs.indexOf(slug) >= 0;
    });
  }
  var linkedArtifacts = [];
  if (state.artifacts && state.artifacts.artifacts) {
    linkedArtifacts = state.artifacts.artifacts.filter(function(a) {
      return a.controlSlugs && a.controlSlugs.indexOf(slug) >= 0;
    });
  }

  var auditHtml = '';
  if (linkedEvidence.length || linkedArtifacts.length) {
    auditHtml = '<section class="audit-package">' +
      '<h2 class="audit-package-title">Audit Package<span class="audit-package-counts">' +
      (linkedEvidence.length ? '<span class="badge badge-evidence">' + linkedEvidence.length + ' evidence</span>' : '') +
      (linkedArtifacts.length ? '<span class="badge badge-artifacts">' + linkedArtifacts.length + ' artifacts</span>' : '') +
      '</span></h2>';

    if (linkedEvidence.length) {
      auditHtml += '<div class="accordion"><div class="accordion-item open"><button class="accordion-trigger" data-accordion>' +
        '<span>Evidence Checklist (' + linkedEvidence.length + ')</span><span class="chevron">\u25B6</span></button>' +
        '<div class="accordion-content">' +
        linkedEvidence.map(function(ev) {
          return '<div class="evidence-item">' +
            '<div class="evidence-item-header"><span class="evidence-id">' + escHtml(ev.id) + '</span>' +
            '<span class="evidence-item-name">' + escHtml(ev.name) + '</span></div>' +
            '<p class="evidence-item-desc">' + escHtml(ev.description) + '</p>' +
            '<div class="evidence-item-meta">' +
            (ev.format ? '<span class="meta-item"><strong>Format:</strong> ' + escHtml(ev.format) + '</span>' : '') +
            (ev.retentionPeriod ? '<span class="meta-item"><strong>Retention:</strong> ' + escHtml(ev.retentionPeriod) + '</span>' : '') +
            '</div></div>';
        }).join('') +
        '</div></div></div>';
    }

    if (linkedArtifacts.length) {
      auditHtml += '<div class="accordion"><div class="accordion-item open"><button class="accordion-trigger" data-accordion>' +
        '<span>Required Artifacts (' + linkedArtifacts.length + ')</span><span class="chevron">\u25B6</span></button>' +
        '<div class="accordion-content">' +
        linkedArtifacts.map(function(a) {
          return '<div class="artifact-card">' +
            '<div class="artifact-card-header"><span class="artifact-card-name">' + escHtml(a.name) + '</span>' +
            '<div class="artifact-card-badges">' +
            (a.mandatory ? '<span class="badge badge-mandatory">Mandatory</span>' : '<span class="badge badge-optional">Optional</span>') +
            (a.category ? '<span class="badge badge-category">' + escHtml(a.category) + '</span>' : '') +
            '</div></div>' +
            (a.description ? '<p class="artifact-card-desc">' + escHtml(a.description) + '</p>' : '') +
            '<div class="artifact-card-meta">' +
            (a.owner ? '<span class="meta-item"><strong>Owner:</strong> ' + escHtml(a.owner) + '</span>' : '') +
            (a.reviewFrequency ? '<span class="meta-item"><strong>Review:</strong> ' + escHtml(a.reviewFrequency) + '</span>' : '') +
            '</div></div>';
        }).join('') +
        '</div></div></div>';
    }

    auditHtml += '</section>';
  }

  // Framework Mappings
  var fwHtml = '';
  if (ctrl.frameworkMappings) {
    var fm = ctrl.frameworkMappings;
    var rows = [];
    if (fm.nist80053 && fm.nist80053.length) rows.push({ label: 'NIST 800-53', codes: fm.nist80053.join(', ') });
    if (fm.nist800171 && fm.nist800171.length) rows.push({ label: 'NIST 800-171', codes: fm.nist800171.join(', ') });
    if (fm.pciDss && fm.pciDss.length) rows.push({ label: 'PCI DSS v4.0', codes: fm.pciDss.join(', ') });
    if (fm.iso27001 && fm.iso27001.length) rows.push({ label: 'ISO 27001:2022', codes: fm.iso27001.join(', ') });
    if (fm.ccmV4 && fm.ccmV4.length) rows.push({ label: 'CSA CCM v4', codes: fm.ccmV4.join(', ') });

    if (rows.length) {
      fwHtml = '<section class="detail-section">' +
        '<h2 class="detail-section-title">Framework Mappings</h2>' +
        '<div class="fw-mappings">' +
        rows.map(function(r) {
          return '<div class="fw-mapping-row"><span class="fw-label">' + escHtml(r.label) + '</span><span class="fw-codes">' + escHtml(r.codes) + '</span></div>';
        }).join('') +
        '</div></section>';
    }
  }

  return '<article class="control-detail">' +
    renderBreadcrumbs([
      { label: 'Overview', hash: 'overview' },
      { label: 'Controls', hash: 'controls' },
      { label: ctrl.slug.toUpperCase() }
    ]) +
    '<header class="control-detail-header">' +
    '<div class="control-detail-id-row">' +
    '<span class="control-id">' + ctrl.slug.toUpperCase() + '</span>' +
    '<span class="badge" style="background:' + getDomainBg(ctrl.domain) + ';color:' + getDomainColor(ctrl.domain) + '">' + escHtml(domName) + '</span>' +
    '<span class="badge badge-source-indicative">constructed-indicative</span>' +
    '</div>' +
    '<h1 class="control-detail-title">' + escHtml(ctrl.name) + '</h1>' +
    '<p class="control-detail-desc">' + escHtml(ctrl.description) + '</p>' +
    '</header>' +
    reqHtml + actHtml + matHtml + auditHtml + fwHtml +
    '</article>';
}

// ---- View: Risk Management ----
function getRiskLevelClass(level) {
  switch (level) {
    case 'Critical': return 'risk-critical';
    case 'High': return 'risk-high';
    case 'Medium': return 'risk-medium';
    case 'Low': return 'risk-low';
    case 'Very Low': return 'risk-verylow';
    default: return '';
  }
}

function renderRiskMatrix(matrix) {
  return '<div class="risk-matrix-wrapper"><table class="risk-matrix-table"><thead><tr>' +
    '<th class="risk-matrix-corner">Likelihood / Impact</th>' +
    matrix.headers.columns.map(function(c) { return '<th>' + escHtml(c) + '</th>'; }).join('') +
    '</tr></thead><tbody>' +
    matrix.cells.map(function(row, i) {
      return '<tr><td class="risk-matrix-row-header">' + escHtml(matrix.headers.rows[i]) + '</td>' +
        row.map(function(cell) {
          return '<td class="risk-matrix-cell ' + getRiskLevelClass(cell.level) + '">' +
            '<span class="risk-matrix-score">' + cell.score + '</span>' +
            '<span class="risk-matrix-level">' + escHtml(cell.level) + '</span></td>';
        }).join('') + '</tr>';
    }).join('') +
    '</tbody></table></div>';
}

function renderRiskManagement(activeSub) {
  var rm = state.riskMgmt;
  if (!rm) return renderError('Risk management data not loaded');

  var register = rm.register;
  var methodology = rm.methodology;
  var matrix = rm.matrix;

  var totalRisks = register.risks.length;
  var criticalCount = register.risks.filter(function(r) { return r.inherentRiskLevel === 'Critical'; }).length;
  var highCount = register.risks.filter(function(r) { return r.inherentRiskLevel === 'High'; }).length;
  var avgResidual = (register.risks.reduce(function(s, r) { return s + r.residualRisk; }, 0) / totalRisks).toFixed(1);

  var subTabs = ['register', 'matrix', 'methodology'];
  var currentSub = activeSub && subTabs.indexOf(activeSub) >= 0 ? activeSub : 'register';

  return '<h2 style="font-size:var(--font-size-xl);font-weight:700;margin-bottom:0.5rem">Risk Management</h2>' +
    '<p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:1rem">Data protection risk assessment with 5x5 likelihood-impact matrix.</p>' +
    '<div class="stats-banner">' +
    '<div class="stat-card"><div class="stat-value">' + totalRisks + '</div><div class="stat-label">Risks</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + criticalCount + '</div><div class="stat-label">Critical</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + highCount + '</div><div class="stat-label">High</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + avgResidual + '</div><div class="stat-label">Avg Residual</div></div>' +
    '</div>' +
    '<div class="sub-tabs">' +
    '<button class="sub-tab' + (currentSub === 'register' ? ' active' : '') + '" data-sub="register">Risk Register (' + totalRisks + ')</button>' +
    '<button class="sub-tab' + (currentSub === 'matrix' ? ' active' : '') + '" data-sub="matrix">Matrix</button>' +
    '<button class="sub-tab' + (currentSub === 'methodology' ? ' active' : '') + '" data-sub="methodology">Methodology</button>' +
    '</div>' +

    // Register panel
    '<div class="sub-panel' + (currentSub === 'register' ? ' active' : '') + '" data-subpanel="register">' +
    '<div style="overflow-x:auto"><table class="data-table risk-register-table"><thead><tr><th>ID</th><th>Risk</th><th>Domain</th><th>Inherent</th><th>Residual</th><th>Treatment</th><th>Owner</th></tr></thead><tbody>' +
    register.risks.map(function(r) {
      return '<tr class="risk-row"><td class="mono" style="white-space:nowrap;font-weight:600">' + escHtml(r.id) + '</td>' +
        '<td><strong style="display:block">' + escHtml(r.title) + '</strong><span style="font-size:var(--font-size-xs);color:var(--text-muted)">' + escHtml(r.description.substring(0, 100)) + (r.description.length > 100 ? '...' : '') + '</span></td>' +
        '<td><span class="dom-pill dom-pill-' + r.domain + '">' + r.domain + '</span></td>' +
        '<td style="text-align:center"><span class="risk-score-badge ' + getRiskLevelClass(r.inherentRiskLevel) + '">' + r.inherentRisk + '</span><div style="font-size:var(--font-size-xs);color:var(--text-muted)">' + escHtml(r.inherentRiskLevel) + '</div></td>' +
        '<td style="text-align:center"><span class="risk-score-badge ' + getRiskLevelClass(r.residualRiskLevel) + '">' + r.residualRisk + '</span><div style="font-size:var(--font-size-xs);color:var(--text-muted)">' + escHtml(r.residualRiskLevel) + '</div></td>' +
        '<td><span class="badge badge-category">' + escHtml(r.treatment) + '</span></td>' +
        '<td style="font-size:var(--font-size-sm);white-space:nowrap">' + escHtml(r.owner) + '</td></tr>';
    }).join('') +
    '</tbody></table></div></div>' +

    // Matrix panel
    '<div class="sub-panel' + (currentSub === 'matrix' ? ' active' : '') + '" data-subpanel="matrix">' +
    renderRiskMatrix(matrix) +
    '<h4 style="font-size:var(--font-size-md);margin:1.5rem 0 0.75rem">Risk Levels</h4>' +
    '<div style="overflow-x:auto"><table class="data-table"><thead><tr><th>Level</th><th>Score Range</th><th>Action Required</th><th>Reporting</th></tr></thead><tbody>' +
    matrix.riskLevels.map(function(l) {
      return '<tr><td><span class="badge" style="background:' + l.color + ';color:white;padding:0.125rem 0.5rem">' + escHtml(l.level) + '</span></td>' +
        '<td class="mono">' + escHtml(l.range) + '</td>' +
        '<td style="font-size:var(--font-size-sm)">' + escHtml(l.action) + '</td>' +
        '<td style="font-size:var(--font-size-sm);white-space:nowrap">' + escHtml(l.reportingFrequency) + '</td></tr>';
    }).join('') +
    '</tbody></table></div></div>' +

    // Methodology panel
    '<div class="sub-panel' + (currentSub === 'methodology' ? ' active' : '') + '" data-subpanel="methodology">' +
    '<div class="impl-objective"><strong style="display:block;margin-bottom:0.25rem;font-size:var(--font-size-xs);text-transform:uppercase;letter-spacing:0.05em;color:var(--accent)">Purpose</strong>' + escHtml(methodology.purpose) + '</div>' +
    '<p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:1rem"><strong>Scope:</strong> ' + escHtml(methodology.scope) + '</p>' +
    '<h4 style="font-size:var(--font-size-md);margin-bottom:0.75rem">Assessment Process</h4>' +
    '<div style="overflow-x:auto"><table class="data-table"><thead><tr><th>Step</th><th>Name</th><th>Description</th></tr></thead><tbody>' +
    methodology.riskAssessmentProcess.map(function(step) {
      return '<tr><td style="font-weight:600;white-space:nowrap">' + step.step + '</td><td><strong>' + escHtml(step.name) + '</strong></td><td style="font-size:var(--font-size-sm);color:var(--text-secondary)">' + escHtml(step.description) + '</td></tr>';
    }).join('') +
    '</tbody></table></div>' +
    '<h4 style="font-size:var(--font-size-md);margin:1.5rem 0 0.75rem">Review Schedule</h4>' +
    '<div style="overflow-x:auto"><table class="data-table"><thead><tr><th>Type</th><th>Schedule</th></tr></thead><tbody>' +
    '<tr><td style="font-weight:600">Full Assessment</td><td>' + escHtml(methodology.reviewSchedule.fullAssessment) + '</td></tr>' +
    '<tr><td style="font-weight:600">Quarterly Review</td><td>' + escHtml(methodology.reviewSchedule.quarterlyReview) + '</td></tr>' +
    '<tr><td style="font-weight:600">Trigger-Based Review</td><td>' + escHtml(methodology.reviewSchedule.triggerBasedReview) + '</td></tr>' +
    '</tbody></table></div></div>';
}

// ---- View: Technologies ----
function renderTechnologies(activeSub) {
  var techKeys = ['dlp', 'encryption', 'key-management', 'tokenization', 'backup-recovery', 'classification'];
  var techNames = {
    'dlp': 'DLP',
    'encryption': 'Encryption',
    'key-management': 'Key Management',
    'tokenization': 'Tokenization',
    'backup-recovery': 'Backup & Recovery',
    'classification': 'Classification'
  };

  var currentSub = activeSub && techKeys.indexOf(activeSub) >= 0 ? activeSub : 'dlp';

  var tabsHtml = '<div class="sub-tabs">' +
    techKeys.map(function(k) {
      return '<button class="sub-tab' + (currentSub === k ? ' active' : '') + '" data-sub="' + k + '">' + techNames[k] + '</button>';
    }).join('') +
    '</div>';

  var panelsHtml = techKeys.map(function(k) {
    var active = currentSub === k ? ' active' : '';
    var data = state.technologies[k];
    var content = data ? renderTechPanel(data) : '<div class="loading"><span>Loading...</span></div>';
    return '<div class="sub-panel' + active + '" data-subpanel="' + k + '">' + content + '</div>';
  }).join('');

  return '<h2 style="font-size:var(--font-size-xl);font-weight:700;margin-bottom:0.5rem">Technology Deep-Dives</h2>' +
    '<p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:1rem">Technical architecture, vendor landscape, and implementation guidance for key data protection technologies.</p>' +
    tabsHtml + panelsHtml;
}

function renderTechPanel(data) {
  var html = '<h3 style="margin-bottom:0.5rem">' + escHtml(data.technology) + '</h3>' +
    '<p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:1.5rem">' + escHtml(data.description) + '</p>';

  // Architecture diagram
  if (data.architecture && data.architecture.diagram) {
    html += '<h4 style="font-size:var(--font-size-md);margin-bottom:0.5rem">Architecture</h4>' +
      '<div class="tech-diagram">' + escHtml(data.architecture.diagram) + '</div>';
  }

  // Vendor landscape
  if (data.vendorLandscape && data.vendorLandscape.length) {
    html += '<h4 style="font-size:var(--font-size-md);margin-bottom:0.75rem">Vendor Landscape</h4>' +
      '<div style="overflow-x:auto"><table class="data-table"><thead><tr><th>Vendor</th><th>Strengths</th></tr></thead><tbody>' +
      data.vendorLandscape.map(function(v) {
        return '<tr><td style="font-weight:600;white-space:nowrap">' + escHtml(v.vendor) + '</td>' +
          '<td style="font-size:var(--font-size-sm)">' + escHtml(v.strengths) + '</td></tr>';
      }).join('') +
      '</tbody></table></div>';
  }

  // Malaysian context
  if (data.malaysianContext) {
    html += '<h4 style="font-size:var(--font-size-md);margin:1.5rem 0 0.5rem">Malaysian Context</h4>' +
      '<div class="impl-objective"><strong style="display:block;margin-bottom:0.25rem;font-size:var(--font-size-xs);text-transform:uppercase;letter-spacing:0.05em;color:var(--accent)">BNM RMiT</strong>' +
      escHtml(data.malaysianContext.bnmRmit || data.malaysianContext.bnmRmit) + '</div>';
    if (data.malaysianContext.considerations && data.malaysianContext.considerations.length) {
      html += '<ul class="activity-list">' +
        data.malaysianContext.considerations.map(function(c) { return '<li>' + escHtml(c) + '</li>'; }).join('') +
        '</ul>';
    }
  }

  return html;
}

// ---- View: Reference ----
function renderReference(sub) {
  var refFiles = [
    { id: 'nist-csf', name: 'NIST CSF 2.0', file: 'dp-to-nist-csf.json' },
    { id: 'iso27001', name: 'ISO 27001:2022', file: 'dp-to-iso27001.json' },
    { id: 'pci-dss', name: 'PCI DSS v4.0', file: 'dp-to-pci-dss.json' },
    { id: 'rmit', name: 'BNM RMiT', file: 'dp-to-rmit.json' },
    { id: 'pdpa', name: 'PDPA (Malaysia)', file: 'dp-to-pdpa.json' }
  ];

  var subTabs = ['cross-refs', 'templates', 'sectors', 'incidents'];
  var currentSub = sub && subTabs.indexOf(sub) >= 0 ? sub : 'cross-refs';

  return '<h2 style="font-size:var(--font-size-xl);font-weight:700;margin-bottom:0.5rem">Reference</h2>' +
    '<p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:1rem">Cross-references, templates, sector requirements, and breach case studies.</p>' +
    '<div class="sub-tabs">' +
    '<button class="sub-tab' + (currentSub === 'cross-refs' ? ' active' : '') + '" data-sub="cross-refs">Cross-References</button>' +
    '<button class="sub-tab' + (currentSub === 'templates' ? ' active' : '') + '" data-sub="templates">Templates</button>' +
    '<button class="sub-tab' + (currentSub === 'sectors' ? ' active' : '') + '" data-sub="sectors">Sectors</button>' +
    '<button class="sub-tab' + (currentSub === 'incidents' ? ' active' : '') + '" data-sub="incidents">Breach Incidents</button>' +
    '</div>' +

    // Cross-References
    '<div class="sub-panel' + (currentSub === 'cross-refs' ? ' active' : '') + '" data-subpanel="cross-refs">' +
    refFiles.map(function(rf) {
      var data = state.crossRefs[rf.id];
      if (!data || !data.mappings) return '';
      return '<h4 style="margin:1rem 0 0.5rem">' + escHtml(rf.name) + '</h4>' +
        '<div style="overflow-x:auto"><table class="data-table"><thead><tr><th>DP Domain/Control</th><th>Mapped Controls</th></tr></thead><tbody>' +
        data.mappings.map(function(m) {
          var source = m.dpControl || m.dpDomain || '';
          var targets = m.csfSubcategories || m.iso27001Controls || m.pciRequirements || m.rmitSections || m.pdpaPrinciples || [];
          var desc = m.description || m.technicalLink || m.similarity || '';
          return '<tr><td class="mono" style="font-weight:600;white-space:nowrap">' + escHtml(source) + '</td>' +
            '<td><span class="fw-codes">' + escHtml(targets.join(', ')) + '</span>' +
            (desc ? '<div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:0.25rem">' + escHtml(desc) + '</div>' : '') +
            '</td></tr>';
        }).join('') +
        '</tbody></table></div>';
    }).join('') +
    '</div>' +

    // Templates
    '<div class="sub-panel' + (currentSub === 'templates' ? ' active' : '') + '" data-subpanel="templates">' +
    (state.templates ? state.templates.templates.map(function(tpl) {
      return '<div class="artifact-card">' +
        '<div class="artifact-card-header"><span class="artifact-card-name">' + escHtml(tpl.name) + '</span>' +
        '<span class="badge badge-category">' + escHtml(tpl.type) + '</span></div>' +
        '<p class="artifact-card-desc">' + escHtml(tpl.description) + '</p>' +
        '<div class="artifact-card-contents"><strong>Sections:</strong><ul>' +
        tpl.sections.map(function(s) { return '<li>' + escHtml(s) + '</li>'; }).join('') +
        '</ul></div>' +
        '<div class="artifact-card-meta"><span class="meta-item"><strong>Domains:</strong> ' + tpl.applicableDomains.join(', ') + '</span></div>' +
        '</div>';
    }).join('') : '<p>Loading templates...</p>') +
    '</div>' +

    // Sectors
    '<div class="sub-panel' + (currentSub === 'sectors' ? ' active' : '') + '" data-subpanel="sectors">' +
    renderSectors() +
    '</div>' +

    // Incidents
    '<div class="sub-panel' + (currentSub === 'incidents' ? ' active' : '') + '" data-subpanel="incidents">' +
    renderIncidents() +
    '</div>';
}

function renderSectors() {
  if (!state.sectors) return '<p>Loading sector data...</p>';

  var sectorFiles = ['financial-services', 'healthcare', 'government'];
  return sectorFiles.map(function(sf) {
    var data = state.sectors[sf];
    if (!data) return '';
    return '<div class="treatment-card">' +
      '<h4>' + escHtml(data.sector) + '</h4>' +
      (data.regulatoryLandscape ? '<div style="margin-bottom:1rem"><strong style="font-size:var(--font-size-xs);text-transform:uppercase;color:var(--text-muted)">Regulatory Landscape</strong>' +
        '<div style="overflow-x:auto"><table class="data-table"><thead><tr><th>Regulation</th><th>Jurisdiction</th><th>Relevant Sections</th></tr></thead><tbody>' +
        data.regulatoryLandscape.map(function(r) {
          return '<tr><td style="font-weight:600">' + escHtml(r.regulation) + '</td><td>' + escHtml(r.jurisdiction) + '</td>' +
            '<td style="font-size:var(--font-size-sm)">' + escHtml((r.relevantSections || []).join(', ')) + '</td></tr>';
        }).join('') +
        '</tbody></table></div></div>' : '') +
      (data.keyDataTypes ? '<div><strong style="font-size:var(--font-size-xs);text-transform:uppercase;color:var(--text-muted)">Key Data Types</strong>' +
        '<div style="overflow-x:auto"><table class="data-table"><thead><tr><th>Data Type</th><th>Classification</th><th>Protection</th></tr></thead><tbody>' +
        data.keyDataTypes.map(function(dt) {
          return '<tr><td style="font-weight:600">' + escHtml(dt.type) + '</td><td><span class="badge badge-category">' + escHtml(dt.classification) + '</span></td>' +
            '<td style="font-size:var(--font-size-sm)">' + escHtml(dt.protection) + '</td></tr>';
        }).join('') +
        '</tbody></table></div></div>' : '') +
      '</div>';
  }).join('');
}

function renderIncidents() {
  if (!state.incidents || !state.incidents.incidents) return '<p>Loading incident data...</p>';

  return state.incidents.incidents.map(function(inc) {
    return '<div class="treatment-card">' +
      '<h4>' + escHtml(inc.name) + ' (' + inc.year + ')</h4>' +
      '<div class="artifact-card-meta" style="margin-bottom:0.75rem">' +
      '<span class="meta-item"><strong>Organization:</strong> ' + escHtml(inc.organization) + '</span>' +
      '<span class="meta-item"><strong>Sector:</strong> ' + escHtml(inc.sector) + '</span>' +
      '<span class="meta-item"><strong>Records:</strong> ' + escHtml(inc.recordsAffected) + '</span>' +
      '</div>' +
      '<p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:0.5rem"><strong>Data Exposed:</strong> ' + escHtml(inc.dataExposed) + '</p>' +
      '<p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:0.5rem"><strong>Root Cause:</strong> ' + escHtml(inc.rootCause) + '</p>' +
      '<p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:0.5rem"><strong>Financial Impact:</strong> ' + escHtml(inc.financialImpact) + '</p>' +
      '<div class="evidence-detail-grid">' +
      '<div class="evidence-block evidence-gap"><div class="evidence-block-label">Failed Controls</div><ul>' +
      inc.failedControls.map(function(f) { return '<li>' + escHtml(f) + '</li>'; }).join('') +
      '</ul></div>' +
      '<div class="evidence-block evidence-good"><div class="evidence-block-label">Lessons Learned</div><ul>' +
      inc.lessonsLearned.map(function(l) { return '<li>' + escHtml(l) + '</li>'; }).join('') +
      '</ul></div>' +
      '</div>' +
      '<div style="margin-top:0.5rem"><strong style="font-size:var(--font-size-xs);color:var(--text-muted)">Relevant Controls:</strong> ' +
      inc.relevantControls.map(function(c) { return '<a href="#control/' + c.toLowerCase() + '" style="margin-right:0.5rem;font-family:var(--font-mono);font-size:var(--font-size-xs)">' + escHtml(c) + '</a>'; }).join('') +
      '</div></div>';
  }).join('');
}

// ---- View: Search ----
function renderSearch(query) {
  if (!query) return '<div class="empty-state"><p class="empty-state-text">Enter a search term to find controls, technologies, and evidence.</p></div>';

  var q = query.toLowerCase();
  var results = [];

  if (state.controls) {
    state.controls.forEach(function(ctrl) {
      if (ctrl.slug.toLowerCase().indexOf(q) >= 0 ||
          ctrl.name.toLowerCase().indexOf(q) >= 0 ||
          ctrl.description.toLowerCase().indexOf(q) >= 0 ||
          ctrl.domain.toLowerCase().indexOf(q) >= 0) {
        results.push(ctrl);
      }
    });
  }

  if (results.length === 0) {
    return '<div class="empty-state"><p class="empty-state-text">No controls match "' + escHtml(query) + '".</p></div>';
  }

  var grouped = {};
  results.forEach(function(r) {
    if (!grouped[r.domain]) grouped[r.domain] = [];
    grouped[r.domain].push(r);
  });

  return '<div class="search-results-header">' + results.length + ' result' + (results.length !== 1 ? 's' : '') + ' for "' + escHtml(query) + '"</div>' +
    Object.keys(grouped).map(function(domId) {
      var dom = getDomain(domId);
      var items = grouped[domId];
      return '<div class="search-group">' +
        '<div class="search-group-title">' +
        '<span class="dom-pill dom-pill-' + domId + '">' + domId + '</span>' +
        '<span style="font-weight:600">' + escHtml(dom ? dom.name : domId) + '</span>' +
        '</div>' +
        '<ul class="sub-list">' +
        items.map(function(ctrl) {
          return '<li><a class="sub-link" href="#control/' + ctrl.slug + '">' +
            '<span class="sub-id">' + ctrl.slug.toUpperCase() + '</span>' +
            '<span class="sub-desc">' + escHtml(ctrl.name) + ' — ' + escHtml(ctrl.description.substring(0, 120)) + (ctrl.description.length > 120 ? '...' : '') + '</span>' +
            '</a></li>';
        }).join('') +
        '</ul></div>';
    }).join('');
}

// ---- Main Render ----
async function render() {
  var app = document.getElementById('app');
  var route = state.route;

  // Load core data
  if (!state.controls) {
    app.innerHTML = renderLoading();
    try {
      var results = await Promise.all([
        fetchJSON('controls/library.json'),
        fetchJSON('controls/domain-index.json'),
        fetchJSON('evidence/index.json'),
        fetchJSON('artifacts/inventory.json'),
        fetchJSON('frameworks/index.json')
      ]);
      if (!results[0] || !results[1]) {
        app.innerHTML = renderError('Failed to load core data', 'Could not fetch controls data. Please refresh.');
        return;
      }
      state.controls = results[0].controls;
      state.domains = results[1].domains;
      state.evidence = results[2];
      state.artifacts = results[3];
      state.frameworks = results[4];
    } catch (err) {
      app.innerHTML = renderError('Failed to load core data', err.message);
      return;
    }
  }

  // Load risk management data
  if (route.view === 'risk' && !state.riskMgmt) {
    app.innerHTML = renderLoading();
    var rmData = await fetchJSON('risk-management/index.json');
    if (!rmData) {
      app.innerHTML = renderError('Failed to load risk management data');
      return;
    }
    state.riskMgmt = rmData;
  }

  // Load framework detail data
  if (route.view === 'framework' && state.frameworks) {
    var fwLoads = state.frameworks.frameworks.map(function(fw) {
      return fetchJSON('frameworks/' + fw.dataFile);
    });
    await Promise.all(fwLoads);
  }

  // Load technology data
  if (route.view === 'technologies') {
    var techFiles = ['dlp', 'encryption', 'key-management', 'tokenization', 'backup-recovery', 'classification'];
    var techLoads = techFiles.map(function(tf) {
      if (state.technologies[tf]) return Promise.resolve(state.technologies[tf]);
      return fetchJSON('technologies/' + tf + '.json').then(function(d) {
        if (d) state.technologies[tf] = d;
        return d;
      });
    });
    await Promise.all(techLoads);
  }

  // Load reference data
  if (route.view === 'reference') {
    var refLoads = [];
    var refMap = {
      'nist-csf': 'dp-to-nist-csf.json',
      'iso27001': 'dp-to-iso27001.json',
      'pci-dss': 'dp-to-pci-dss.json',
      'rmit': 'dp-to-rmit.json',
      'pdpa': 'dp-to-pdpa.json'
    };
    Object.keys(refMap).forEach(function(key) {
      if (!state.crossRefs[key]) {
        refLoads.push(fetchJSON('cross-references/' + refMap[key]).then(function(d) {
          if (d) state.crossRefs[key] = d;
        }));
      }
    });
    if (!state.templates) {
      refLoads.push(fetchJSON('templates/index.json').then(function(d) { if (d) state.templates = d; }));
    }
    if (!state.incidents) {
      refLoads.push(fetchJSON('threats/known-incidents.json').then(function(d) { if (d) state.incidents = d; }));
    }
    if (!state.sectors) {
      state.sectors = {};
      var sectorFiles = ['financial-services', 'healthcare', 'government'];
      sectorFiles.forEach(function(sf) {
        refLoads.push(fetchJSON('sectors/' + sf + '.json').then(function(d) { if (d) state.sectors[sf] = d; }));
      });
    }
    if (refLoads.length) await Promise.all(refLoads);
  }

  // Load control detail data
  if (route.view === 'control') {
    var detailLoads = [];
    if (!state.evidence) detailLoads.push(fetchJSON('evidence/index.json').then(function(d) { if (d) state.evidence = d; }));
    if (!state.artifacts) detailLoads.push(fetchJSON('artifacts/inventory.json').then(function(d) { if (d) state.artifacts = d; }));
    if (detailLoads.length) await Promise.all(detailLoads);
  }

  var content = '';
  switch (route.view) {
    case 'overview':
      content = renderOverview();
      break;
    case 'framework':
      content = renderFramework(route.sub);
      break;
    case 'controls':
      content = renderControls();
      break;
    case 'control':
      content = renderControlDetail(route.slug);
      break;
    case 'risk':
      content = renderRiskManagement(route.sub);
      break;
    case 'technologies':
      content = renderTechnologies(route.sub);
      break;
    case 'reference':
      content = renderReference(route.sub);
      break;
    case 'search':
      content = renderSearch(route.query);
      break;
    default:
      content = renderOverview();
  }

  app.innerHTML = '<div class="main">' + content + '</div>';
  updateNav();

  var searchInput = document.getElementById('search-input');
  if (searchInput && route.view === 'search') {
    searchInput.value = route.query || '';
  }
}

// ---- Event Delegation ----
function setupEvents() {
  window.addEventListener('hashchange', function() {
    state.route = parseHash();
    render();
  });

  document.addEventListener('click', function(e) {
    var accTrigger = e.target.closest('.accordion-trigger');
    if (accTrigger) {
      if (accTrigger.hasAttribute('data-accordion')) {
        var item = accTrigger.closest('.accordion-item');
        if (item) item.classList.toggle('open');
      }
      if (accTrigger.hasAttribute('aria-expanded')) {
        var expanded = accTrigger.getAttribute('aria-expanded') === 'true';
        accTrigger.setAttribute('aria-expanded', !expanded);
        var contentEl = accTrigger.nextElementSibling;
        if (contentEl) contentEl.hidden = expanded;
      }
      return;
    }

    var subTab = e.target.closest('.sub-tab');
    if (subTab) {
      var subName = subTab.dataset.sub;
      subTab.parentElement.querySelectorAll('.sub-tab').forEach(function(t) { t.classList.toggle('active', t === subTab); });
      var container = subTab.closest('.main') || document.getElementById('app');
      container.querySelectorAll('.sub-panel').forEach(function(p) {
        p.classList.toggle('active', p.dataset.subpanel === subName);
      });
      return;
    }
  });

  var searchTimeout;
  document.addEventListener('input', function(e) {
    if (e.target.id === 'search-input') {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(function() {
        var val = e.target.value.trim();
        if (val) {
          navigate('search/' + encodeURIComponent(val));
        } else {
          navigate('overview');
        }
      }, 300);
    }
  });

  document.addEventListener('keydown', function(e) {
    if (e.target.id === 'search-input' && e.key === 'Enter') {
      e.preventDefault();
      clearTimeout(searchTimeout);
      var val = e.target.value.trim();
      if (val) {
        navigate('search/' + encodeURIComponent(val));
      }
    }
  });
}

// ---- Init ----
function init() {
  var pdfBtn = document.getElementById('btn-pdf');
  var csvBtn = document.getElementById('btn-csv');
  if (pdfBtn) pdfBtn.addEventListener('click', exportToPDF);
  if (csvBtn) csvBtn.addEventListener('click', exportToCSV);

  state.route = parseHash();
  setupEvents();
  render();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

// === Export Functions ===

function exportToPDF() {
  document.body.classList.add('printing');
  window.print();
  document.body.classList.remove('printing');
}

function exportToCSV() {
  var view = state.route.view;
  var data = [];
  var filename = 'dataprotection-' + view + '-' + new Date().toISOString().slice(0, 10) + '.csv';

  if (view === 'risk' && state.riskMgmt) {
    var risks = state.riskMgmt.register.risks;
    data = risks.map(function(r) {
      return {
        ID: r.id,
        Title: r.title,
        Domain: r.domain,
        Inherent_Risk: r.inherentRisk,
        Inherent_Level: r.inherentRiskLevel,
        Residual_Risk: r.residualRisk,
        Residual_Level: r.residualRiskLevel,
        Treatment: r.treatment,
        Owner: r.owner
      };
    });
  } else if (view === 'controls' && state.controls) {
    data = state.controls.map(function(c) {
      return {
        Slug: c.slug,
        Name: c.name,
        Domain: c.domain,
        Description: c.description.replace(/\n/g, ' ')
      };
    });
  } else {
    alert('CSV export is supported for Controls and Risk Management views.');
    return;
  }

  if (data.length === 0) {
    alert('No data found to export.');
    return;
  }

  var headers = Object.keys(data[0]);
  var csvContent = [
    headers.join(','),
    data.map(function(row) {
      return headers.map(function(h) {
        return '"' + (row[h] || '').toString().replace(/"/g, '""') + '"';
      }).join(',');
    }).join('\n')
  ].join('\n');

  var blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  var link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

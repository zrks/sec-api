import '@fontsource/inter/400.css'
import '@fontsource/inter/600.css'
import '@fontsource/inter/700.css'
import './styles.css'
import { ApiError, api } from './api.js'

const root = document.getElementById('root')
const severityOrder = ['critical', 'high', 'medium', 'low', 'info']
const state = {
  flash: null,
  connectionLabel: 'Checking API...',
  connectionTone: 'warning',
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function formatDateTime(value) {
  if (!value) {
    return 'Not available'
  }
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    return value
  }
  return parsed.toLocaleString()
}

function titleCaseSeverity(value) {
  return value.charAt(0).toUpperCase() + value.slice(1)
}

function scoreTone(score) {
  if (score >= 85) {
    return 'good'
  }
  if (score >= 60) {
    return 'warning'
  }
  return 'danger'
}

function statusPill(label, tone) {
  return `<span class="status-pill status-pill-${tone}">${escapeHtml(label)}</span>`
}

function severityBadge(severity) {
  return `<span class="severity-badge severity-${escapeHtml(severity)}">${escapeHtml(titleCaseSeverity(severity))}</span>`
}

function buttonLink(href, label, secondary = false) {
  return `<a class="button${secondary ? ' button-secondary' : ''}" data-link href="${href}">${escapeHtml(label)}</a>`
}

function card(title, body, eyebrow = '') {
  return `
    <section class="card">
      ${eyebrow ? `<p class="eyebrow">${escapeHtml(eyebrow)}</p>` : ''}
      ${title ? `<h2>${escapeHtml(title)}</h2>` : ''}
      ${body}
    </section>
  `
}

function renderFlash() {
  if (!state.flash) {
    return ''
  }

  const flash = state.flash
  state.flash = null
  const className = flash.type === 'error' ? 'error-banner' : 'success-banner'
  return `<section class="card ${className}">${escapeHtml(flash.message)}</section>`
}

function setFlash(type, message) {
  state.flash = { type, message }
}

function renderLayout(content) {
  root.innerHTML = `
    <div class="app-shell">
      <header class="site-header">
        <div>
          <a class="brand-link" data-link href="/">Domain Risk Dashboard</a>
          <p class="site-tagline">External domain checks for DNS, TLS, email protections, and website security basics.</p>
        </div>
        <div class="header-meta">
          <span id="connection-status" class="status-pill status-pill-${state.connectionTone}">${escapeHtml(state.connectionLabel)}</span>
          <nav class="site-nav">
            <a class="nav-link${location.pathname === '/domains' ? ' nav-link-active' : ''}" data-link href="/domains">Domains</a>
            <a class="nav-link${location.pathname === '/domains/new' ? ' nav-link-active' : ''}" data-link href="/domains/new">Add Domain</a>
            <a class="nav-link${location.pathname === '/settings' ? ' nav-link-active' : ''}" data-link href="/settings">Settings</a>
          </nav>
        </div>
      </header>
      <main class="page-shell">${content}</main>
    </div>
  `
}

function renderLoading(label) {
  return `<section class="card loading-state"><p>${escapeHtml(label)}</p></section>`
}

function renderError(title, message, retryPath = null) {
  return `
    <section class="card error-state stack-sm">
      <h2>${escapeHtml(title)}</h2>
      <p>${escapeHtml(message)}</p>
      ${retryPath ? buttonLink(retryPath, 'Try again', true) : ''}
    </section>
  `
}

function renderEmpty(title, message, actionHref = '', actionLabel = '') {
  return `
    <section class="card empty-state stack-sm">
      <h2>${escapeHtml(title)}</h2>
      <p>${escapeHtml(message)}</p>
      ${actionHref && actionLabel ? buttonLink(actionHref, actionLabel) : ''}
    </section>
  `
}

function renderRiskScoreCard(score, generatedAt) {
  return `
    <section class="card risk-card risk-card-${scoreTone(score)}">
      <p class="eyebrow">Domain Risk Dashboard</p>
      <h2 class="risk-score-value">${escapeHtml(score)} / 100</h2>
      <p class="muted">A higher score means fewer visible issues were detected in the latest scan.</p>
      ${generatedAt ? `<p class="meta-text">Latest report: ${escapeHtml(formatDateTime(generatedAt))}</p>` : ''}
    </section>
  `
}

function flattenFindings(grouped) {
  return severityOrder.flatMap((severity) => grouped[severity] ?? [])
}

function renderFixFirstList(grouped, explicitItems = null) {
  const items = explicitItems ?? flattenFindings(grouped).slice(0, 5)
  return `
    <section class="card">
      <p class="eyebrow">Fix This First</p>
      ${items.length === 0 ? '<p class="muted">No urgent fixes were generated from the latest report.</p>' : `
        <ol class="fix-list">
          ${items.map((finding) => `<li><strong>${escapeHtml(finding.title)}</strong><span>${escapeHtml(finding.recommendation)}</span></li>`).join('')}
        </ol>
      `}
    </section>
  `
}

function renderFindingCard(finding) {
  return `
    <article class="card finding-card">
      <div class="card-row card-row-start">
        ${severityBadge(finding.severity)}
        <h3>${escapeHtml(finding.title)}</h3>
      </div>
      <p>${escapeHtml(finding.description)}</p>
      <p class="recommendation"><strong>Recommended next step:</strong> ${escapeHtml(finding.recommendation)}</p>
    </article>
  `
}

function renderObservationList(title, observations) {
  return `
    <section class="card">
      <h2>${escapeHtml(title)}</h2>
      ${observations.length === 0 ? '<p class="muted">No observations were captured in this section.</p>' : `
        <div class="observation-list">
          ${observations.map((observation, index) => `
            <article class="observation-item" data-index="${index}">
              <div class="card-row">
                <strong>${escapeHtml(observation.key)}</strong>
                <span class="muted">${escapeHtml(observation.subject)}</span>
              </div>
              <pre>${escapeHtml(JSON.stringify(observation.value, null, 2))}</pre>
            </article>
          `).join('')}
        </div>
      `}
    </section>
  `
}

function renderChangeList(changes) {
  return `
    <section class="card">
      <p class="eyebrow">Domain Change Monitoring</p>
      <h2>What changed since the previous scan</h2>
      ${changes.length === 0 ? '<p class="muted">No new changes were detected since the previous scan.</p>' : `
        <div class="observation-list">
          ${changes.map((change) => `
            <article class="observation-item">
              <div class="card-row card-row-spread">
                <strong>${escapeHtml(change.subject)}</strong>
                <span class="status-pill status-pill-neutral">${escapeHtml(change.change_type)}</span>
              </div>
              <p class="muted">${escapeHtml(change.category)} / ${escapeHtml(change.key)}</p>
              <pre>${escapeHtml(JSON.stringify({ old_value: change.old_value, new_value: change.new_value }, null, 2))}</pre>
            </article>
          `).join('')}
        </div>
      `}
    </section>
  `
}

function renderReportHistoryList(domainId, reports) {
  if (!reports.length) {
    return '<p class="muted">No past reports yet.</p>'
  }

  return `
    <div class="observation-list">
      ${reports.map((report) => `
        <article class="observation-item">
          <div class="card-row card-row-spread">
            <strong>Score ${escapeHtml(report.score)} / 100</strong>
            <span class="muted">${escapeHtml(formatDateTime(report.created_at))}</span>
          </div>
          <div class="card-row">
            ${buttonLink(`/domains/${domainId}/reports/${report.id}`, 'Open Report', true)}
          </div>
        </article>
      `).join('')}
    </div>
  `
}

function matchRoute(pathname) {
  if (pathname === '/') {
    return { name: 'landing' }
  }
  if (pathname === '/domains') {
    return { name: 'domains' }
  }
  if (pathname === '/domains/new') {
    return { name: 'add-domain' }
  }
  if (pathname === '/settings') {
    return { name: 'settings' }
  }

  const reportMatch = pathname.match(/^\/domains\/([^/]+)\/report$/)
  if (reportMatch) {
    return { name: 'report', id: reportMatch[1] }
  }

  const reportHistoryMatch = pathname.match(/^\/domains\/([^/]+)\/reports\/([^/]+)$/)
  if (reportHistoryMatch) {
    return { name: 'report-detail', id: reportHistoryMatch[1], reportId: reportHistoryMatch[2] }
  }

  const detailMatch = pathname.match(/^\/domains\/([^/]+)$/)
  if (detailMatch) {
    return { name: 'domain-detail', id: detailMatch[1] }
  }

  return { name: 'not-found' }
}

function navigate(path) {
  window.history.pushState({}, '', path)
  void renderRoute()
}

async function updateConnectionStatus() {
  try {
    const [health, version] = await Promise.all([api.getHealth(), api.getVersion()])
    state.connectionLabel = `API connected (${health}, ${version.version})`
    state.connectionTone = 'good'
  } catch {
    state.connectionLabel = 'API unavailable'
    state.connectionTone = 'warning'
  }

  const element = document.getElementById('connection-status')
  if (element) {
    element.className = `status-pill status-pill-${state.connectionTone}`
    element.textContent = state.connectionLabel
  }
}

function bindNavigation() {
  document.querySelectorAll('[data-link]').forEach((link) => {
    link.addEventListener('click', (event) => {
      event.preventDefault()
      navigate(link.getAttribute('href'))
    })
  })
}

function renderLandingPage() {
  return `
    <div class="stack-lg">
      <section class="hero card hero-card">
        <div>
          <p class="eyebrow">Weekly external domain-risk monitoring</p>
          <h1>Keep track of the domain issues your team should fix first.</h1>
          <p class="hero-copy">DomainRiskDigest checks passive subdomain exposure, DNS posture, TLS health, registration changes, email-domain protections, and website security basics. It helps your team understand what changed since the last scan and where to start.</p>
          <div class="card-row">
            ${buttonLink('/domains/new', 'Add your first domain')}
            ${buttonLink('/domains', 'Open dashboard', true)}
          </div>
        </div>
      </section>
      <section class="feature-grid">
        ${card('TLS expiry and hostname checks', '<p>Spot expiring certificates, expired certificates, and hostname mismatches before they become customer-facing incidents.</p>', 'Certificate Failure Prevention')}
        ${card('SPF and DMARC visibility', '<p>See whether your email-domain protections are present and whether obvious weak SPF patterns may be relevant.</p>', 'Email Spoofing Protection Check')}
        ${card('Header coverage summary', '<p>Review HSTS, CSP, X-Frame-Options, and X-Content-Type-Options in business-friendly language.</p>', 'Website Security Basics')}
        ${card('Simple trend-ready reporting', '<p>Track report history, passive subdomain discovery, and visible domain registration changes alongside the latest score.</p>', 'Domain Change Monitoring')}
      </section>
    </div>
  `
}

async function renderDomainsPage() {
  const domains = await api.listDomains()

  if (domains.length === 0) {
    return `${renderFlash()}${renderEmpty('No domains yet', 'Add your first public domain to generate an immediate external-risk profile.', '/domains/new', 'Add Domain')}`
  }

  return `
    <div class="stack-lg">
      <section class="card card-row card-row-spread">
        <div>
          <p class="eyebrow">Domain Risk Dashboard</p>
          <h1>Monitored domains</h1>
        </div>
        ${buttonLink('/domains/new', 'Add Domain')}
      </section>
      ${renderFlash()}
      <div class="domain-grid">
        ${domains.map((domain) => `
          <article class="card domain-card">
            <div class="card-row card-row-spread">
              <div>
                <h2>${escapeHtml(domain.domain)}</h2>
                <p class="meta-text">Added ${escapeHtml(formatDateTime(domain.created_at))}</p>
              </div>
              ${statusPill(domain.status ?? 'active', domain.status === 'active' ? 'good' : 'warning')}
            </div>
            <div class="domain-metadata-grid">
              <div>
                <span class="kv-label">Latest risk score</span>
                <strong>${typeof domain.latest_score === 'number' ? `${escapeHtml(domain.latest_score)} / 100` : 'No report yet'}</strong>
              </div>
              <div>
                <span class="kv-label">Last scan status</span>
                <strong>${escapeHtml(domain.latest_scan_status ?? 'No scan yet')}</strong>
              </div>
              <div>
                <span class="kv-label">Latest report</span>
                <strong>${escapeHtml(formatDateTime(domain.latest_report_generated_at))}</strong>
              </div>
            </div>
            ${domain.last_error ? `<p class="muted">Last scan note: ${escapeHtml(domain.last_error)}</p>` : ''}
            <div class="card-row">
              ${buttonLink(`/domains/${domain.id}`, 'View', true)}
              <button data-action="scan" data-id="${domain.id}" data-domain="${escapeHtml(domain.domain)}" ${domain.status === 'active' ? '' : 'disabled'}>Scan</button>
            </div>
          </article>
        `).join('')}
      </div>
    </div>
  `
}

function bindDomainsPage() {
  document.querySelectorAll('[data-action="scan"]').forEach((button) => {
    button.addEventListener('click', async () => {
      button.disabled = true
      try {
        const result = await api.scanNow(button.dataset.id)
        setFlash('success', `Scan completed for ${button.dataset.domain}. Score: ${result.report.score} / 100.`)
      } catch (error) {
        setFlash('error', error instanceof Error ? error.message : 'Scan failed')
      }
      await renderRoute()
    })
  })
}

function renderAddDomainPage() {
  return `
    <div class="page-narrow">
      <section class="card">
        <p class="eyebrow">Add Domain</p>
        <h1>Start monitoring a domain</h1>
        <p class="muted">Use a public domain or website URL such as <code>example.com</code> or <code>https://www.example.com/path</code>. The app will normalize it and run a public-domain profile immediately.</p>
        ${renderFlash()}
        <form id="add-domain-form" class="stack">
          <label class="stack-sm">
            <span>Domain name</span>
            <input id="domain-input" placeholder="example.com" autocomplete="off">
          </label>
          <button type="submit">Create Domain</button>
        </form>
      </section>
    </div>
  `
}

function bindAddDomainPage() {
  const form = document.getElementById('add-domain-form')
  const input = document.getElementById('domain-input')
  form.addEventListener('submit', async (event) => {
    event.preventDefault()
    const domain = input.value.trim()
    if (!domain) {
      setFlash('error', 'Domain name is required.')
      await renderRoute()
      return
    }

    const button = form.querySelector('button')
    button.disabled = true
    button.textContent = 'Creating...'

    try {
      const created = await api.createDomain(domain)
      setFlash('success', 'Add domain succeeded. Initial public-domain profile generated.')
      navigate(`/domains/${created.domain.id}`)
    } catch (error) {
      setFlash('error', error instanceof Error ? error.message : 'Failed to add domain')
      await renderRoute()
    }
  })
}

function renderOwnershipNote(domain) {
  return `
    <section class="card instruction-card">
      <p class="eyebrow">Future sensitive features</p>
      <h2>Ownership verification is optional for now</h2>
      <p>Ownership verification will be required later for sensitive features such as breach monitoring and active scanning.</p>
      ${domain.verification_token ? `<details><summary>Ownership verification details</summary><div class="kv-grid"><div><span class="kv-label">Host</span><code>${escapeHtml(domain.verification_record_name)}</code></div><div><span class="kv-label">Value</span><code>${escapeHtml(domain.verification_record_value)}</code></div></div></details>` : ''}
    </section>
  `
}

async function renderDomainDetailPage(id) {
  const domain = await api.getDomain(id)
  let latestReport = null
  let reports = []

  try {
    latestReport = await api.getLatestReport(id)
  } catch (error) {
    if (!(error instanceof ApiError) || error.status !== 404) {
      throw error
    }
  }

  try {
    reports = await api.listReports(id)
  } catch (error) {
    if (!(error instanceof ApiError) || error.status !== 404) {
      throw error
    }
  }

  return `
    <div class="stack-lg">
      <section class="card card-row card-row-spread">
        <div>
          <p class="eyebrow">Domain detail</p>
          <h1>${escapeHtml(domain.domain)}</h1>
        </div>
        ${statusPill(domain.status ?? 'active', domain.status === 'active' ? 'good' : 'warning')}
      </section>
      ${renderFlash()}
      ${renderOwnershipNote(domain)}
      <section class="card card-row card-row-spread">
        <div>
          <p class="eyebrow">Actions</p>
          <h2>Public-domain monitoring</h2>
          <p class="muted">Public external-risk checks can run immediately for active monitored domains.</p>
        </div>
        <div class="card-row">
          <button data-action="detail-scan" data-id="${domain.id}" ${domain.status === 'active' ? '' : 'disabled'}>Scan Now</button>
        </div>
      </section>
      ${latestReport ? `
        <section class="detail-grid">
          ${renderRiskScoreCard(latestReport.score, latestReport.generated_at)}
          <section class="card">
            <p class="eyebrow">Latest report</p>
            <h2>Ready to review</h2>
            <p class="muted">Open the full report for grouped findings, raw observations, and fix-first recommendations.</p>
            ${buttonLink(`/domains/${domain.id}/report`, 'Open Latest Report')}
          </section>
        </section>
      ` : `
        <section class="card">
          <p class="eyebrow">Latest report</p>
          <h2>No report available yet</h2>
          <p class="muted">Run a manual scan to generate the first report.</p>
        </section>
      `}
      <section class="card">
        <p class="eyebrow">Report history</p>
        <h2>Stored reports</h2>
        ${renderReportHistoryList(domain.id, reports)}
      </section>
    </div>
  `
}

function bindDomainDetailPage(id) {
  const scanButton = document.querySelector('[data-action="detail-scan"]')
  if (scanButton) {
    scanButton.addEventListener('click', async () => {
      scanButton.disabled = true
      try {
        const result = await api.scanNow(id)
        setFlash('success', `Scan completed. Latest score: ${result.report.score} / 100.`)
      } catch (error) {
        setFlash('error', error instanceof Error ? error.message : 'Scan failed')
      }
      await renderRoute()
    })
  }
}

async function renderReportPage(id) {
  const domain = await api.getDomain(id)
  let report

  try {
    report = await api.getLatestReport(id)
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return renderEmpty('No report available yet', 'Run a scan to generate the first report.', `/domains/${id}`, 'Back to Domain')
    }
    throw error
  }

  const groups = {
    dns: report.observations.filter((item) => item.category === 'dns'),
    tls: report.observations.filter((item) => item.category === 'tls'),
    http: report.observations.filter((item) => item.category === 'http'),
  }

  return `
    <div class="stack-lg">
      <section class="card card-row card-row-spread">
        <div>
          <p class="eyebrow">Latest report</p>
          <h1>${escapeHtml(domain.domain)}</h1>
          <p class="muted">Generated ${escapeHtml(formatDateTime(report.generated_at))}</p>
        </div>
        ${buttonLink(`/domains/${domain.id}`, 'Back to Domain', true)}
      </section>
      <section class="report-top-grid">
        ${renderRiskScoreCard(report.score, report.generated_at)}
        ${renderFixFirstList(report.findings, report.fix_first?.length ? report.fix_first : null)}
      </section>
      <section class="detail-grid">
        ${renderObservationList('Domain Registration Health', report.sections?.whois ?? [])}
        ${renderObservationList('Email Spoofing Protection Check', report.sections?.dns ?? groups.dns)}
      </section>
      ${renderChangeList(report.changes ?? [])}
      <section class="card">
        <p class="eyebrow">Findings by severity</p>
        <div class="stack-lg">
          ${severityOrder.map((severity) => {
            const findings = report.findings[severity] ?? []
            return `
              <div class="stack">
                <div class="card-row card-row-start">
                  <h2>${escapeHtml(titleCaseSeverity(severity))}</h2>
                  <span class="muted">${findings.length}</span>
                </div>
                ${findings.length === 0 ? '<p class="muted">None in this group.</p>' : findings.map(renderFindingCard).join('')}
              </div>
            `
          }).join('')}
        </div>
      </section>
      <div class="detail-grid">
        ${renderObservationList('Certificate Failure Prevention', report.sections?.tls ?? groups.tls)}
        ${renderObservationList('Website Security Basics', report.sections?.http ?? groups.http)}
      </div>
      <div class="detail-grid">
        ${renderObservationList('Passive subdomain discovery', report.sections?.subdomains ?? [])}
        ${card('Public Exposure Monitoring', '<p class="muted">Passive public service intelligence will appear here when optional provider APIs are configured.</p>', 'Placeholder')}
      </div>
      <div class="detail-grid">
        ${card('Forgotten Subdomain Detection', '<p class="muted">Use the passive subdomain list above to review hostnames that may need retirement or redirect cleanup.</p>', 'Placeholder')}
        ${card('Exploited Vulnerability Watch', '<p class="muted">Technology-based vulnerability watch will appear here when optional provider APIs are configured.</p>', 'Placeholder')}
      </div>
      <section class="card">
        <p class="eyebrow">Observation summary</p>
        <p class="muted">${escapeHtml(report.observation_summary.total)} observations captured across ${escapeHtml(Object.keys(report.observation_summary.by_category).length)} categories.</p>
      </section>
      <section class="card">
        <details>
          <summary>Raw observations</summary>
          <pre>${escapeHtml(JSON.stringify(report.observations, null, 2))}</pre>
        </details>
      </section>
    </div>
  `
}

async function renderStoredReportPage(domainId, reportId) {
  const domain = await api.getDomain(domainId)
  const report = await api.getReport(reportId)

  return `
    <div class="stack-lg">
      <section class="card card-row card-row-spread">
        <div>
          <p class="eyebrow">Stored report</p>
          <h1>${escapeHtml(domain.domain)}</h1>
          <p class="muted">Generated ${escapeHtml(formatDateTime(report.generated_at))}</p>
        </div>
        <div class="card-row">
          ${buttonLink(`/domains/${domain.id}`, 'Back to Domain', true)}
          ${buttonLink(`/domains/${domain.id}/report`, 'Open Latest Report')}
        </div>
      </section>
      ${renderRiskScoreCard(report.score, report.generated_at)}
      ${renderChangeList(report.changes ?? [])}
      ${renderObservationList('Exposed subdomains', report.sections?.subdomains ?? [])}
    </div>
  `
}

function renderSettingsPage() {
  return `
    <div class="stack-lg">
      <section class="card">
        <p class="eyebrow">Settings</p>
        <h1>Local configuration</h1>
        <p class="muted">This phase keeps the product local and simple. Authentication, billing, and external paid integrations are intentionally out of scope.</p>
        <div class="kv-grid">
          <div>
            <span class="kv-label">API base URL</span>
            <code>${escapeHtml(api.baseUrl)}</code>
          </div>
        </div>
      </section>
      <section class="feature-grid">
        ${card('Passive subdomain discovery', '<p>Certificate transparency discovery is active in this build and shows public hostnames that may need review.</p>', 'Available now')}
        ${card('Domain registration change checks', '<p>RDAP-based registration metadata is active in this build when the registry returns compatible fields.</p>', 'Available now')}
        ${card('Client-ready reports', '<p>Placeholder for white-label PDF reports and branded exports for managed service providers.</p>', 'Future MSP feature')}
        ${card('Weekly email digest', '<p>Placeholder for summary delivery after the main dashboard and latest report flow are working well.</p>', 'Future paid feature')}
      </section>
    </div>
  `
}

async function renderRoute() {
  renderLayout(renderLoading('Loading page...'))
  bindNavigation()
  void updateConnectionStatus()

  const route = matchRoute(location.pathname)

  try {
    let content = ''

    if (route.name === 'landing') {
      content = renderLandingPage()
    } else if (route.name === 'domains') {
      content = await renderDomainsPage()
    } else if (route.name === 'add-domain') {
      content = renderAddDomainPage()
    } else if (route.name === 'domain-detail') {
      content = await renderDomainDetailPage(route.id)
    } else if (route.name === 'report') {
      content = await renderReportPage(route.id)
    } else if (route.name === 'report-detail') {
      content = await renderStoredReportPage(route.id, route.reportId)
    } else if (route.name === 'settings') {
      content = renderSettingsPage()
    } else {
      content = renderEmpty('Page not found', 'The page you requested does not exist.', '/', 'Back to home')
    }

    renderLayout(content)
    bindNavigation()
    void updateConnectionStatus()

    if (route.name === 'domains') {
      bindDomainsPage()
    }
    if (route.name === 'add-domain') {
      bindAddDomainPage()
    }
    if (route.name === 'domain-detail') {
      bindDomainDetailPage(route.id)
    }
  } catch (error) {
    renderLayout(renderError('Something went wrong', error instanceof Error ? error.message : 'Unexpected error', location.pathname))
    bindNavigation()
    void updateConnectionStatus()
  }
}

window.addEventListener('popstate', () => {
  void renderRoute()
})

void renderRoute()

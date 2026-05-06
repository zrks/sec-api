import { test, expect } from '@playwright/test'

const domainId = '11111111-1111-1111-1111-111111111111'
const reportId = '22222222-2222-2222-2222-222222222222'

const domain = {
  id: domainId,
  domain: 'example.com',
  normalized_domain: 'example.com',
  status: 'active',
  ownership_verified: false,
  verification_token: 'token-123',
  verification_record_name: '_domainriskdigest.example.com',
  verification_record_value: 'drd-verify-token-123',
  created_at: '2026-05-01T10:00:00Z',
  updated_at: '2026-05-02T10:00:00Z',
  latest_score: 72,
  latest_report_generated_at: '2026-05-02T11:00:00Z',
  latest_scan_status: 'finished',
}

const latestReport = {
  score: 72,
  generated_at: '2026-05-02T11:00:00Z',
  observation_summary: {
    total: 7,
    by_category: {
      dns: 2,
      tls: 2,
      http: 3,
    },
  },
  observations: [
    { category: 'dns', subject: 'example.com', key: 'SPF', value: { records: ['v=spf1 -all'] } },
    { category: 'dns', subject: '_dmarc.example.com', key: 'DMARC', value: { records: ['v=DMARC1; p=reject'] } },
    { category: 'tls', subject: 'example.com', key: 'expiry', value: { days_remaining: 21, not_after: '2026-05-23T11:00:00Z' } },
    { category: 'tls', subject: 'example.com', key: 'hostname', value: { valid: true } },
    { category: 'http', subject: 'https://example.com', key: 'hsts', value: { present: true } },
    { category: 'http', subject: 'https://example.com', key: 'csp', value: { present: false } },
    { category: 'http', subject: 'https://example.com', key: 'x_frame_options', value: { present: true } },
  ],
  sections: {
    whois: [
      { category: 'rdap', subject: 'example.com', key: 'registrar', value: { name: 'Example Registrar' } },
    ],
    dns: [
      { category: 'dns', subject: 'example.com', key: 'SPF', value: { records: ['v=spf1 -all'] } },
      { category: 'dns', subject: '_dmarc.example.com', key: 'DMARC', value: { records: ['v=DMARC1; p=reject'] } },
    ],
    tls: [
      { category: 'tls', subject: 'example.com', key: 'expiry', value: { days_remaining: 21, not_after: '2026-05-23T11:00:00Z' } },
    ],
    http: [
      { category: 'http', subject: 'https://example.com', key: 'csp', value: { present: false } },
      { category: 'http', subject: 'https://example.com', key: 'hsts', value: { present: true } },
    ],
    subdomains: [
      { category: 'subdomains', subject: 'assets.example.com', key: 'discovered', value: { source: 'crt.sh' } },
    ],
  },
  findings: {
    critical: [],
    high: [
      {
        severity: 'high',
        title: 'CSP missing',
        description: 'A Content-Security-Policy header was not detected.',
        recommendation: 'Add a baseline CSP for the main website responses.',
      },
    ],
    medium: [
      {
        severity: 'medium',
        title: 'Review passive subdomains',
        description: 'A passive hostname was discovered from certificate transparency.',
        recommendation: 'Review the subdomain inventory and retire anything unused.',
      },
    ],
    low: [],
    info: [],
  },
  fix_first: [
    {
      severity: 'high',
      title: 'CSP missing',
      recommendation: 'Add a baseline CSP for the main website responses.',
    },
    {
      severity: 'medium',
      title: 'Review passive subdomains',
      recommendation: 'Review the subdomain inventory and retire anything unused.',
    },
  ],
  changes: [
    {
      change_type: 'added',
      category: 'subdomains',
      subject: 'assets.example.com',
      key: 'discovered',
      old_value: null,
      new_value: { source: 'crt.sh' },
    },
  ],
}

const storedReport = {
  ...latestReport,
  id: reportId,
  generated_at: '2026-04-25T11:00:00Z',
}

const reportHistory = [
  {
    id: reportId,
    scan_run_id: '33333333-3333-3333-3333-333333333333',
    score: 72,
    created_at: '2026-04-25T11:00:00Z',
  },
]

test.beforeEach(async ({ page }) => {
  await page.route('http://localhost:8080/**', async (route) => {
    const url = new URL(route.request().url())
    const method = route.request().method()

    if (url.pathname === '/healthz') {
      await route.fulfill({ status: 200, contentType: 'text/plain', body: 'ok' })
      return
    }
    if (url.pathname === '/api/v1/version') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ version: 'mvp' }) })
      return
    }
    if (url.pathname === '/api/v1/domains' && method === 'GET') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([domain]) })
      return
    }
    if (url.pathname === `/api/v1/domains/${domainId}` && method === 'GET') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(domain) })
      return
    }
    if (url.pathname === `/api/v1/domains/${domainId}/latest-report` && method === 'GET') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(latestReport) })
      return
    }
    if (url.pathname === `/api/v1/domains/${domainId}/reports` && method === 'GET') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(reportHistory) })
      return
    }
    if (url.pathname === `/api/v1/reports/${reportId}` && method === 'GET') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(storedReport) })
      return
    }
    if (url.pathname === `/api/v1/domains/${domainId}/scan-now` && method === 'POST') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          scan_id: '44444444-4444-4444-4444-444444444444',
          report: latestReport,
          findings: latestReport.findings,
        }),
      })
      return
    }

    await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: `No mock for ${method} ${url.pathname}` }) })
  })
})

test('landing page visual baseline', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByText('API connected (ok, mvp)')).toBeVisible()
  await expect(page).toHaveScreenshot('landing-page.png', { fullPage: true })
})

test('domains dashboard visual baseline', async ({ page }) => {
  await page.goto('/domains')
  await expect(page.getByRole('heading', { name: 'Monitored domains' })).toBeVisible()
  await expect(page).toHaveScreenshot('domains-dashboard.png', { fullPage: true })
})

test('latest report visual baseline', async ({ page }) => {
  await page.goto(`/domains/${domainId}/report`)
  await expect(page.getByRole('heading', { name: 'example.com' })).toBeVisible()
  await expect(page.getByText('Fix This First')).toBeVisible()
  await expect(page).toHaveScreenshot('latest-report.png', { fullPage: true })
})

test('settings page visual baseline', async ({ page }) => {
  await page.goto('/settings')
  await expect(page.getByRole('heading', { name: 'Local configuration' })).toBeVisible()
  await expect(page).toHaveScreenshot('settings-page.png', { fullPage: true })
})

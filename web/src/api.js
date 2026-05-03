const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080'

export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request(path, init = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers ?? {}),
    },
  })

  const raw = await response.text()
  let parsed = raw

  if (raw) {
    try {
      parsed = JSON.parse(raw)
    } catch {
      parsed = raw
    }
  }

  if (!response.ok) {
    const message = parsed && typeof parsed === 'object' && typeof parsed.error === 'string'
      ? parsed.error
      : typeof parsed === 'string'
        ? parsed
        : `Request failed with status ${response.status}`
    throw new ApiError(message, response.status)
  }

  return parsed
}

export const api = {
  baseUrl: API_BASE_URL,
  getHealth: async () => {
    const response = await fetch(`${API_BASE_URL}/healthz`)
    if (!response.ok) {
      throw new ApiError(`Health check failed with status ${response.status}`, response.status)
    }
    return response.text()
  },
  getVersion: () => request('/api/v1/version', { method: 'GET' }),
  listDomains: () => request('/api/v1/domains', { method: 'GET' }),
  getDomain: (id) => request(`/api/v1/domains/${id}`, { method: 'GET' }),
  createDomain: (domain) => request('/api/v1/domains', { method: 'POST', body: JSON.stringify({ domain }) }),
  verifyOwnership: (id) => request(`/api/v1/domains/${id}/verify-ownership`, { method: 'POST' }),
  scanNow: (id) => request(`/api/v1/domains/${id}/scan-now`, { method: 'POST' }),
  getLatestReport: (id) => request(`/api/v1/domains/${id}/latest-report`, { method: 'GET' }),
  listReports: (id) => request(`/api/v1/domains/${id}/reports`, { method: 'GET' }),
  getReport: (id) => request(`/api/v1/reports/${id}`, { method: 'GET' }),
}

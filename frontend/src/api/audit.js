import client from './client'

export const getAuditLogs = (params = {}) =>
  client.get('/audit', { params })

export const exportAuditLogs = () =>
  client.get('/audit/export', { responseType: 'blob' })

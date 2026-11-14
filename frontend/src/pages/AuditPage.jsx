import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getAuditLogs, exportAuditLogs } from '../api/audit.js'
import { ShieldCheck, Download, Filter, RefreshCw, Calendar, User, Activity } from 'lucide-react'
import toast from 'react-hot-toast'

export default function AuditPage() {
  const [page, setPage] = useState(1)
  const [actionFilter, setActionFilter] = useState('')
  const [resourceFilter, setResourceFilter] = useState('')

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['audit-logs', page, actionFilter, resourceFilter],
    queryFn: () => getAuditLogs({ page, action: actionFilter, resource_type: resourceFilter }),
    keepPreviousData: true,
  })

  const handleExport = async () => {
    try {
      toast.loading('Generating immutable audit log export...', { id: 'export' })
      const blob = await exportAuditLogs()
      const url = window.URL.createObjectURL(new Blob([blob]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `audit_log_${new Date().toISOString().slice(0, 10)}.csv`)
      document.body.appendChild(link)
      link.click()
      link.parentNode.removeChild(link)
      toast.success('Audit log CSV exported successfully', { id: 'export' })
    } catch (err) {
      toast.error('Failed to export audit log', { id: 'export' })
    }
  }

  const logs = data?.logs || []
  const totalPages = data?.total_pages || 1

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <ShieldCheck className="h-7 w-7 text-blue-600" />
            Security Audit Trail
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Immutable system activity and cryptographic signature event logs (Integrity control).
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition"
          >
            <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleExport}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 shadow-sm transition"
          >
            <Download className="h-4 w-4" />
            Export CSV
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm flex flex-wrap gap-4 items-center">
        <div className="flex items-center gap-2 text-sm font-medium text-gray-700">
          <Filter className="h-4 w-4 text-gray-400" />
          Filters:
        </div>
        <select
          value={actionFilter}
          onChange={(e) => {
            setActionFilter(e.target.value)
            setPage(1)
          }}
          className="text-sm border border-gray-300 rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="">All Actions</option>
          <option value="DOCUMENT_UPLOAD">Document Upload</option>
          <option value="DOCUMENT_SIGN">Digital Signature</option>
          <option value="DOCUMENT_VERIFY">Integrity Verification</option>
          <option value="DOCUMENT_DOWNLOAD">Document Download</option>
          <option value="USER_LOGIN">User Login</option>
          <option value="USER_REGISTER">User Registration</option>
          <option value="MFA_ENABLED">MFA Enabled</option>
        </select>

        <select
          value={resourceFilter}
          onChange={(e) => {
            setResourceFilter(e.target.value)
            setPage(1)
          }}
          className="text-sm border border-gray-300 rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="">All Resource Types</option>
          <option value="document">Documents</option>
          <option value="signature">Signatures</option>
          <option value="auth">Auth & Sessions</option>
          <option value="user">User Accounts</option>
        </select>
      </div>

      {/* Audit Log Table */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        {isLoading ? (
          <div className="py-16 text-center text-gray-500">
            <RefreshCw className="h-6 w-6 animate-spin mx-auto text-blue-600 mb-2" />
            Loading audit records...
          </div>
        ) : logs.length === 0 ? (
          <div className="py-16 text-center text-gray-500">
            <Activity className="h-8 w-8 mx-auto text-gray-400 mb-2" />
            No audit records match the current criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 text-left text-sm">
              <thead className="bg-gray-50 text-gray-600 uppercase text-xs font-semibold">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">User</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Resource</th>
                  <th className="py-3 px-4">IP Address</th>
                  <th className="py-3 px-4">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 font-mono text-xs">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-gray-50">
                    <td className="py-3 px-4 text-gray-600 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-gray-900 font-sans font-medium whitespace-nowrap">
                      {log.user_email || 'System / Unauth'}
                    </td>
                    <td className="py-3 px-4">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                        {log.action}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-gray-500">
                      {log.resource_type ? `${log.resource_type}:${log.resource_id}` : '-'}
                    </td>
                    <td className="py-3 px-4 text-gray-500">{log.ip_address || '127.0.0.1'}</td>
                    <td className="py-3 px-4 text-gray-600 truncate max-w-xs font-sans text-xs">
                      {typeof log.details === 'object' ? JSON.stringify(log.details) : log.details || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="px-4 py-3 border-t border-gray-200 flex items-center justify-between">
            <button
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="px-3 py-1.5 text-sm rounded border border-gray-300 disabled:opacity-50"
            >
              Previous
            </button>
            <span className="text-sm text-gray-600">
              Page {page} of {totalPages}
            </span>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              className="px-3 py-1.5 text-sm rounded border border-gray-300 disabled:opacity-50"
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  )
}


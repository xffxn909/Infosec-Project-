import { useQuery } from '@tanstack/react-query'
import { FileText, CheckCircle, Clock, Activity } from 'lucide-react'
import { getStats } from '../api/admin'
import { getAuditLogs } from '../api/audit'
import { useAuth } from '../context/AuthContext.jsx'
import { formatDistanceToNow } from 'date-fns'

function StatCard({ icon: Icon, label, value, color }) {
  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 flex items-center gap-4">
      <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${color}`}>
        <Icon size={22} className="text-white" />
      </div>
      <div>
        <p className="text-sm text-gray-500">{label}</p>
        <p className="text-2xl font-bold text-gray-800">{value ?? '—'}</p>
      </div>
    </div>
  )
}

export default function DashboardPage() {
  const { role } = useAuth()

  const { data: statsData } = useQuery({
    queryKey: ['stats'],
    queryFn: () => getStats().then((r) => r.data),
    enabled: role === 'admin' || role === 'manager',
  })

  const { data: auditData } = useQuery({
    queryKey: ['recentAudit'],
    queryFn: () => getAuditLogs({ per_page: 5 }).then((r) => r.data),
  })

  const stats = statsData || {}
  const recentLogs = auditData?.logs || auditData?.items || []

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-800">Dashboard</h2>
        <p className="text-sm text-gray-500 mt-1">Overview of your document management activity</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={FileText}
          label="Total Documents"
          value={stats.total_documents}
          color="bg-blue-500"
        />
        <StatCard
          icon={CheckCircle}
          label="Signed Documents"
          value={stats.signed_documents}
          color="bg-green-500"
        />
        <StatCard
          icon={Clock}
          label="Pending / Draft"
          value={stats.draft_documents}
          color="bg-yellow-500"
        />
        <StatCard
          icon={Activity}
          label="Total Users"
          value={stats.total_users}
          color="bg-purple-500"
        />
      </div>

      {/* Recent Audit Activity */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
        <h3 className="text-base font-semibold text-gray-700 mb-4 flex items-center gap-2">
          <Activity size={18} className="text-blue-500" />
          Recent Activity
        </h3>
        {recentLogs.length === 0 ? (
          <p className="text-sm text-gray-400">No recent activity.</p>
        ) : (
          <div className="space-y-3">
            {recentLogs.map((log, i) => (
              <div key={log.id || i} className="flex items-start gap-3 pb-3 border-b border-gray-50 last:border-0">
                <div className="w-2 h-2 mt-2 rounded-full bg-blue-400 flex-shrink-0" />
                <div className="flex-1">
                  <p className="text-sm text-gray-700">
                    <span className="font-medium">{log.user?.full_name || log.user_email || 'System'}</span>
                    {' — '}
                    <span className="text-gray-500">{log.action}</span>
                    {log.resource_type && (
                      <span className="text-gray-400"> on {log.resource_type}</span>
                    )}
                  </p>
                  <p className="text-xs text-gray-400">
                    {log.timestamp
                      ? formatDistanceToNow(new Date(log.timestamp), { addSuffix: true })
                      : ''}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

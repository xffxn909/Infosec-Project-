import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getUsers, createUser, updateUser, deleteUser } from '../api/admin.js'
import { Users, UserPlus, Shield, CheckCircle, XCircle, Key, RefreshCw } from 'lucide-react'
import toast from 'react-hot-toast'

export default function AdminPage() {
  const queryClient = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [formData, setFormData] = useState({
    email: '',
    full_name: '',
    password: '',
    role: 'staff',
  })

  const { data: users = [], isLoading, isFetching } = useQuery({
    queryKey: ['admin-users'],
    queryFn: getUsers,
  })

  const createMutation = useMutation({
    mutationFn: createUser,
    onSuccess: () => {
      queryClient.invalidateQueries(['admin-users'])
      toast.success('User account and RSA cryptographic keys created!')
      setShowModal(false)
      setFormData({ email: '', full_name: '', password: '', role: 'staff' })
    },
    onError: (err) => {
      toast.error(err.response?.data?.message || 'Failed to create user')
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }) => updateUser(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries(['admin-users'])
      toast.success('User updated successfully')
    },
    onError: (err) => {
      toast.error(err.response?.data?.message || 'Failed to update user')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: deleteUser,
    onSuccess: () => {
      queryClient.invalidateQueries(['admin-users'])
      toast.success('User deactivated')
    },
    onError: (err) => {
      toast.error(err.response?.data?.message || 'Failed to deactivate user')
    },
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!formData.email || !formData.password || !formData.full_name) {
      toast.error('All fields are required')
      return
    }
    createMutation.mutate(formData)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <Users className="h-7 w-7 text-blue-600" />
            User & Role Management
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Enforce Role-Based Access Control (RBAC: Admin, Manager, Staff) and PKI credentials.
          </p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="inline-flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 shadow-sm transition"
        >
          <UserPlus className="h-4 w-4" />
          Add New User
        </button>
      </div>

      {/* Users Table */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        {isLoading ? (
          <div className="py-16 text-center text-gray-500">
            <RefreshCw className="h-6 w-6 animate-spin mx-auto text-blue-600 mb-2" />
            Loading accounts...
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 text-left text-sm">
              <thead className="bg-gray-50 text-gray-600 uppercase text-xs font-semibold">
                <tr>
                  <th className="py-3 px-4">Name</th>
                  <th className="py-3 px-4">Email</th>
                  <th className="py-3 px-4">Role (RBAC)</th>
                  <th className="py-3 px-4">MFA Status</th>
                  <th className="py-3 px-4">Digital Cert</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-gray-50">
                    <td className="py-3 px-4 font-medium text-gray-900">{u.full_name}</td>
                    <td className="py-3 px-4 text-gray-600">{u.email}</td>
                    <td className="py-3 px-4">
                      <select
                        value={u.role}
                        onChange={(e) => updateMutation.mutate({ id: u.id, data: { role: e.target.value } })}
                        className="text-xs font-medium px-2.5 py-1 rounded-full border border-gray-300 bg-white"
                      >
                        <option value="admin">Admin</option>
                        <option value="manager">Manager</option>
                        <option value="staff">Staff</option>
                      </select>
                    </td>
                    <td className="py-3 px-4">
                      {u.mfa_enabled ? (
                        <span className="inline-flex items-center gap-1 text-xs text-green-700 font-medium bg-green-50 px-2 py-0.5 rounded">
                          <CheckCircle className="h-3.5 w-3.5 text-green-500" /> TOTP Enabled
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-amber-700 font-medium bg-amber-50 px-2 py-0.5 rounded">
                          <XCircle className="h-3.5 w-3.5 text-amber-500" /> Pending
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className="inline-flex items-center gap-1 text-xs text-gray-600">
                        <Key className="h-3.5 w-3.5 text-blue-500" /> RSA-2048
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                          u.is_active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                        }`}
                      >
                        {u.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      {u.is_active ? (
                        <button
                          onClick={() => deleteMutation.mutate(u.id)}
                          className="text-xs text-red-600 hover:text-red-800 font-medium"
                        >
                          Deactivate
                        </button>
                      ) : (
                        <button
                          onClick={() => updateMutation.mutate({ id: u.id, data: { is_active: true } })}
                          className="text-xs text-green-600 hover:text-green-800 font-medium"
                        >
                          Activate
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create User Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-md w-full p-6 shadow-xl space-y-4">
            <h2 className="text-xl font-bold text-gray-900 flex items-center gap-2">
              <UserPlus className="h-5 w-5 text-blue-600" />
              Create New Staff / Manager
            </h2>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  value={formData.full_name}
                  onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
                  placeholder="e.g. Jane Doe"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">Email Address</label>
                <input
                  type="email"
                  required
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
                  placeholder="name@organization.org"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">Password (Argon2id)</label>
                <input
                  type="password"
                  required
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
                  placeholder="Strong password"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">Role (RBAC)</label>
                <select
                  value={formData.role}
                  onChange={(e) => setFormData({ ...formData, role: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
                >
                  <option value="staff">Staff (Upload & Sign own documents)</option>
                  <option value="manager">Manager (Review all documents & Audit)</option>
                  <option value="admin">Administrator (Full System Control)</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 text-sm text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isLoading}
                  className="px-4 py-2 text-sm text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                  {createMutation.isLoading ? 'Creating...' : 'Create Account'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}


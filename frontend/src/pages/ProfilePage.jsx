import { useAuth } from '../context/AuthContext.jsx'
import { Link } from 'react-router-dom'
import { User, Shield, Key, Lock, CheckCircle, AlertTriangle } from 'lucide-react'

export default function ProfilePage() {
  const { user } = useAuth()

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-sm">
        <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
          <User className="h-7 w-7 text-blue-600" />
          User Profile & Security Settings
        </h1>
        <p className="text-sm text-gray-500 mt-1">
          Review your role permissions, cryptographic signature credentials, and two-factor authentication.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
          <div className="border border-gray-100 rounded-lg p-4 bg-gray-50 space-y-3">
            <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wider">Account Details</h2>
            <div>
              <span className="text-xs text-gray-500">Full Name</span>
              <p className="text-sm font-medium text-gray-900">{user?.full_name || 'Staff User'}</p>
            </div>
            <div>
              <span className="text-xs text-gray-500">Email Address</span>
              <p className="text-sm font-medium text-gray-900">{user?.email}</p>
            </div>
            <div>
              <span className="text-xs text-gray-500">Role-Based Access (RBAC)</span>
              <p className="text-sm font-semibold text-blue-700 uppercase mt-0.5">{user?.role || 'staff'}</p>
            </div>
          </div>

          <div className="border border-gray-100 rounded-lg p-4 bg-gray-50 space-y-3">
            <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wider">Cryptographic Credentials</h2>
            <div>
              <span className="text-xs text-gray-500">Document Signing Key</span>
              <p className="text-sm font-medium text-gray-900 flex items-center gap-1.5 mt-0.5">
                <Key className="h-4 w-4 text-emerald-600" />
                RSA-2048 Bit Private/Public Keypair
              </p>
            </div>
            <div>
              <span className="text-xs text-gray-500">Password Storage Standard</span>
              <p className="text-sm font-medium text-gray-900 flex items-center gap-1.5 mt-0.5">
                <Lock className="h-4 w-4 text-emerald-600" />
                Argon2id (Salted & Memory-Hard)
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Multi-Factor Authentication Card */}
      <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="space-y-1">
          <h2 className="text-lg font-bold text-gray-900 flex items-center gap-2">
            <Shield className="h-5 w-5 text-blue-600" />
            Multi-Factor Authentication (TOTP / Google Authenticator)
          </h2>
          <p className="text-sm text-gray-500">
            Confidentiality requirement: Protects document access using time-based one-time passwords.
          </p>
          <div className="pt-2">
            {user?.mfa_enabled ? (
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800">
                <CheckCircle className="h-4 w-4" /> MFA is currently Active and Enforced
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-100 text-amber-800">
                <AlertTriangle className="h-4 w-4" /> MFA is not yet enabled on your account
              </span>
            )}
          </div>
        </div>

        <div>
          <Link
            to="/mfa-setup"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 shadow-sm transition"
          >
            {user?.mfa_enabled ? 'Reconfigure MFA' : 'Setup Two-Factor Auth'}
          </Link>
        </div>
      </div>
    </div>
  )
}


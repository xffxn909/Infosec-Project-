import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { setupMFA, verifyMFA } from '../api/auth.js'
import { useNavigate } from 'react-router-dom'
import { Shield, KeyRound, CheckCircle, ArrowLeft, RefreshCw } from 'lucide-react'
import toast from 'react-hot-toast'

export default function MFASetupPage() {
  const navigate = useNavigate()
  const [code, setCode] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['mfa-setup-data'],
    queryFn: setupMFA,
  })

  const verifyMutation = useMutation({
    mutationFn: (token) => verifyMFA(token),
    onSuccess: () => {
      toast.success('MFA successfully enabled! Your account is now protected.')
      navigate('/profile')
    },
    onError: (err) => {
      toast.error(err.response?.data?.message || 'Invalid 6-digit TOTP code')
    },
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!code || code.length !== 6) {
      toast.error('Please enter a valid 6-digit verification code')
      return
    }
    verifyMutation.mutate(code)
  }

  return (
    <div className="max-w-md mx-auto space-y-6">
      <button
        onClick={() => navigate('/profile')}
        className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-700"
      >
        <ArrowLeft className="h-4 w-4" /> Back to Profile
      </button>

      <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-sm space-y-6">
        <div>
          <h1 className="text-xl font-bold text-gray-900 flex items-center gap-2">
            <Shield className="h-6 w-6 text-blue-600" />
            Setup Two-Factor Authentication
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            Scan this QR code using Google Authenticator, Authy, or any TOTP mobile app.
          </p>
        </div>

        {isLoading ? (
          <div className="py-12 text-center text-gray-500">
            <RefreshCw className="h-6 w-6 animate-spin mx-auto text-blue-600 mb-2" />
            Generating cryptographic MFA secret...
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex justify-center p-4 bg-gray-50 rounded-xl border border-gray-100">
              {data?.qr_code_image ? (
                <img
                  src={`data:image/png;base64,${data.qr_code_image}`}
                  alt="MFA QR Code"
                  className="w-48 h-48 rounded shadow-sm"
                />
              ) : (
                <div className="w-48 h-48 flex items-center justify-center bg-gray-200 rounded text-xs text-gray-500">
                  QR Code Unavailable
                </div>
              )}
            </div>

            <div className="text-center">
              <span className="text-xs text-gray-400">Manual entry secret key:</span>
              <p className="font-mono text-sm font-bold text-gray-800 tracking-wider">
                {data?.secret || '----------------'}
              </p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-3 pt-2">
              <label className="block text-xs font-semibold text-gray-700">
                Enter 6-digit Code from Authenticator App:
              </label>
              <div className="relative">
                <KeyRound className="absolute left-3 top-2.5 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="123456"
                  className="w-full pl-9 pr-3 py-2 text-center font-mono text-lg tracking-widest border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none"
                />
              </div>

              <button
                type="submit"
                disabled={verifyMutation.isLoading || code.length !== 6}
                className="w-full py-2.5 text-sm font-semibold text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50 transition"
              >
                {verifyMutation.isLoading ? 'Verifying...' : 'Verify & Enable MFA'}
              </button>
            </form>
          </div>
        )}
      </div>
    </div>
  )
}

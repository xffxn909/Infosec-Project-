import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { Lock, Eye, EyeOff, ShieldCheck } from 'lucide-react'
import toast from 'react-hot-toast'
import { login as apiLogin, verifyMFA } from '../api/auth'
import { useAuth } from '../context/AuthContext.jsx'

export default function LoginPage() {
  const navigate = useNavigate()
  const { login } = useAuth()
  const [showPassword, setShowPassword] = useState(false)
  const [mfaRequired, setMfaRequired] = useState(false)
  const [mfaCode, setMfaCode] = useState('')
  const [tempToken, setTempToken] = useState(null)
  const [loading, setLoading] = useState(false)

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm()

  const onSubmit = async ({ email, password }) => {
    setLoading(true)
    try {
      const res = await apiLogin(email, password)
      const data = res.data

      if (data.mfa_required) {
        // Backend signals MFA step needed
        setTempToken(data.temp_token || null)
        setMfaRequired(true)
        toast('Enter your authenticator code', { icon: '🔐' })
      } else {
        login(data.access_token, data.user)
        toast.success(`Welcome back, ${data.user?.full_name || 'User'}!`)
        navigate('/dashboard')
      }
    } catch (err) {
      const msg = err.response?.data?.message || err.response?.data?.error || 'Login failed'
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }

  const handleMFASubmit = async (e) => {
    e.preventDefault()
    if (!mfaCode.trim()) return
    setLoading(true)
    try {
      const res = await verifyMFA(mfaCode)
      const data = res.data
      login(data.access_token, data.user)
      toast.success('Authenticated successfully!')
      navigate('/dashboard')
    } catch (err) {
      const msg = err.response?.data?.message || 'Invalid MFA code'
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="w-full max-w-md">
        {/* Card */}
        <div className="bg-white rounded-2xl shadow-xl overflow-hidden">
          {/* Header */}
          <div className="px-8 py-8" style={{ backgroundColor: '#1e2a3a' }}>
            <div className="flex items-center gap-3 mb-2">
              <Lock className="text-blue-400" size={28} />
              <span className="text-white font-bold text-2xl">SecureDoc</span>
            </div>
            <p className="text-gray-400 text-sm">
              Document Management &amp; E-Signature System
            </p>
          </div>

          <div className="px-8 py-8">
            {!mfaRequired ? (
              <>
                <h2 className="text-xl font-semibold text-gray-800 mb-6">Sign in to your account</h2>
                <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Email address
                    </label>
                    <input
                      type="email"
                      {...register('email', { required: 'Email is required' })}
                      className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                      placeholder="you@example.com"
                    />
                    {errors.email && (
                      <p className="text-red-500 text-xs mt-1">{errors.email.message}</p>
                    )}
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                    <div className="relative">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        {...register('password', { required: 'Password is required' })}
                        className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm pr-10"
                        placeholder="••••••••"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                      >
                        {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                    {errors.password && (
                      <p className="text-red-500 text-xs mt-1">{errors.password.message}</p>
                    )}
                  </div>

                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full py-2.5 px-4 bg-blue-500 hover:bg-blue-600 disabled:bg-blue-300 text-white font-medium rounded-lg transition-colors text-sm"
                  >
                    {loading ? 'Signing in…' : 'Sign in'}
                  </button>
                </form>
              </>
            ) : (
              <>
                <div className="flex items-center gap-2 mb-6">
                  <ShieldCheck className="text-blue-500" size={22} />
                  <h2 className="text-xl font-semibold text-gray-800">Two-Factor Authentication</h2>
                </div>
                <p className="text-sm text-gray-600 mb-5">
                  Enter the 6-digit code from your authenticator app.
                </p>
                <form onSubmit={handleMFASubmit} className="space-y-5">
                  <input
                    type="text"
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center tracking-widest text-lg"
                    placeholder="000000"
                    maxLength={6}
                    autoFocus
                  />
                  <button
                    type="submit"
                    disabled={loading || mfaCode.length !== 6}
                    className="w-full py-2.5 px-4 bg-blue-500 hover:bg-blue-600 disabled:bg-blue-300 text-white font-medium rounded-lg transition-colors text-sm"
                  >
                    {loading ? 'Verifying…' : 'Verify'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setMfaRequired(false)}
                    className="w-full text-gray-500 hover:text-gray-700 text-sm text-center"
                  >
                    ← Back to login
                  </button>
                </form>
              </>
            )}
          </div>
        </div>

        <p className="text-center text-gray-500 text-xs mt-4">
          InfoSec Project — Secure Document System
        </p>
      </div>
    </div>
  )
}

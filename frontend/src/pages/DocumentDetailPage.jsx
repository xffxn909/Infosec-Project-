import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Download,
  PenLine,
  ShieldCheck,
  Trash2,
  ArrowLeft,
  CheckCircle,
  XCircle,
  Loader2,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { format } from 'date-fns'
import {
  getDocument,
  downloadDocument,
  signDocument,
  verifyDocument,
  deleteDocument,
} from '../api/documents'
import { useAuth } from '../context/AuthContext.jsx'

const statusColors = {
  draft: 'bg-yellow-100 text-yellow-700',
  signed: 'bg-green-100 text-green-700',
  verified: 'bg-blue-100 text-blue-700',
}

export default function DocumentDetailPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { user, role } = useAuth()
  const queryClient = useQueryClient()
  const [verifyResult, setVerifyResult] = useState(null)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['document', id],
    queryFn: () => getDocument(id).then((r) => r.data),
  })

  const doc = data?.document || data

  const signMutation = useMutation({
    mutationFn: () => signDocument(id),
    onSuccess: () => {
      toast.success('Document signed successfully!')
      queryClient.invalidateQueries({ queryKey: ['document', id] })
      queryClient.invalidateQueries({ queryKey: ['documents'] })
    },
    onError: (err) => {
      toast.error(err.response?.data?.message || 'Failed to sign document')
    },
  })

  const verifyMutation = useMutation({
    mutationFn: () => verifyDocument(id),
    onSuccess: (res) => {
      const result = res.data
      setVerifyResult(result)
      if (result.valid || result.integrity_ok) {
        toast.success('Document integrity verified!')
      } else {
        toast.error('Integrity check failed — document may be tampered!')
      }
    },
    onError: (err) => {
      toast.error(err.response?.data?.message || 'Verification failed')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: () => deleteDocument(id),
    onSuccess: () => {
      toast.success('Document deleted')
      navigate('/documents')
    },
    onError: (err) => {
      toast.error(err.response?.data?.message || 'Failed to delete')
    },
  })

  const handleDownload = async () => {
    try {
      const res = await downloadDocument(id)
      const url = URL.createObjectURL(new Blob([res.data]))
      const a = document.createElement('a')
      a.href = url
      a.download = doc?.original_filename || 'document'
      a.click()
      URL.revokeObjectURL(url)
      toast.success('Download started')
    } catch {
      toast.error('Download failed')
    }
  }

  const userHasSigned = doc?.signatures?.some((s) => s.signer_id === user?.id)
  const canDelete = role === 'admin' || role === 'manager'

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-500" />
      </div>
    )
  }

  if (isError || !doc) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-red-600 text-sm">
        Failed to load document.
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Back button */}
      <button
        onClick={() => navigate('/documents')}
        className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-800"
      >
        <ArrowLeft size={16} /> Back to Documents
      </button>

      {/* Header card */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <h2 className="text-xl font-bold text-gray-800">{doc.title}</h2>
              <span
                className={`px-2.5 py-0.5 rounded-full text-xs font-medium capitalize ${
                  statusColors[doc.status] || 'bg-gray-100 text-gray-600'
                }`}
              >
                {doc.status}
              </span>
            </div>
            {doc.description && (
              <p className="text-sm text-gray-500 mb-4">{doc.description}</p>
            )}
            <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-2 text-sm">
              <div>
                <dt className="text-gray-400">Original File</dt>
                <dd className="text-gray-700 font-medium">{doc.original_filename}</dd>
              </div>
              <div>
                <dt className="text-gray-400">Uploaded By</dt>
                <dd className="text-gray-700 font-medium">
                  {doc.uploader?.full_name || doc.uploader_name || '—'}
                </dd>
              </div>
              <div>
                <dt className="text-gray-400">Upload Date</dt>
                <dd className="text-gray-700">
                  {doc.created_at ? format(new Date(doc.created_at), 'PPpp') : '—'}
                </dd>
              </div>
              <div>
                <dt className="text-gray-400">Signatures</dt>
                <dd className="text-gray-700">{doc.signatures?.length || 0}</dd>
              </div>
            </dl>
          </div>

          {/* Action buttons */}
          <div className="flex flex-wrap gap-2">
            <button
              onClick={handleDownload}
              className="flex items-center gap-2 px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg text-sm font-medium transition-colors"
            >
              <Download size={16} />
              Download
            </button>

            {!userHasSigned && (
              <button
                onClick={() => signMutation.mutate()}
                disabled={signMutation.isPending}
                className="flex items-center gap-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:bg-blue-300 text-white rounded-lg text-sm font-medium transition-colors"
              >
                {signMutation.isPending ? (
                  <Loader2 size={16} className="animate-spin" />
                ) : (
                  <PenLine size={16} />
                )}
                Sign Document
              </button>
            )}

            <button
              onClick={() => verifyMutation.mutate()}
              disabled={verifyMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-green-500 hover:bg-green-600 disabled:bg-green-300 text-white rounded-lg text-sm font-medium transition-colors"
            >
              {verifyMutation.isPending ? (
                <Loader2 size={16} className="animate-spin" />
              ) : (
                <ShieldCheck size={16} />
              )}
              Verify Integrity
            </button>

            {canDelete && (
              <button
                onClick={() => {
                  if (window.confirm('Delete this document?')) deleteMutation.mutate()
                }}
                disabled={deleteMutation.isPending}
                className="flex items-center gap-2 px-4 py-2 bg-red-500 hover:bg-red-600 disabled:bg-red-300 text-white rounded-lg text-sm font-medium transition-colors"
              >
                <Trash2 size={16} />
                Delete
              </button>
            )}
          </div>
        </div>
      </div>

      {/* SHA-256 Hash */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
        <h3 className="text-sm font-semibold text-gray-700 mb-2">SHA-256 Hash</h3>
        <p className="font-mono text-xs text-gray-600 break-all bg-gray-50 p-3 rounded-lg">
          {doc.file_hash || '—'}
        </p>
      </div>

      {/* Verify Result */}
      {verifyResult && (
        <div
          className={`rounded-xl border p-5 flex items-start gap-3 ${
            verifyResult.valid || verifyResult.integrity_ok
              ? 'bg-green-50 border-green-200'
              : 'bg-red-50 border-red-200'
          }`}
        >
          {verifyResult.valid || verifyResult.integrity_ok ? (
            <CheckCircle className="text-green-500 mt-0.5" size={20} />
          ) : (
            <XCircle className="text-red-500 mt-0.5" size={20} />
          )}
          <div>
            <p className="font-medium text-sm">
              {verifyResult.valid || verifyResult.integrity_ok
                ? 'Integrity Verified — document has not been tampered with.'
                : 'Integrity Failed — document hash does not match!'}
            </p>
            {verifyResult.message && (
              <p className="text-xs mt-1 text-gray-600">{verifyResult.message}</p>
            )}
          </div>
        </div>
      )}

      {/* Signatures */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
        <h3 className="text-base font-semibold text-gray-700 mb-4">Signatures</h3>
        {!doc.signatures || doc.signatures.length === 0 ? (
          <p className="text-sm text-gray-400">No signatures yet.</p>
        ) : (
          <div className="space-y-3">
            {doc.signatures.map((sig, i) => (
              <div key={sig.id || i} className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
                <CheckCircle size={18} className="text-green-500 flex-shrink-0" />
                <div>
                  <p className="text-sm font-medium text-gray-700">
                    {sig.signer?.full_name || sig.signer_name || `Signer #${i + 1}`}
                  </p>
                  <p className="text-xs text-gray-400">
                    {sig.signed_at ? format(new Date(sig.signed_at), 'PPpp') : ''}
                    {sig.is_valid === false && (
                      <span className="ml-2 text-red-500">Invalid signature</span>
                    )}
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

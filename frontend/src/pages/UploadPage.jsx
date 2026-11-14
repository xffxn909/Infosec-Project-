import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { useForm } from 'react-hook-form'
import { Upload, FileText, X, CheckCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { uploadDocument } from '../api/documents'

const ACCEPTED_TYPES = [
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'text/plain',
  'image/png',
  'image/jpeg',
]
const ACCEPTED_EXT = '.pdf,.docx,.txt,.png,.jpg,.jpeg'

export default function UploadPage() {
  const navigate = useNavigate()
  const [file, setFile] = useState(null)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [uploadedHash, setUploadedHash] = useState(null)
  const fileInputRef = useRef(null)

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm()

  const uploadMutation = useMutation({
    mutationFn: (formData) =>
      uploadDocument(formData, {
        onUploadProgress: (e) => {
          if (e.total) setUploadProgress(Math.round((e.loaded / e.total) * 100))
        },
      }),
    onSuccess: (res) => {
      const data = res.data
      const docId = data?.document?.id || data?.id
      const hash = data?.document?.file_hash || data?.file_hash
      setUploadedHash(hash)
      toast.success('Document uploaded successfully!')
      setTimeout(() => {
        if (docId) navigate(`/documents/${docId}`)
        else navigate('/documents')
      }, 2000)
    },
    onError: (err) => {
      setUploadProgress(0)
      toast.error(err.response?.data?.message || 'Upload failed')
    },
  })

  const onSubmit = async ({ title, description }) => {
    if (!file) {
      toast.error('Please select a file')
      return
    }
    const formData = new FormData()
    formData.append('file', file)
    formData.append('title', title)
    if (description) formData.append('description', description)
    setUploadProgress(0)
    uploadMutation.mutate(formData)
  }

  const handleFileChange = (e) => {
    const f = e.target.files?.[0]
    if (!f) return
    if (!ACCEPTED_TYPES.includes(f.type) && !f.name.match(/\.(pdf|docx|txt|png|jpe?g)$/i)) {
      toast.error('Unsupported file type')
      return
    }
    setFile(f)
  }

  const removeFile = () => {
    setFile(null)
    setUploadProgress(0)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-800">Upload Document</h2>
        <p className="text-sm text-gray-500 mt-1">
          Supported formats: PDF, DOCX, TXT, PNG, JPG
        </p>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
          {/* Title */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Title <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              {...register('title', { required: 'Title is required' })}
              className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
              placeholder="Document title"
            />
            {errors.title && (
              <p className="text-red-500 text-xs mt-1">{errors.title.message}</p>
            )}
          </div>

          {/* Description */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Description
            </label>
            <textarea
              {...register('description')}
              rows={3}
              className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm resize-none"
              placeholder="Optional description…"
            />
          </div>

          {/* File picker */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              File <span className="text-red-500">*</span>
            </label>
            {!file ? (
              <label
                htmlFor="fileInput"
                className="flex flex-col items-center justify-center w-full h-40 border-2 border-dashed border-gray-300 rounded-xl cursor-pointer hover:border-blue-400 hover:bg-blue-50 transition-colors"
              >
                <Upload size={32} className="text-gray-300 mb-2" />
                <p className="text-sm text-gray-500">Click to browse or drag & drop</p>
                <p className="text-xs text-gray-400 mt-1">PDF, DOCX, TXT, PNG, JPG</p>
                <input
                  id="fileInput"
                  type="file"
                  accept={ACCEPTED_EXT}
                  className="hidden"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                />
              </label>
            ) : (
              <div className="flex items-center gap-3 p-4 bg-blue-50 border border-blue-200 rounded-xl">
                <FileText size={24} className="text-blue-500 flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-800 truncate">{file.name}</p>
                  <p className="text-xs text-gray-500">
                    {(file.size / 1024).toFixed(1)} KB
                  </p>
                </div>
                <button
                  type="button"
                  onClick={removeFile}
                  className="text-gray-400 hover:text-red-500"
                >
                  <X size={18} />
                </button>
              </div>
            )}
          </div>

          {/* Progress bar */}
          {uploadMutation.isPending && (
            <div>
              <div className="flex justify-between text-xs text-gray-500 mb-1">
                <span>Uploading…</span>
                <span>{uploadProgress}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-blue-500 h-2 rounded-full transition-all duration-200"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}

          {/* Success hash display */}
          {uploadedHash && (
            <div className="flex items-start gap-3 p-4 bg-green-50 border border-green-200 rounded-xl">
              <CheckCircle size={20} className="text-green-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-green-700">Upload Successful</p>
                <p className="text-xs text-gray-600 mt-1">SHA-256:</p>
                <p className="font-mono text-xs break-all text-gray-700">{uploadedHash}</p>
                <p className="text-xs text-gray-500 mt-1">Redirecting to document detail…</p>
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={uploadMutation.isPending || !file}
            className="w-full py-2.5 px-4 bg-blue-500 hover:bg-blue-600 disabled:bg-blue-300 text-white font-medium rounded-lg transition-colors text-sm flex items-center justify-center gap-2"
          >
            {uploadMutation.isPending ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white" />
                Uploading…
              </>
            ) : (
              <>
                <Upload size={16} />
                Upload Document
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  )
}

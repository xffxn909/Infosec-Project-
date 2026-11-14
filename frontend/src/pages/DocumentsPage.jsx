import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { FileText, Upload } from 'lucide-react'
import { listDocuments } from '../api/documents'
import { format } from 'date-fns'

const statusColors = {
  draft: 'bg-yellow-100 text-yellow-700',
  signed: 'bg-green-100 text-green-700',
  verified: 'bg-blue-100 text-blue-700',
}

export default function DocumentsPage() {
  const navigate = useNavigate()

  const { data, isLoading, isError } = useQuery({
    queryKey: ['documents'],
    queryFn: () => listDocuments().then((r) => r.data),
  })

  const documents = data?.documents || data || []

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-500" />
      </div>
    )
  }

  if (isError) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-red-600 text-sm">
        Failed to load documents. Please try again.
      </div>
    )
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-800">Documents</h2>
          <p className="text-sm text-gray-500 mt-1">{documents.length} document(s)</p>
        </div>
        <button
          onClick={() => navigate('/upload')}
          className="flex items-center gap-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg text-sm font-medium transition-colors"
        >
          <Upload size={16} />
          Upload New
        </button>
      </div>

      {documents.length === 0 ? (
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-16 flex flex-col items-center text-center">
          <FileText size={48} className="text-gray-200 mb-4" />
          <p className="text-gray-500 font-medium">No documents yet</p>
          <p className="text-gray-400 text-sm mt-1">Upload your first document to get started.</p>
          <button
            onClick={() => navigate('/upload')}
            className="mt-4 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg text-sm font-medium"
          >
            Upload Document
          </button>
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 bg-gray-50">
                <th className="text-left px-5 py-3 font-medium text-gray-500">Title</th>
                <th className="text-left px-5 py-3 font-medium text-gray-500">Original File</th>
                <th className="text-left px-5 py-3 font-medium text-gray-500">SHA-256</th>
                <th className="text-left px-5 py-3 font-medium text-gray-500">Status</th>
                <th className="text-left px-5 py-3 font-medium text-gray-500">Uploaded By</th>
                <th className="text-left px-5 py-3 font-medium text-gray-500">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {documents.map((doc) => (
                <tr
                  key={doc.id}
                  onClick={() => navigate(`/documents/${doc.id}`)}
                  className="hover:bg-blue-50 cursor-pointer transition-colors"
                >
                  <td className="px-5 py-3 font-medium text-gray-800">{doc.title}</td>
                  <td className="px-5 py-3 text-gray-600">{doc.original_filename}</td>
                  <td className="px-5 py-3 font-mono text-xs text-gray-500">
                    {doc.file_hash ? doc.file_hash.substring(0, 16) + '…' : '—'}
                  </td>
                  <td className="px-5 py-3">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-xs font-medium capitalize ${
                        statusColors[doc.status] || 'bg-gray-100 text-gray-600'
                      }`}
                    >
                      {doc.status}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-gray-600">
                    {doc.uploader?.full_name || doc.uploader_name || '—'}
                  </td>
                  <td className="px-5 py-3 text-gray-500">
                    {doc.created_at
                      ? format(new Date(doc.created_at), 'MMM d, yyyy')
                      : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './context/AuthContext.jsx'
import ProtectedRoute from './components/ProtectedRoute.jsx'
import Layout from './components/Layout.jsx'
import LoginPage from './pages/LoginPage.jsx'
import DashboardPage from './pages/DashboardPage.jsx'
import DocumentsPage from './pages/DocumentsPage.jsx'
import DocumentDetailPage from './pages/DocumentDetailPage.jsx'
import UploadPage from './pages/UploadPage.jsx'
import AuditPage from './pages/AuditPage.jsx'
import AdminPage from './pages/AdminPage.jsx'
import ProfilePage from './pages/ProfilePage.jsx'
import MFASetupPage from './pages/MFASetupPage.jsx'

function RootRedirect() {
  const { isAuthenticated } = useAuth()
  return isAuthenticated ? <Navigate to="/dashboard" replace /> : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<RootRedirect />} />
      <Route path="/login" element={<LoginPage />} />

      {/* Protected routes wrapped in Layout */}
      <Route
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/documents" element={<DocumentsPage />} />
        <Route path="/documents/:id" element={<DocumentDetailPage />} />
        <Route path="/upload" element={<UploadPage />} />
        <Route path="/profile" element={<ProfilePage />} />
        <Route path="/mfa-setup" element={<MFASetupPage />} />

        {/* Manager + Admin only */}
        <Route
          path="/audit"
          element={
            <ProtectedRoute roles={['admin', 'manager']}>
              <AuditPage />
            </ProtectedRoute>
          }
        />

        {/* Admin only */}
        <Route
          path="/admin"
          element={
            <ProtectedRoute roles={['admin']}>
              <AdminPage />
            </ProtectedRoute>
          }
        />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

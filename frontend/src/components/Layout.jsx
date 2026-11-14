import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  FileText,
  Upload,
  ClipboardList,
  ShieldCheck,
  User,
  LogOut,
  Lock,
} from 'lucide-react'
import { useAuth } from '../context/AuthContext.jsx'
import { logout as apiLogout } from '../api/auth'
import toast from 'react-hot-toast'

const navItems = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, roles: null },
  { to: '/documents', label: 'Documents', icon: FileText, roles: null },
  { to: '/upload', label: 'Upload', icon: Upload, roles: null },
  { to: '/audit', label: 'Audit Log', icon: ClipboardList, roles: ['admin', 'manager'] },
  { to: '/admin', label: 'Admin', icon: ShieldCheck, roles: ['admin'] },
  { to: '/profile', label: 'Profile', icon: User, roles: null },
]

export default function Layout() {
  const { user, role, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = async () => {
    try {
      await apiLogout()
    } catch {
      // ignore
    }
    logout()
    toast.success('Logged out successfully')
    navigate('/login')
  }

  const visibleNavItems = navItems.filter(
    (item) => !item.roles || item.roles.includes(role),
  )

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 flex-shrink-0 flex flex-col" style={{ backgroundColor: '#1e2a3a' }}>
        {/* Logo */}
        <div className="flex items-center gap-3 px-6 py-5 border-b border-white/10">
          <Lock className="text-blue-400" size={22} />
          <span className="text-white font-bold text-lg tracking-wide">SecureDoc</span>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-4 py-6 space-y-1 overflow-y-auto">
          {visibleNavItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-blue-500 text-white'
                    : 'text-gray-300 hover:bg-white/10 hover:text-white'
                }`
              }
            >
              <Icon size={18} />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* User info at bottom */}
        <div className="border-t border-white/10 px-4 py-4">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-9 h-9 rounded-full bg-blue-500 flex items-center justify-center text-white text-sm font-bold">
              {user?.full_name?.[0]?.toUpperCase() || 'U'}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-white text-sm font-medium truncate">{user?.full_name}</p>
              <p className="text-gray-400 text-xs capitalize">{role}</p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 w-full px-3 py-2 rounded-lg text-gray-300 hover:bg-white/10 hover:text-white text-sm transition-all"
          >
            <LogOut size={16} />
            Sign out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top header */}
        <header className="bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
          <h1 className="text-gray-500 text-sm">
            Secure Document Management &amp; E-Signature System
          </h1>
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <User size={16} />
            <span>{user?.email}</span>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto bg-gray-50 p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

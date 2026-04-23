import React from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Attacks from './pages/Attacks'
import Sessions from './pages/Sessions'
import Forensics from './pages/Forensics'
import Reports from './pages/Reports'
import Sidebar from './components/Sidebar'

function PrivateLayout({ children }) {
  const token = localStorage.getItem('token')
  if (!token) return <Navigate to="/login" replace />
  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content">{children}</main>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<PrivateLayout><Dashboard /></PrivateLayout>} />
        <Route path="/attacks" element={<PrivateLayout><Attacks /></PrivateLayout>} />
        <Route path="/sessions" element={<PrivateLayout><Sessions /></PrivateLayout>} />
        <Route path="/forensics" element={<PrivateLayout><Forensics /></PrivateLayout>} />
        <Route path="/reports" element={<PrivateLayout><Reports /></PrivateLayout>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

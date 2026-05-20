import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import { ModalProvider } from './contexts/ModalContext';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';

const Landing        = lazy(() => import('./pages/Landing'));
const Login          = lazy(() => import('./pages/Login'));
const Stats          = lazy(() => import('./pages/Stats'));
const Alerts         = lazy(() => import('./pages/Alerts'));
const Health         = lazy(() => import('./pages/Health'));
const Timeline       = lazy(() => import('./pages/Timeline'));
const Reconstruction = lazy(() => import('./pages/Reconstruction'));
const Evidence       = lazy(() => import('./pages/Evidence'));
const Profiling      = lazy(() => import('./pages/Profiling'));
const GeoMap         = lazy(() => import('./pages/GeoMap'));
const Reporting      = lazy(() => import('./pages/Reporting'));
const Honeypots      = lazy(() => import('./pages/Honeypots'));
const Access         = lazy(() => import('./pages/Access'));
const Settings       = lazy(() => import('./pages/Settings'));
const Config         = lazy(() => import('./pages/Config'));
const Audit          = lazy(() => import('./pages/Audit'));
const Yara           = lazy(() => import('./pages/Yara'));
const Sessions       = lazy(() => import('./pages/Sessions'));
const Dashboard      = lazy(() => import('./pages/Dashboard'));

function PageLoader() {
  return <div className="alert info" style={{margin:'40px 20px'}}>Loading…</div>;
}

function Protected({ children, roles }) {
  return <ProtectedRoute roles={roles}>{children}</ProtectedRoute>;
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ModalProvider>
          <Suspense fallback={<PageLoader />}>
            <Routes>
              <Route path="/" element={<Landing />} />
              <Route path="/login" element={<Login />} />
              <Route element={
                <Protected>
                  <Layout />
                </Protected>
              }>
                <Route path="/stats"          element={<Stats />} />
                <Route path="/alerts"         element={<Alerts />} />
                <Route path="/health"         element={<Protected roles={['admin']}><Health /></Protected>} />
                <Route path="/timeline"       element={<Timeline />} />
                <Route path="/reconstruction" element={<Reconstruction />} />
                <Route path="/evidence"       element={<Evidence />} />
                <Route path="/profiling"      element={<Profiling />} />
                <Route path="/geomap"         element={<GeoMap />} />
                <Route path="/reporting"      element={<Reporting />} />
                <Route path="/honeypots"      element={<Protected roles={['admin']}><Honeypots /></Protected>} />
                <Route path="/access"         element={<Protected roles={['admin']}><Access /></Protected>} />
                <Route path="/settings"       element={<Settings />} />
                <Route path="/config"         element={<Protected roles={['admin']}><Config /></Protected>} />
                <Route path="/audit"          element={<Audit />} />
                <Route path="/yara"           element={<Yara />} />
                <Route path="/sessions"       element={<Sessions />} />
                <Route path="/dashboard"      element={<Navigate to="/stats" replace />} />
                <Route path="*"               element={<Navigate to="/stats" replace />} />
              </Route>
            </Routes>
          </Suspense>
        </ModalProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}

import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import { DashboardLayout } from "./components/layout/DashboardLayout";

import { LandingPage } from "./pages/LandingPage";
import { LoginPage } from "./pages/LoginPage";
import { SignupPage } from "./pages/SignupPage";
import { DashboardPage } from "./pages/DashboardPage";
import { WebsitesPage } from "./pages/WebsitesPage";
import { NewScanPage } from "./pages/NewScanPage";
import { ScansListPage } from "./pages/ScansListPage";
import { ScanDetailPage } from "./pages/ScanDetailPage";
import { ScanComparePage } from "./pages/ScanComparePage";
import { VulnerabilitiesPage } from "./pages/VulnerabilitiesPage";
import { VulnerabilityDetailPage } from "./pages/VulnerabilityDetailPage";
import { RemediationPage } from "./pages/RemediationPage";
import { ReportsPage } from "./pages/ReportsPage";
import { MonitoringPage } from "./pages/MonitoringPage";
import { AdminDashboardPage } from "./pages/AdminDashboardPage";
import { AuditLogsPage } from "./pages/AuditLogsPage";
import { ProfilePage } from "./pages/ProfilePage";

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#0B0F19] flex items-center justify-center text-xs text-slate-400 font-mono">
        Connecting to SecureAudit Pro SOC session...
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Routes */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/signup" element={<SignupPage />} />
          <Route path="/register" element={<SignupPage />} />

          {/* Authenticated Dashboard Routes */}
          <Route
            element={
              <ProtectedRoute>
                <DashboardLayout />
              </ProtectedRoute>
            }
          >
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/monitoring" element={<MonitoringPage />} />
            <Route path="/websites" element={<WebsitesPage />} />
            <Route path="/scans" element={<ScansListPage />} />
            <Route path="/scans/new" element={<NewScanPage />} />
            <Route path="/scans/:id" element={<ScanDetailPage />} />
            <Route path="/scans/compare" element={<ScanComparePage />} />
            <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
            <Route path="/vulnerabilities/:id" element={<VulnerabilityDetailPage />} />
            <Route path="/remediation" element={<RemediationPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/admin" element={<AdminDashboardPage />} />
            <Route path="/admin/audit-logs" element={<AuditLogsPage />} />
            <Route path="/profile" element={<ProfilePage />} />
          </Route>

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
};

export default App;

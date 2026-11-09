import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import {
  Settings,
  Server,
  Database,
  Cpu,
  HardDrive,
  Users,
  ShieldCheck,
  RotateCcw,
  CheckCircle2,
  AlertCircle,
  ScrollText,
  Activity
} from "lucide-react";
import { adminApi } from "../services/api";

export const AdminDashboardPage: React.FC = () => {
  const [stats, setStats] = useState<any | null>(null);
  const [health, setHealth] = useState<any | null>(null);
  const [users, setUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [resetting, setResetting] = useState(false);
  const [resetSuccess, setResetSuccess] = useState<string | null>(null);

  const fetchAdminData = async () => {
    try {
      const [stRes, hRes] = await Promise.all([
        adminApi.getStats(),
        adminApi.getHealth()
      ]);
      setStats(stRes.data);
      setHealth(hRes.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAdminData();
  }, []);

  const handleResetDemo = async () => {
    if (!window.confirm("Are you sure you want to reset demo data? This will re-seed websites, sample scans, and test accounts.")) {
      return;
    }
    setResetting(true);
    setResetSuccess(null);
    try {
      const res = await adminApi.resetDemoData();
      setResetSuccess(res.data.message || "Demo data successfully re-seeded!");
      fetchAdminData();
    } catch (err: any) {
      alert("Error resetting demo data: " + err.message);
    } finally {
      setResetting(false);
    }
  };

  if (loading) {
    return <div className="py-20 text-center text-xs text-slate-500 font-mono">Loading platform diagnostics...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
            <Settings className="h-6 w-6 text-cyan-400" /> System Administration & Diagnostics
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            PLATFORM HEALTH, SCANNER SERVICE TOPOLOGY, STORAGE UTILIZATION, AND DEMO ENVIRONMENT MANAGEMENT
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/admin/audit-logs"
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold flex items-center gap-2 transition-colors"
          >
            <ScrollText className="h-4 w-4" /> View Audit Logs
          </Link>
          <button
            onClick={handleResetDemo}
            disabled={resetting}
            className="px-3.5 py-2 bg-rose-600/20 hover:bg-rose-600/30 border border-rose-500/40 text-rose-300 rounded-lg text-xs font-bold flex items-center gap-2 transition-colors"
          >
            <RotateCcw className={`h-4 w-4 ${resetting ? "animate-spin" : ""}`} /> Reset Demo Data
          </button>
        </div>
      </div>

      {resetSuccess && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-400 flex items-center gap-2">
          <CheckCircle2 className="h-4 w-4" /> {resetSuccess}
        </div>
      )}

      {/* Services Health Grid */}
      <div className="grid md:grid-cols-4 gap-4">
        <div className="bg-[#111827] border border-[#1E293B] p-4 rounded-xl">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-400 mb-2">
            <span>Database Layer</span>
            <Database className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-sm font-bold text-white font-mono">{health?.services?.database?.engine}</div>
          <div className="text-[11px] text-emerald-400 mt-1 font-mono flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            {health?.services?.database?.status}
          </div>
        </div>

        <div className="bg-[#111827] border border-[#1E293B] p-4 rounded-xl">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-400 mb-2">
            <span>Broker & Cache</span>
            <Server className="h-4 w-4 text-purple-400" />
          </div>
          <div className="text-sm font-bold text-white font-mono">{health?.services?.cache_broker?.engine}</div>
          <div className="text-[11px] text-cyan-400 mt-1 font-mono flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
            {health?.services?.cache_broker?.status}
          </div>
        </div>

        <div className="bg-[#111827] border border-[#1E293B] p-4 rounded-xl">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-400 mb-2">
            <span>Task Queue Workers</span>
            <Activity className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-sm font-bold text-white font-mono">Celery / Worker Pool</div>
          <div className="text-[11px] text-emerald-400 mt-1 font-mono flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            Active & Ready
          </div>
        </div>

        <div className="bg-[#111827] border border-[#1E293B] p-4 rounded-xl">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-400 mb-2">
            <span>Disk Storage</span>
            <HardDrive className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-sm font-bold text-white font-mono">
            {health?.storage?.used_gb || 0} / {health?.storage?.total_gb || 0} GB
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono">
            {health?.storage?.percent_used}% utilized
          </div>
        </div>
      </div>

      {/* Security Scanning Engines Status */}
      <div className="bg-[#111827] border border-[#1E293B] rounded-2xl p-5 space-y-4">
        <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
          <Cpu className="h-4 w-4 text-cyan-400" /> Scanning Engine Adapter Integrations
        </h3>

        <div className="grid md:grid-cols-3 gap-4">
          <div className="bg-[#0B0F19] border border-[#1E293B] p-4 rounded-xl">
            <div className="text-xs font-bold text-white mb-1">Native Python VAPT Engine</div>
            <div className="text-xs text-slate-400 mb-2">HTTP, SSL/TLS, Headers, Cookies, CORS, DNS, Exposed Files, OWASP Top 10</div>
            <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-mono">
              ONLINE (Embedded)
            </span>
          </div>

          <div className="bg-[#0B0F19] border border-[#1E293B] p-4 rounded-xl">
            <div className="text-xs font-bold text-white mb-1">OWASP ZAP Automation Framework</div>
            <div className="text-xs text-slate-400 mb-2">Automated spidering, passive alert collection, and active scan orchestration</div>
            <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-mono">
              ADAPTER READY (API: owasp-zap:8080)
            </span>
          </div>

          <div className="bg-[#0B0F19] border border-[#1E293B] p-4 rounded-xl">
            <div className="text-xs font-bold text-white mb-1">ProjectDiscovery Nuclei</div>
            <div className="text-xs text-slate-400 mb-2">Curated safe community templates (CVEs, misconfigs, exposure) with rate limiting</div>
            <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-mono">
              ADAPTER READY (Safe Templates)
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Globe,
  Radar,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  Clock,
  ArrowRight,
  TrendingDown,
  ShieldCheck,
  Server,
  Lock,
  Layers,
  Activity,
  Zap,
  Sparkles
} from "lucide-react";
import { SeverityDonutChart } from "../charts/SeverityDonutChart";
import { OwaspDistributionChart, SecurityScoreGauge } from "../charts/OwaspRadarChart";
import { SeverityBadge, StatusBadge } from "../components/ui/SeverityBadge";
import { websitesApi, scansApi, vulnerabilitiesApi, adminApi } from "../services/api";

const containerVariants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: {
      staggerChildren: 0.04
    }
  }
};

const cardVariants = {
  hidden: { opacity: 0, y: 15, scale: 0.98 },
  show: { 
    opacity: 1, 
    y: 0, 
    scale: 1,
    transition: { type: "spring", stiffness: 350, damping: 25 }
  }
};

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [quickUrl, setQuickUrl] = useState("");
  const [websites, setWebsites] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadDashboardData = async () => {
      try {
        const [wRes, sRes, vRes, stRes] = await Promise.all([
          websitesApi.list(),
          scansApi.list(),
          vulnerabilitiesApi.list(),
          adminApi.getStats()
        ]);
        setWebsites(wRes.data);
        setScans(sRes.data);
        setVulnerabilities(vRes.data);
        setStats(stRes.data);
      } catch (err) {
        console.error("Dashboard data load error:", err);
      } finally {
        setLoading(false);
      }
    };
    loadDashboardData();
  }, []);

  // Compute metrics from actual data
  const totalWebsites = websites.length;
  const totalScans = scans.length;
  const activeScans = scans.filter(s => s.status === "running").length;
  const totalVulns = vulnerabilities.length;
  const criticalVulns = vulnerabilities.filter(v => v.severity === "critical" && v.status !== "fixed").length;
  const highVulns = vulnerabilities.filter(v => v.severity === "high" && v.status !== "fixed").length;
  const mediumVulns = vulnerabilities.filter(v => v.severity === "medium" && v.status !== "fixed").length;
  const lowVulns = vulnerabilities.filter(v => v.severity === "low" && v.status !== "fixed").length;
  const resolvedVulns = vulnerabilities.filter(v => v.status === "fixed").length;

  const avgSecurityScore = websites.length > 0
    ? Math.round(websites.reduce((acc, s) => acc + (s.security_score || 100), 0) / websites.length)
    : 100;

  const severityCounts = {
    critical: criticalVulns,
    high: highVulns,
    medium: mediumVulns,
    low: lowVulns,
    info: vulnerabilities.filter(v => v.severity === "info" && v.status !== "fixed").length
  };

  return (
    <div className="space-y-6">
      {/* Page Title & Quick Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2">
        <div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
            Security Operations Center <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            LIVE CONTINUOUS APPLICATION SECURITY POSTURE & VULNERABILITY INTELLIGENCE
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link
            to="/scans/new"
            className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-lg text-xs font-bold tracking-wide shadow-md transition-all flex items-center gap-2"
          >
            <Radar className="h-4 w-4" /> Launch Scan Wizard
          </Link>
          <Link
            to="/websites"
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-all flex items-center gap-2"
          >
            <Globe className="h-4 w-4" /> Add Target Website
          </Link>
        </div>
      </div>

      {/* Direct Target URL Quick Assessment Bar */}
      <div className="p-4 rounded-2xl bg-gradient-to-r from-cyan-950/40 via-[#111827] to-blue-950/40 border border-cyan-500/30 shadow-xl space-y-2">
        <div className="flex flex-col sm:flex-row items-center gap-3">
          <div className="flex items-center gap-2 text-cyan-300 font-bold text-xs shrink-0 font-mono">
            <Zap className="h-4 w-4 text-cyan-400" /> DIRECT URL SCANNER:
          </div>
          <div className="relative flex-1 w-full">
            <Globe className="absolute left-3.5 top-2.5 h-4 w-4 text-slate-500" />
            <input
              type="text"
              value={quickUrl}
              onChange={(e) => setQuickUrl(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && quickUrl.trim()) {
                  navigate(`/scans/new?url=${encodeURIComponent(quickUrl.trim())}`);
                }
              }}
              placeholder="Enter any target website or URL (e.g. https://example.com or http://target-api.internal)..."
              className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl pl-10 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
          <button
            onClick={() => {
              if (quickUrl.trim()) {
                navigate(`/scans/new?url=${encodeURIComponent(quickUrl.trim())}`);
              } else {
                navigate("/scans/new");
              }
            }}
            className="w-full sm:w-auto px-5 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white rounded-xl text-xs font-bold transition-all shadow-lg shadow-cyan-950/40 flex items-center justify-center gap-1.5 shrink-0"
          >
            <Radar className="h-4 w-4" /> Start VAPT Audit
          </button>
        </div>
        <div className="flex items-center gap-2 text-[10px] text-slate-400 font-mono pl-1">
          <span>Supported:</span>
          <span className="text-cyan-400">Open Ports & Perimeter Discovery</span>
          <span className="text-slate-600">•</span>
          <span className="text-purple-400">OWASP Top 10:2025</span>
          <span className="text-slate-600">•</span>
          <span className="text-emerald-400">SSL/TLS & Headers</span>
          <span className="text-slate-600">•</span>
          <span className="text-amber-400">Exposed Files (.env/.git)</span>
        </div>
      </div>

      {/* 10 Overview KPI Cards Grid */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="show"
        className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5"
      >
        <motion.div variants={cardVariants} whileHover={{ y: -4, scale: 1.02 }} className="glass-panel glass-panel-hover p-4 rounded-2xl shadow-sm cursor-pointer">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Targets</span>
            <Globe className="h-3.5 w-3.5 text-cyan-400" />
          </div>
          <div className="text-2xl font-extrabold text-white mt-1.5 font-mono">{totalWebsites}</div>
          <div className="text-[10px] text-slate-500 mt-1">Registered websites</div>
        </motion.div>

        <motion.div variants={cardVariants} whileHover={{ y: -4, scale: 1.02 }} className="glass-panel glass-panel-hover p-4 rounded-2xl shadow-sm cursor-pointer">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Scans Run</span>
            <Radar className="h-3.5 w-3.5 text-blue-400" />
          </div>
          <div className="text-2xl font-extrabold text-white mt-1.5 font-mono">{totalScans}</div>
          <div className="text-[10px] text-slate-500 mt-1">Total completed</div>
        </motion.div>

        <motion.div variants={cardVariants} whileHover={{ y: -4, scale: 1.02 }} className="glass-panel glass-panel-hover p-4 rounded-2xl shadow-sm cursor-pointer">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Active Scans</span>
            <Activity className="h-3.5 w-3.5 text-amber-400" />
          </div>
          <div className="text-2xl font-extrabold text-amber-400 mt-1.5 font-mono">{activeScans}</div>
          <div className="text-[10px] text-slate-500 mt-1">Currently running</div>
        </motion.div>

        <motion.div variants={cardVariants} whileHover={{ y: -4, scale: 1.02 }} className="glass-panel glass-panel-hover p-4 rounded-2xl shadow-sm cursor-pointer">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Critical</span>
            <ShieldAlert className="h-3.5 w-3.5 text-red-400" />
          </div>
          <div className="text-2xl font-extrabold text-red-400 mt-1.5 font-mono">{criticalVulns}</div>
          <div className="text-[10px] text-red-500/80 mt-1 font-semibold">Immediate action</div>
        </motion.div>

        <motion.div variants={cardVariants} whileHover={{ y: -4, scale: 1.02 }} className="glass-panel glass-panel-hover p-4 rounded-2xl shadow-sm cursor-pointer">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>High</span>
            <AlertTriangle className="h-3.5 w-3.5 text-orange-400" />
          </div>
          <div className="text-2xl font-extrabold text-orange-400 mt-1.5 font-mono">{highVulns}</div>
          <div className="text-[10px] text-slate-500 mt-1">Priority remediate</div>
        </motion.div>

        <motion.div variants={cardVariants} whileHover={{ y: -4, scale: 1.02 }} className="glass-panel glass-panel-hover p-4 rounded-2xl shadow-sm cursor-pointer">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Medium</span>
            <Layers className="h-3.5 w-3.5 text-amber-400" />
          </div>
          <div className="text-2xl font-extrabold text-amber-400 mt-1.5 font-mono">{mediumVulns}</div>
          <div className="text-[10px] text-slate-500 mt-1">Misconfigurations</div>
        </motion.div>

        <motion.div variants={cardVariants} whileHover={{ y: -4, scale: 1.02 }} className="glass-panel glass-panel-hover p-4 rounded-2xl shadow-sm cursor-pointer">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Low / Info</span>
            <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
          </div>
          <div className="text-2xl font-extrabold text-emerald-400 mt-1.5 font-mono">{lowVulns}</div>
          <div className="text-[10px] text-slate-500 mt-1">Hardening hints</div>
        </motion.div>

        <motion.div variants={cardVariants} whileHover={{ y: -4, scale: 1.02 }} className="glass-panel glass-panel-hover p-4 rounded-2xl shadow-sm cursor-pointer">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Resolved</span>
            <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
          </div>
          <div className="text-2xl font-extrabold text-emerald-400 mt-1.5 font-mono">{resolvedVulns}</div>
          <div className="text-[10px] text-slate-500 mt-1">Fixed issues</div>
        </motion.div>

        <motion.div variants={cardVariants} whileHover={{ y: -4, scale: 1.02 }} className="glass-panel glass-panel-hover p-4 rounded-2xl shadow-sm cursor-pointer">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Total Vulns</span>
            <Clock className="h-3.5 w-3.5 text-slate-400" />
          </div>
          <div className="text-2xl font-extrabold text-white mt-1.5 font-mono">{totalVulns}</div>
          <div className="text-[10px] text-slate-500 mt-1">Across all assets</div>
        </motion.div>

        <motion.div variants={cardVariants} whileHover={{ y: -4, scale: 1.02 }} className="glass-panel glass-panel-hover p-4 rounded-2xl shadow-sm cursor-pointer">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Mean Score</span>
            <span className={`text-[10px] font-bold ${avgSecurityScore >= 80 ? 'text-emerald-400' : 'text-amber-400'}`}>
              Grade {avgSecurityScore >= 85 ? 'A' : avgSecurityScore >= 70 ? 'B' : 'C'}
            </span>
          </div>
          <div className="text-2xl font-extrabold text-cyan-400 mt-1.5 font-mono">{avgSecurityScore}</div>
          <div className="text-[10px] text-slate-500 mt-1">Asset posture avg</div>
        </motion.div>
      </motion.div>

      {/* Main Charts & Posture Section */}
      <div className="grid lg:grid-cols-3 gap-6">
        {/* Severity Donut */}
        <div className="bg-[#111827] border border-[#1E293B] rounded-2xl p-5">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-bold text-white tracking-wide">Severity Distribution</h3>
            <span className="text-[11px] text-slate-400 font-mono">CVSS Weighted</span>
          </div>
          <SeverityDonutChart data={severityCounts} />
          <div className="grid grid-cols-3 gap-2 text-center pt-2 border-t border-[#1E293B]">
            <div>
              <div className="text-xs font-bold text-red-400 font-mono">{criticalVulns}</div>
              <div className="text-[10px] text-slate-400">Critical</div>
            </div>
            <div>
              <div className="text-xs font-bold text-orange-400 font-mono">{highVulns}</div>
              <div className="text-[10px] text-slate-400">High</div>
            </div>
            <div>
              <div className="text-xs font-bold text-amber-400 font-mono">{mediumVulns}</div>
              <div className="text-[10px] text-slate-400">Medium</div>
            </div>
          </div>
        </div>

        {/* OWASP Top 10 Breakdown */}
        <div className="bg-[#111827] border border-[#1E293B] rounded-2xl p-5">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-bold text-white tracking-wide">OWASP Top 10:2025 Analysis</h3>
            <span className="text-[11px] text-cyan-400 font-mono">Real Findings</span>
          </div>
          <OwaspDistributionChart vulnerabilities={vulnerabilities} />
        </div>

        {/* Global Security Gauge */}
        <div className="bg-[#111827] border border-[#1E293B] rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-bold text-white tracking-wide">Organization Security Score</h3>
              <span className="text-[11px] text-slate-400 font-mono">0-100 Algorithm</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Calculated via weighted penalties per confirmed defect, asset criticality, and finding confidence.
            </p>
          </div>
          <SecurityScoreGauge score={avgSecurityScore} riskLevel="Aggregate Posture Score" />
          <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 text-[11px] text-slate-400 text-center">
            Zero defects detected does not constitute a formal certificate of complete security.
          </div>
        </div>
      </div>

      {/* Recent Discovered Vulnerabilities & Scans Table */}
      <div className="grid lg:grid-cols-2 gap-6">
        {/* Discovered Vulnerabilities */}
        <div className="bg-[#111827] border border-[#1E293B] rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-cyan-400" /> Active Security Findings
            </h3>
            <Link to="/vulnerabilities" className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold">
              View all <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
          <div className="space-y-2.5">
            {vulnerabilities.slice(0, 5).map((v) => (
              <Link
                key={v.id}
                to={`/vulnerabilities/${v.id}`}
                className="p-3 bg-[#0B0F19] hover:bg-slate-800/40 border border-[#1E293B] rounded-xl flex items-center justify-between gap-3 transition-colors block"
              >
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-white truncate">{v.title}</div>
                  <div className="text-[11px] text-slate-400 font-mono truncate mt-0.5">{v.affected_url}</div>
                </div>
                <div className="shrink-0 flex items-center gap-2">
                  <SeverityBadge severity={v.severity} size="sm" />
                  <StatusBadge status={v.status} />
                </div>
              </Link>
            ))}
          </div>
        </div>

        {/* Latest Scans */}
        <div className="bg-[#111827] border border-[#1E293B] rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Radar className="h-4 w-4 text-cyan-400" /> Recent Security Scans
            </h3>
            <Link to="/scans" className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold">
              View all <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
          <div className="space-y-2.5">
            {scans.slice(0, 5).map((s) => (
              <Link
                key={s.id}
                to={`/scans/${s.id}`}
                className="p-3 bg-[#0B0F19] hover:bg-slate-800/40 border border-[#1E293B] rounded-xl flex items-center justify-between gap-3 transition-colors block"
              >
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-white truncate">{s.website_name}</div>
                  <div className="text-[11px] text-slate-400 font-mono truncate mt-0.5">{s.target_url}</div>
                </div>
                <div className="shrink-0 text-right">
                  <span className={`inline-block px-2 py-0.5 rounded text-xs font-mono uppercase ${
                    s.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' :
                    s.status === 'running' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30 animate-pulse' :
                    'bg-slate-800 text-slate-300'
                  }`}>
                    {s.status}
                  </span>
                  <div className="text-[10px] text-slate-500 mt-1">Score: {s.security_score ?? 'N/A'}/100</div>
                </div>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

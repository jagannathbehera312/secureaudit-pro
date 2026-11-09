import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Radar, Plus, ArrowRight, Clock, CheckCircle2, AlertCircle, XCircle, Search, RefreshCw, Activity, ShieldCheck, Flame } from "lucide-react";
import { scansApi } from "../services/api";

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.06,
      delayChildren: 0.1
    }
  }
};

const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.35, ease: "easeOut" }
  }
};

export const ScansListPage: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("all");
  const [search, setSearch] = useState("");

  const fetchScans = async () => {
    try {
      const res = await scansApi.list();
      setScans(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 10000);
    return () => clearInterval(interval);
  }, []);

  const filteredScans = scans.filter((s) => {
    if (statusFilter !== "all" && s.status !== statusFilter) return false;
    if (search && !s.target_url?.toLowerCase().includes(search.toLowerCase()) && !s.website_name?.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const runningCount = scans.filter((s) => s.status === "running").length;
  const completedCount = scans.filter((s) => s.status === "completed").length;
  const totalFindings = scans.reduce((acc, s) => acc + (s.findings_count || 0), 0);
  const avgScore = completedCount > 0
    ? Math.round(scans.filter(s => s.status === "completed" && s.security_score !== null && s.security_score !== undefined).reduce((acc, s) => acc + s.security_score, 0) / (scans.filter(s => s.status === "completed" && s.security_score !== null && s.security_score !== undefined).length || 1))
    : 100;

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="space-y-6"
    >
      {/* Top Header */}
      <motion.div variants={itemVariants} className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-extrabold text-white tracking-tight">Security Assessment Runs</h1>
            {runningCount > 0 && (
              <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
                {runningCount} Active Job{runningCount > 1 ? "s" : ""}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            HISTORICAL AUDIT LOGS, ACTIVE JOBS, AND DISCOVERED VULNERABILITY COUNTS
          </p>
        </div>
        <div className="flex items-center gap-3">
          <motion.button
            whileHover={{ scale: 1.05, rotate: 180 }}
            whileTap={{ scale: 0.95 }}
            transition={{ duration: 0.25 }}
            onClick={fetchScans}
            className="p-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs border border-slate-700/60 shadow-sm"
            title="Refresh Scans"
          >
            <RefreshCw className="h-4 w-4" />
          </motion.button>
          <motion.div whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
            <Link
              to="/scans/new"
              className="px-4 py-2.5 bg-gradient-to-r from-cyan-600 via-teal-600 to-blue-600 text-white rounded-xl text-xs font-bold shadow-lg shadow-cyan-900/30 transition-all flex items-center gap-2 glow-cyan"
            >
              <Plus className="h-4 w-4" /> New Security Scan
            </Link>
          </motion.div>
        </div>
      </motion.div>

      {/* Mini KPI summary strip */}
      <motion.div variants={itemVariants} className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="glass-panel p-3.5 rounded-xl border border-white/5 flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
            <Activity className="h-4 w-4" />
          </div>
          <div>
            <div className="text-[10px] text-slate-400 uppercase font-mono">Total Scans</div>
            <div className="text-lg font-bold text-white font-mono">{scans.length}</div>
          </div>
        </div>

        <div className="glass-panel p-3.5 rounded-xl border border-white/5 flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
            <Radar className="h-4 w-4 animate-spin" style={{ animationDuration: "8s" }} />
          </div>
          <div>
            <div className="text-[10px] text-slate-400 uppercase font-mono">Running Jobs</div>
            <div className="text-lg font-bold text-amber-400 font-mono">{runningCount}</div>
          </div>
        </div>

        <div className="glass-panel p-3.5 rounded-xl border border-white/5 flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <ShieldCheck className="h-4 w-4" />
          </div>
          <div>
            <div className="text-[10px] text-slate-400 uppercase font-mono">Avg Health Score</div>
            <div className="text-lg font-bold text-emerald-400 font-mono">{avgScore}/100</div>
          </div>
        </div>

        <div className="glass-panel p-3.5 rounded-xl border border-white/5 flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400">
            <Flame className="h-4 w-4" />
          </div>
          <div>
            <div className="text-[10px] text-slate-400 uppercase font-mono">Flaws Found</div>
            <div className="text-lg font-bold text-red-400 font-mono">{totalFindings}</div>
          </div>
        </div>
      </motion.div>

      {/* Filter and Search Bar with Animated Pill */}
      <motion.div variants={itemVariants} className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-[#111827]/90 backdrop-blur-md p-3 rounded-2xl border border-[#1E293B]">
        <div className="flex items-center gap-2 w-full sm:w-80 bg-[#0B0F19] px-3 py-2 rounded-xl border border-[#1E293B] focus-within:border-cyan-500/60 transition-colors">
          <Search className="h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search scans by URL or asset..."
            className="bg-transparent text-xs text-white focus:outline-none w-full placeholder:text-slate-500"
          />
        </div>

        {/* Animated Sliding Pill Filter Tabs */}
        <div className="flex items-center gap-1.5 self-end sm:self-auto overflow-x-auto p-1 bg-[#0B0F19] rounded-xl border border-[#1E293B]">
          {["all", "running", "completed", "failed", "cancelled"].map((st) => {
            const isActive = statusFilter === st;
            return (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`relative px-3 py-1.5 rounded-lg text-xs font-semibold capitalize transition-colors duration-200 ${
                  isActive ? "text-cyan-300" : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {isActive && (
                  <motion.div
                    layoutId="activeScanFilterPill"
                    className="absolute inset-0 bg-cyan-500/20 border border-cyan-500/40 rounded-lg shadow-sm"
                    transition={{ type: "spring", stiffness: 450, damping: 32 }}
                  />
                )}
                <span className="relative z-10 flex items-center gap-1.5">
                  {st === "running" && <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />}
                  {st}
                </span>
              </button>
            );
          })}
        </div>
      </motion.div>

      {/* Scans Table */}
      <motion.div variants={itemVariants} className="bg-[#111827]/80 backdrop-blur-md border border-[#1E293B] rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0B0F19]/90 border-b border-[#1E293B] text-slate-400 uppercase font-mono text-[10px]">
              <tr>
                <th className="py-3.5 px-4">Target Website</th>
                <th className="py-3.5 px-4">Profile</th>
                <th className="py-3.5 px-4">Status & Progress</th>
                <th className="py-3.5 px-4">Score</th>
                <th className="py-3.5 px-4">Findings</th>
                <th className="py-3.5 px-4">Executed</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]/60">
              {filteredScans.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-slate-500">
                    <Radar className="h-8 w-8 mx-auto mb-2 text-slate-600 opacity-60" />
                    No matching scan runs found.
                  </td>
                </tr>
              ) : (
                filteredScans.map((s, idx) => (
                  <motion.tr
                    key={s.id}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.25, delay: idx * 0.03 }}
                    className="hover:bg-slate-800/30 transition-colors group"
                  >
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-white group-hover:text-cyan-300 transition-colors">{s.website_name}</div>
                      <div className="text-[11px] text-cyan-400 font-mono truncate max-w-xs">{s.target_url}</div>
                    </td>
                    <td className="py-3.5 px-4 font-mono uppercase text-slate-300">
                      <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700/60 text-[10px]">
                        {s.profile}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded-md text-[10px] font-mono uppercase font-semibold ${
                          s.status === "completed" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30" :
                          s.status === "running" ? "bg-amber-500/15 text-amber-300 border border-amber-500/40 animate-pulse" :
                          s.status === "failed" ? "bg-red-500/10 text-red-400 border border-red-500/30" :
                          "bg-slate-800 text-slate-400"
                        }`}>
                          {s.status}
                        </span>
                        {s.status === "running" && (
                          <span className="text-[10px] text-cyan-400 font-mono font-bold">{s.progress}%</span>
                        )}
                      </div>
                      {s.status === "running" && (
                        <div className="w-36 h-1.5 bg-slate-800 rounded-full mt-1.5 overflow-hidden">
                          <motion.div
                            className="h-full bg-gradient-to-r from-cyan-500 to-blue-500"
                            initial={{ width: 0 }}
                            animate={{ width: `${s.progress}%` }}
                            transition={{ duration: 0.5 }}
                          />
                        </div>
                      )}
                      <div className="text-[10px] text-slate-500 mt-1 truncate max-w-[200px] font-mono">{s.current_stage}</div>
                    </td>
                    <td className="py-3.5 px-4 font-mono font-bold">
                      {s.security_score !== null && s.security_score !== undefined ? (
                        <span className={s.security_score >= 80 ? "text-emerald-400" : s.security_score >= 60 ? "text-amber-400" : "text-red-400"}>
                          {s.security_score}/100
                        </span>
                      ) : (
                        <span className="text-slate-600">-</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 font-mono font-semibold">
                      {s.findings_count > 0 ? (
                        <span className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400">
                          {s.findings_count} flaws
                        </span>
                      ) : (
                        <span className="text-slate-500">0</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 text-[11px] font-mono">
                      {new Date(s.created_at).toLocaleDateString()} {new Date(s.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }} className="inline-block">
                        <Link
                          to={`/scans/${s.id}`}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-cyan-500/15 border border-slate-700/80 hover:border-cyan-500/40 text-slate-200 hover:text-cyan-300 rounded-lg text-xs font-semibold transition-all shadow-sm"
                        >
                          Inspect <ArrowRight className="h-3 w-3" />
                        </Link>
                      </motion.div>
                    </td>
                  </motion.tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </motion.div>
    </motion.div>
  );
};

import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { ShieldAlert, Search, Filter, ArrowRight, ExternalLink, Flame, AlertTriangle, ShieldCheck, Activity } from "lucide-react";
import { SeverityBadge, StatusBadge } from "../components/ui/SeverityBadge";
import { vulnerabilitiesApi } from "../services/api";

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.05,
      delayChildren: 0.08
    }
  }
};

const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.3, ease: "easeOut" }
  }
};

export const VulnerabilitiesPage: React.FC = () => {
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [search, setSearch] = useState("");

  const fetchVulns = async () => {
    try {
      const params: any = {};
      if (severityFilter !== "all") params.severity = severityFilter;
      if (statusFilter !== "all") params.status = statusFilter;
      if (search) params.search = search;
      const res = await vulnerabilitiesApi.list(params);
      setVulnerabilities(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchVulns();
  }, [severityFilter, statusFilter, search]);

  const critCount = vulnerabilities.filter(v => v.severity === "critical").length;
  const highCount = vulnerabilities.filter(v => v.severity === "high").length;
  const medCount = vulnerabilities.filter(v => v.severity === "medium").length;
  const lowCount = vulnerabilities.filter(v => v.severity === "low").length;

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="space-y-6"
    >
      {/* Header */}
      <motion.div variants={itemVariants} className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-extrabold text-white tracking-tight">Vulnerability Catalog</h1>
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
              {vulnerabilities.length} Total Findings
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            DISCOVERED SECURITY DEFECTS, CVSS ASSESSMENTS, CWE MAPPINGS, AND EVIDENCE TRACES
          </p>
        </div>
      </motion.div>

      {/* Mini Severity Breakdown Strip */}
      <motion.div variants={itemVariants} className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="glass-panel p-3.5 rounded-xl border border-red-500/20 bg-red-950/10 flex items-center justify-between">
          <div>
            <div className="text-[10px] text-red-400/80 uppercase font-mono font-bold">Critical</div>
            <div className="text-xl font-extrabold text-red-400 font-mono mt-0.5">{critCount}</div>
          </div>
          <div className="h-8 w-8 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400">
            <Flame className="h-4 w-4" />
          </div>
        </div>

        <div className="glass-panel p-3.5 rounded-xl border border-amber-500/20 bg-amber-950/10 flex items-center justify-between">
          <div>
            <div className="text-[10px] text-amber-400/80 uppercase font-mono font-bold">High</div>
            <div className="text-xl font-extrabold text-amber-400 font-mono mt-0.5">{highCount}</div>
          </div>
          <div className="h-8 w-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
            <AlertTriangle className="h-4 w-4" />
          </div>
        </div>

        <div className="glass-panel p-3.5 rounded-xl border border-blue-500/20 bg-blue-950/10 flex items-center justify-between">
          <div>
            <div className="text-[10px] text-blue-400/80 uppercase font-mono font-bold">Medium</div>
            <div className="text-xl font-extrabold text-blue-400 font-mono mt-0.5">{medCount}</div>
          </div>
          <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
            <Activity className="h-4 w-4" />
          </div>
        </div>

        <div className="glass-panel p-3.5 rounded-xl border border-emerald-500/20 bg-emerald-950/10 flex items-center justify-between">
          <div>
            <div className="text-[10px] text-emerald-400/80 uppercase font-mono font-bold">Low / Info</div>
            <div className="text-xl font-extrabold text-emerald-400 font-mono mt-0.5">{lowCount}</div>
          </div>
          <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <ShieldCheck className="h-4 w-4" />
          </div>
        </div>
      </motion.div>

      {/* Filter and Search Bar with Animated Sliding Pills */}
      <motion.div variants={itemVariants} className="bg-[#111827]/90 backdrop-blur-md border border-[#1E293B] p-3.5 rounded-2xl flex flex-col md:flex-row items-center justify-between gap-3 shadow-lg">
        <div className="flex items-center gap-2 w-full md:w-80 bg-[#0B0F19] px-3 py-2 rounded-xl border border-[#1E293B] focus-within:border-cyan-500/60 transition-colors">
          <Search className="h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by title, CWE, or URL..."
            className="bg-transparent text-xs text-white focus:outline-none w-full placeholder:text-slate-500"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
          {/* Animated Severity selector */}
          <div className="flex items-center gap-1 bg-[#0B0F19] p-1 rounded-xl border border-[#1E293B]">
            <span className="text-[10px] text-slate-500 uppercase font-mono px-2">Severity:</span>
            {["all", "critical", "high", "medium", "low"].map((sev) => {
              const isActive = severityFilter === sev;
              return (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`relative px-2.5 py-1 rounded-lg text-xs font-semibold capitalize transition-colors duration-200 ${
                    isActive ? "text-cyan-300" : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {isActive && (
                    <motion.div
                      layoutId="activeVulnSeverityPill"
                      className="absolute inset-0 bg-cyan-500/20 border border-cyan-500/40 rounded-lg shadow-sm"
                      transition={{ type: "spring", stiffness: 450, damping: 32 }}
                    />
                  )}
                  <span className="relative z-10">{sev}</span>
                </button>
              );
            })}
          </div>

          {/* Animated Status selector */}
          <div className="flex items-center gap-1 bg-[#0B0F19] p-1 rounded-xl border border-[#1E293B]">
            <span className="text-[10px] text-slate-500 uppercase font-mono px-2">Status:</span>
            {["all", "open", "in_progress", "fixed"].map((st) => {
              const isActive = statusFilter === st;
              return (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`relative px-2.5 py-1 rounded-lg text-xs font-semibold capitalize transition-colors duration-200 ${
                    isActive ? "text-cyan-300" : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {isActive && (
                    <motion.div
                      layoutId="activeVulnStatusPill"
                      className="absolute inset-0 bg-cyan-500/20 border border-cyan-500/40 rounded-lg shadow-sm"
                      transition={{ type: "spring", stiffness: 450, damping: 32 }}
                    />
                  )}
                  <span className="relative z-10">{st.replace("_", " ")}</span>
                </button>
              );
            })}
          </div>
        </div>
      </motion.div>

      {/* Vulnerabilities Table */}
      <motion.div variants={itemVariants} className="bg-[#111827]/80 backdrop-blur-md border border-[#1E293B] rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0B0F19]/90 border-b border-[#1E293B] text-slate-400 uppercase font-mono text-[10px]">
              <tr>
                <th className="py-3.5 px-4">Severity</th>
                <th className="py-3.5 px-4">Vulnerability Title</th>
                <th className="py-3.5 px-4">Affected URL</th>
                <th className="py-3.5 px-4">OWASP Category</th>
                <th className="py-3.5 px-4">CVSS & CWE</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]/60">
              {vulnerabilities.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-slate-500">
                    <ShieldAlert className="h-8 w-8 mx-auto mb-2 text-slate-600 opacity-60" />
                    No matching vulnerabilities found.
                  </td>
                </tr>
              ) : (
                vulnerabilities.map((v, idx) => (
                  <motion.tr
                    key={v.id}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.25, delay: idx * 0.02 }}
                    className="hover:bg-slate-800/30 transition-colors group"
                  >
                    <td className="py-3.5 px-4">
                      <SeverityBadge severity={v.severity} size="sm" />
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-white max-w-sm group-hover:text-cyan-300 transition-colors leading-snug">{v.title}</div>
                      <div className="text-[10px] text-slate-500 mt-0.5 font-mono">{v.scanner_source}</div>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-cyan-400 max-w-xs truncate">
                      {v.affected_url}
                    </td>
                    <td className="py-3.5 px-4 text-slate-300 max-w-xs truncate text-[11px]">
                      {v.owasp_category}
                    </td>
                    <td className="py-3.5 px-4 font-mono">
                      <span className="text-white font-bold">{v.cvss_score || "N/A"}</span>
                      <span className="text-slate-500 block text-[10px]">{v.cwe_id}</span>
                    </td>
                    <td className="py-3.5 px-4">
                      <StatusBadge status={v.status} />
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }} className="inline-block">
                        <Link
                          to={`/vulnerabilities/${v.id}`}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-cyan-500/15 border border-slate-700/80 hover:border-cyan-500/40 text-slate-200 hover:text-cyan-300 rounded-lg text-xs font-semibold transition-all shadow-sm"
                        >
                          Details <ArrowRight className="h-3 w-3" />
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

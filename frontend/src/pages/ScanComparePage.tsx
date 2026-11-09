import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { GitCompare, ArrowRight, CheckCircle2, AlertTriangle, ShieldCheck, TrendingUp, TrendingDown, Layers, Sparkles } from "lucide-react";
import { scansApi } from "../services/api";
import { SeverityBadge } from "../components/ui/SeverityBadge";

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.07,
      delayChildren: 0.1
    }
  }
};

const itemVariants = {
  hidden: { opacity: 0, y: 14 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.35, ease: "easeOut" }
  }
};

export const ScanComparePage: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [scanAId, setScanAId] = useState("");
  const [scanBId, setScanBId] = useState("");
  const [comparison, setComparison] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadScans = async () => {
      try {
        const res = await scansApi.list();
        setScans(res.data);
        if (res.data.length >= 2) {
          setScanAId(res.data[1].id);
          setScanBId(res.data[0].id);
        }
      } catch (err) {
        console.error(err);
      }
    };
    loadScans();
  }, []);

  const handleCompare = async () => {
    if (!scanAId || !scanBId) {
      setError("Please select both Baseline Scan (A) and Target Scan (B).");
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const res = await scansApi.compare(scanAId, scanBId);
      setComparison(res.data);
    } catch (err: any) {
      setError(err.response?.data?.error || "Error generating scan comparison.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="space-y-6"
    >
      <motion.div variants={itemVariants}>
        <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
          <GitCompare className="h-6 w-6 text-cyan-400" /> Historical Scan Comparison
        </h1>
        <p className="text-xs text-slate-400 mt-1 font-mono">
          SIDE-BY-SIDE DIFF ANALYSIS, NEW VULNERABILITIES, RESOLVED DEFECTS, AND POSTURE DELTAS
        </p>
      </motion.div>

      {/* Selectors Bar */}
      <motion.div variants={itemVariants} className="bg-[#111827]/90 backdrop-blur-md border border-[#1E293B] rounded-2xl p-5 space-y-4 shadow-xl">
        <div className="grid md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">BASELINE SCAN A (OLDER)</label>
            <select
              value={scanAId}
              onChange={(e) => setScanAId(e.target.value)}
              className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl px-3 py-2.5 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="">Select Baseline Scan</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.website_name} ({new Date(s.created_at).toLocaleDateString()}) - Score: {s.security_score ?? 'N/A'}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">COMPARISON SCAN B (NEWER)</label>
            <select
              value={scanBId}
              onChange={(e) => setScanBId(e.target.value)}
              className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl px-3 py-2.5 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="">Select Comparison Scan</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.website_name} ({new Date(s.created_at).toLocaleDateString()}) - Score: {s.security_score ?? 'N/A'}
                </option>
              ))}
            </select>
          </div>
        </div>

        {error && (
          <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-400">
            {error}
          </div>
        )}

        <div className="flex justify-end pt-2">
          <motion.button
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            onClick={handleCompare}
            disabled={loading}
            className="px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-cyan-900/30 transition-all flex items-center gap-2 glow-cyan"
          >
            {loading ? (
              <>
                <div className="h-3.5 w-3.5 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                Analyzing Diffs...
              </>
            ) : (
              <>
                Run Side-By-Side Comparison
                <ArrowRight className="h-4 w-4" />
              </>
            )}
          </motion.button>
        </div>
      </motion.div>

      {/* Comparison Results */}
      <AnimatePresence>
        {comparison && (
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 15 }}
            transition={{ duration: 0.4 }}
            className="space-y-6"
          >
            {/* Posture Score Delta Cards */}
            <div className="grid sm:grid-cols-4 gap-4">
              <div className="glass-panel border border-white/5 p-4 rounded-xl">
                <span className="text-[10px] text-slate-400 uppercase font-mono">Score A vs B</span>
                <div className="text-xl font-bold font-mono text-white mt-1">
                  {comparison.score_a} → {comparison.score_b}
                </div>
              </div>

              <div className="glass-panel border border-white/5 p-4 rounded-xl">
                <span className="text-[10px] text-slate-400 uppercase font-mono">Score Delta</span>
                <div className={`text-xl font-bold font-mono flex items-center gap-1 mt-1 ${
                  comparison.score_delta >= 0 ? "text-emerald-400" : "text-red-400"
                }`}>
                  {comparison.score_delta >= 0 ? <TrendingUp className="h-4 w-4" /> : <TrendingDown className="h-4 w-4" />}
                  {comparison.score_delta >= 0 ? `+${comparison.score_delta}` : comparison.score_delta} pts
                </div>
              </div>

              <div className="glass-panel border border-red-500/20 bg-red-950/10 p-4 rounded-xl">
                <span className="text-[10px] text-red-400/80 uppercase font-mono font-bold">New Flaws Introduced</span>
                <div className="text-xl font-bold font-mono text-red-400 mt-1">
                  +{comparison.new_count}
                </div>
              </div>

              <div className="glass-panel border border-emerald-500/20 bg-emerald-950/10 p-4 rounded-xl">
                <span className="text-[10px] text-emerald-400/80 uppercase font-mono font-bold">Defects Remediated</span>
                <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
                  {comparison.resolved_count}
                </div>
              </div>
            </div>

            {/* New Findings List */}
            <div className="bg-[#111827]/90 border border-[#1E293B] rounded-2xl p-5 shadow-lg">
              <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-3">
                <AlertTriangle className="h-4 w-4 text-red-400" /> Newly Detected Vulnerabilities in Scan B ({comparison.new_count})
              </h3>
              {comparison.new_findings.length === 0 ? (
                <div className="text-xs text-slate-500 py-3 font-mono">No new vulnerabilities introduced.</div>
              ) : (
                <div className="space-y-2">
                  {comparison.new_findings.map((f: any, idx: number) => (
                    <motion.div
                      key={f.id}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.05 }}
                      className="p-3 bg-red-500/5 border border-red-500/20 rounded-xl flex items-center justify-between"
                    >
                      <div>
                        <div className="text-xs font-semibold text-white">{f.title}</div>
                        <div className="text-[10px] text-slate-400 font-mono mt-0.5">{f.affected_url}</div>
                      </div>
                      <SeverityBadge severity={f.severity} size="sm" />
                    </motion.div>
                  ))}
                </div>
              )}
            </div>

            {/* Resolved Findings List */}
            <div className="bg-[#111827]/90 border border-[#1E293B] rounded-2xl p-5 shadow-lg">
              <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-3">
                <CheckCircle2 className="h-4 w-4 text-emerald-400" /> Resolved / Remediated Since Scan A ({comparison.resolved_count})
              </h3>
              {comparison.resolved_findings.length === 0 ? (
                <div className="text-xs text-slate-500 py-3 font-mono">No resolved vulnerabilities between these two runs.</div>
              ) : (
                <div className="space-y-2">
                  {comparison.resolved_findings.map((f: any, idx: number) => (
                    <motion.div
                      key={f.id}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.05 }}
                      className="p-3 bg-emerald-500/5 border border-emerald-500/20 rounded-xl flex items-center justify-between"
                    >
                      <div>
                        <div className="text-xs font-semibold text-white line-through opacity-70">{f.title}</div>
                        <div className="text-[10px] text-emerald-400 font-mono mt-0.5">Fixed on {f.affected_url}</div>
                      </div>
                      <span className="px-2.5 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 font-mono font-bold">RESOLVED</span>
                    </motion.div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

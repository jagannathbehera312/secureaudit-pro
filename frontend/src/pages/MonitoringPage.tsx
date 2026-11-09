import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Activity,
  Radar,
  Plus,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RotateCw,
  Trash2,
  ExternalLink,
  Terminal,
  Clock,
  Network,
  Copy,
  Check,
  Code2,
  Server,
  Globe,
  Radio,
  Flame,
  X,
  Sparkles,
  Zap
} from "lucide-react";
import { monitoringApi } from "../services/api";

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

export const MonitoringPage: React.FC = () => {
  const [targets, setTargets] = useState<any[]>([]);
  const [threatEvents, setThreatEvents] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>({
    total_monitored: 0,
    healthy_count: 0,
    active_threats: 0,
    avg_latency_ms: 0
  });
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newTarget, setNewTarget] = useState("");
  const [newName, setNewName] = useState("");
  const [newInterval, setNewInterval] = useState(5);
  const [addingTarget, setAddingTarget] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);
  const [checkingId, setCheckingId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const fetchMonitoringData = async () => {
    try {
      const resTargets = await monitoringApi.list();
      if (resTargets.data) {
        setTargets(resTargets.data.targets || []);
        setSummary(resTargets.data.summary || {});
      }
    } catch (err) {
      console.error("Failed to load targets", err);
    }

    try {
      const resEvents = await monitoringApi.getEvents({ status: "active" });
      if (resEvents.data) {
        setThreatEvents(resEvents.data || []);
      }
    } catch (err) {
      console.error("Failed to load events", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMonitoringData();
    const interval = setInterval(fetchMonitoringData, 12000);
    return () => clearInterval(interval);
  }, []);

  const handleAddTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTarget.trim()) return;
    setAddError(null);
    setAddingTarget(true);

    try {
      const res = await monitoringApi.create({
        target: newTarget.trim(),
        name: newName.trim(),
        interval_minutes: newInterval
      });
      if (res.data) {
        setTargets(prev => [res.data, ...prev.filter(t => t.id !== res.data.id)]);
      }
      setNewTarget("");
      setNewName("");
      setShowAddModal(false);
      fetchMonitoringData();
    } catch (err: any) {
      setAddError(err.response?.data?.error || "Failed to initialize target monitoring.");
    } finally {
      setAddingTarget(false);
    }
  };

  const handleCheckNow = async (id: string) => {
    setCheckingId(id);
    try {
      await monitoringApi.checkNow(id);
      await fetchMonitoringData();
    } catch (err) {
      console.error("Diagnostic check failed", err);
    } finally {
      setCheckingId(null);
    }
  };

  const handleDeleteTarget = async (id: string) => {
    if (!window.confirm("Are you sure you want to stop monitoring this target?")) return;
    try {
      await monitoringApi.delete(id);
      fetchMonitoringData();
    } catch (err) {
      console.error("Failed to remove target", err);
    }
  };

  const handleResolveThreat = async (eventId: string) => {
    try {
      await monitoringApi.resolveEvent(eventId, "Mitigated and confirmed safe by security analyst.");
      fetchMonitoringData();
    } catch (err) {
      console.error("Failed to resolve threat", err);
    }
  };

  const handleCopyCommand = (key: string, text: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedId(key);
    setTimeout(() => setCopiedId(null), 2500);
  };

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="space-y-6"
    >
      {/* Top Header & Quick Action */}
      <motion.div variants={itemVariants} className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
              <Radio className="h-6 w-6 text-cyan-400 animate-pulse" />
              Live Threat & Attack Radar
            </h1>
            <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
              <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
              RADAR ACTIVE
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            REAL-TIME DEFACEMENT DETECTION, PERIMETER BACKDOOR PROBING, DDOS MONITORING & AUTOMATED CONTAINMENT
          </p>
        </div>

        <div className="flex items-center gap-3">
          <motion.button
            whileHover={{ scale: 1.05, rotate: 180 }}
            whileTap={{ scale: 0.95 }}
            transition={{ duration: 0.25 }}
            onClick={fetchMonitoringData}
            className="p-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs border border-slate-700/60 shadow-sm"
            title="Refresh Radar Feed"
          >
            <RotateCw className="h-4 w-4" />
          </motion.button>

          <motion.button
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            onClick={() => setShowAddModal(true)}
            className="px-4 py-2.5 bg-gradient-to-r from-cyan-600 via-teal-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-cyan-900/30 transition-all flex items-center gap-2 glow-cyan"
          >
            <Plus className="h-4 w-4" /> Monitor IP or URL
          </motion.button>
        </div>
      </motion.div>

      {/* High-Level Posture KPI Strip */}
      <motion.div variants={itemVariants} className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="glass-panel p-4 rounded-xl border border-white/5 flex items-center gap-3.5">
          <div className="h-10 w-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
            <Server className="h-5 w-5" />
          </div>
          <div>
            <div className="text-[10px] text-slate-400 uppercase font-mono">Monitored Assets</div>
            <div className="text-xl font-bold text-white font-mono">{summary.total_monitored || 0}</div>
          </div>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-red-500/20 bg-red-950/10 flex items-center gap-3.5">
          <div className="h-10 w-10 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400">
            <Flame className="h-5 w-5" />
          </div>
          <div>
            <div className="text-[10px] text-red-400/80 uppercase font-mono font-bold">Active Threats</div>
            <div className="text-xl font-bold text-red-400 font-mono">{summary.active_threats || 0}</div>
          </div>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-emerald-500/20 bg-emerald-950/10 flex items-center gap-3.5">
          <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <div className="text-[10px] text-emerald-400/80 uppercase font-mono font-bold">Clean & Healthy</div>
            <div className="text-xl font-bold text-emerald-400 font-mono">{summary.healthy_count || 0}</div>
          </div>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-cyan-500/20 bg-cyan-950/10 flex items-center gap-3.5">
          <div className="h-10 w-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Zap className="h-5 w-5" />
          </div>
          <div>
            <div className="text-[10px] text-cyan-400/80 uppercase font-mono font-bold">Avg Ping Latency</div>
            <div className="text-xl font-bold text-cyan-400 font-mono">{summary.avg_latency_ms || 45} ms</div>
          </div>
        </div>
      </motion.div>

      {/* Monitored Assets Grid */}
      <motion.div variants={itemVariants} className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
            <Network className="h-4 w-4 text-cyan-400" /> Monitored Assets Inventory ({targets.length})
          </h2>
          <span className="text-[11px] text-slate-400 font-mono">Continuous Threat Loop: Every 5 Mins</span>
        </div>

        {targets.length === 0 ? (
          <div className="glass-panel border border-[#1E293B] rounded-2xl p-12 text-center text-slate-500">
            <Radio className="h-10 w-10 mx-auto mb-3 text-slate-600 opacity-60" />
            <div className="text-sm font-semibold text-slate-300">No Target Assets Under Active Monitoring</div>
            <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
              Enter any external IP address or website URL. SecureAudit Pro will monitor it continuously for unauthorized defacement, open perimeter ports, and DDoS spikes.
            </p>
            <motion.button
              whileHover={{ scale: 1.04 }}
              whileTap={{ scale: 0.96 }}
              onClick={() => setShowAddModal(true)}
              className="mt-4 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-bold transition-all shadow-md inline-flex items-center gap-1.5"
            >
              <Plus className="h-4 w-4" /> Add First Target
            </motion.button>
          </div>
        ) : (
          <div className="grid md:grid-cols-2 gap-4">
            {targets.map((tgt) => {
              const isChecking = checkingId === tgt.id;
              const hasThreat = tgt.status === "critical" || tgt.threat_score < 70;
              const openPorts = tgt.open_ports || [];

              return (
                <motion.div
                  key={tgt.id}
                  whileHover={{ y: -2 }}
                  className={`glass-panel rounded-2xl p-5 border transition-all shadow-lg ${
                    hasThreat
                      ? "border-red-500/40 bg-red-950/10 shadow-red-950/20"
                      : "border-[#1E293B] hover:border-cyan-500/40"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white text-base">{tgt.name}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                          tgt.is_ip ? "bg-purple-500/20 text-purple-300 border border-purple-500/30" : "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                        }`}>
                          {tgt.is_ip ? "IPV4 ASSET" : "URL ASSET"}
                        </span>
                      </div>
                      <div className="text-xs text-cyan-400 font-mono mt-0.5 flex items-center gap-1.5">
                        <Globe className="h-3.5 w-3.5 text-slate-500" />
                        <span className="font-semibold">{tgt.canonical_url}</span>
                      </div>
                    </div>

                    <span className={`px-2.5 py-1 rounded-lg text-[10px] font-mono font-extrabold uppercase tracking-wider ${
                      tgt.status === "healthy"
                        ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                        : tgt.status === "degraded"
                        ? "bg-amber-500/15 text-amber-300 border border-amber-500/30 animate-pulse"
                        : "bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse"
                    }`}>
                      {tgt.status === "healthy" ? "● SHIELD SECURE" : "▲ THREAT DETECTED"}
                    </span>
                  </div>

                  {/* Telemetry Stats Strip */}
                  <div className="grid grid-cols-3 gap-2 bg-[#0B0F19] p-3 rounded-xl border border-[#1E293B] text-xs font-mono my-3">
                    <div>
                      <span className="text-[10px] text-slate-500 block uppercase">Threat Score</span>
                      <span className={`font-extrabold text-sm ${
                        tgt.threat_score >= 85 ? "text-emerald-400" : tgt.threat_score >= 60 ? "text-amber-400" : "text-red-400"
                      }`}>
                        {tgt.threat_score}/100
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 block uppercase">Socket RTT</span>
                      <span className="text-white font-bold text-sm">{tgt.latency_ms || 45} ms</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 block uppercase">HTTP Status</span>
                      <span className="text-cyan-400 font-bold text-sm">{tgt.http_status || 200}</span>
                    </div>
                  </div>

                  {/* Open Ports Pills */}
                  <div className="mb-4">
                    <div className="text-[10px] text-slate-400 uppercase font-mono mb-1.5 flex items-center justify-between">
                      <span>Discovered Perimeter Ports ({openPorts.length}):</span>
                      {openPorts.some((p: any) => p.risk === "critical") && (
                        <span className="text-red-400 font-bold text-[9px] uppercase">Dangerous Ports Exposed</span>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {openPorts.length === 0 ? (
                        <span className="text-[11px] text-slate-500 font-mono">No open ports exposed.</span>
                      ) : (
                        openPorts.map((p: any) => (
                          <span
                            key={p.port}
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold flex items-center gap-1 ${
                              p.risk === "critical"
                                ? "bg-red-500/20 text-red-300 border border-red-500/40"
                                : p.risk === "high"
                                ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                                : "bg-slate-800 text-slate-300 border border-slate-700"
                            }`}
                            title={p.desc}
                          >
                            {p.port}/tcp ({p.service})
                          </span>
                        ))
                      )}
                    </div>
                  </div>

                  {/* Actions & Diagnostic Trigger */}
                  <div className="flex items-center justify-between pt-3 border-t border-[#1E293B]">
                    <span className="text-[10px] text-slate-500 font-mono">
                      Last Check: {tgt.last_checked_at ? new Date(tgt.last_checked_at).toLocaleTimeString() : "Just now"}
                    </span>

                    <div className="flex items-center gap-2">
                      <motion.button
                        whileHover={{ scale: 1.04 }}
                        whileTap={{ scale: 0.96 }}
                        onClick={() => handleCheckNow(tgt.id)}
                        disabled={isChecking}
                        className="px-3 py-1.5 bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 text-cyan-300 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                      >
                        <Radar className={`h-3.5 w-3.5 ${isChecking ? "animate-spin" : ""}`} />
                        {isChecking ? "Auditing Target..." : "Run Threat Diagnostic"}
                      </motion.button>

                      <button
                        onClick={() => handleDeleteTarget(tgt.id)}
                        className="p-1.5 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                        title="Remove Target"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        )}
      </motion.div>

      {/* Real-Time Attack & Threat Stream Console */}
      <motion.div variants={itemVariants} className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-red-400" /> Real-Time Detected Incidents & Attack Signals ({threatEvents.length})
            </h2>
            {threatEvents.length > 0 && (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-500/20 text-red-400 font-bold border border-red-500/30">
                ACTION REQUIRED
              </span>
            )}
          </div>
          <span className="text-[11px] text-slate-400 font-mono">Auto-Containment Rule Derivation</span>
        </div>

        {threatEvents.length === 0 ? (
          <div className="glass-panel border border-[#1E293B] rounded-2xl p-8 text-center text-slate-500 font-mono text-xs">
            <ShieldCheck className="h-8 w-8 mx-auto mb-2 text-emerald-400 opacity-70" />
            [+] All monitored assets report clean integrity. No active defacements, backdoors, or latency anomalies detected.
          </div>
        ) : (
          <div className="space-y-3">
            {threatEvents.map((ev) => {
              const isCopied = copiedId === ev.id;
              return (
                <motion.div
                  key={ev.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="glass-panel border border-red-500/30 bg-red-950/15 rounded-2xl p-5 shadow-xl space-y-3 glow-cyan"
                >
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-extrabold uppercase bg-red-500/30 text-red-300 border border-red-500/50">
                          {ev.severity} THREAT
                        </span>
                        <span className="text-xs text-slate-400 font-mono">Target: <strong className="text-white">{ev.target}</strong></span>
                        <span className="text-[11px] text-slate-500 font-mono">
                          {new Date(ev.created_at).toLocaleTimeString()} ({new Date(ev.created_at).toLocaleDateString()})
                        </span>
                      </div>
                      <h3 className="text-sm font-bold text-white mt-1.5">{ev.title}</h3>
                      <p className="text-xs text-slate-300 mt-0.5 leading-relaxed">{ev.description}</p>
                    </div>

                    <motion.button
                      whileHover={{ scale: 1.04 }}
                      whileTap={{ scale: 0.96 }}
                      onClick={() => handleResolveThreat(ev.id)}
                      className="px-3 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/40 text-emerald-300 rounded-lg text-xs font-semibold shrink-0 transition-colors cursor-pointer"
                    >
                      <Check className="h-3.5 w-3.5 inline mr-1" /> Mark Mitigated
                    </motion.button>
                  </div>

                  {/* Technical Evidence Trace */}
                  <div className="bg-[#0B0F19] p-3 rounded-xl border border-[#1E293B] font-mono text-[11px] text-slate-300 whitespace-pre-wrap leading-relaxed">
                    <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">Incident Trace:</div>
                    {ev.evidence}
                  </div>

                  {/* Actionable Containment / Mitigation Command Box */}
                  {ev.fix_command && (
                    <div className="bg-[#070A12] border border-cyan-500/40 rounded-xl p-3 font-mono text-xs text-cyan-300 bg-gradient-to-r from-cyan-950/30 to-transparent">
                      <div className="flex items-center justify-between pb-1.5 border-b border-cyan-900/40 mb-2">
                        <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                          <Code2 className="h-3.5 w-3.5" /> Recommended Containment / Mitigation Rule:
                        </span>
                        <motion.button
                          whileHover={{ scale: 1.05 }}
                          whileTap={{ scale: 0.95 }}
                          type="button"
                          onClick={() => handleCopyCommand(ev.id, ev.fix_command)}
                          className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[11px] flex items-center gap-1 cursor-pointer border border-cyan-500/30"
                        >
                          {isCopied ? (
                            <>
                              <Check className="h-3 w-3 text-emerald-400" />
                              <span className="text-emerald-400 font-bold">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="h-3 w-3" />
                              <span>Copy Command</span>
                            </>
                          )}
                        </motion.button>
                      </div>
                      <div className="whitespace-pre-wrap word-break text-[11px] text-slate-200">
                        {ev.fix_command}
                      </div>
                    </div>
                  )}
                </motion.div>
              );
            })}
          </div>
        )}
      </motion.div>

      {/* Add Target Modal */}
      <AnimatePresence>
        {showAddModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setShowAddModal(false)}
              className="fixed inset-0 bg-black/75 backdrop-blur-md"
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 15 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 15 }}
              transition={{ type: "spring", damping: 25, stiffness: 350 }}
              className="relative z-10 bg-[#111827] border border-cyan-500/30 rounded-2xl max-w-md w-full p-6 shadow-2xl glow-cyan"
            >
              <div className="flex items-center justify-between pb-3 border-b border-[#1E293B] mb-4">
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <Radio className="h-5 w-5 text-cyan-400" /> Add Asset to Live Threat Radar
                </h3>
                <button
                  onClick={() => setShowAddModal(false)}
                  className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              {addError && (
                <div className="p-3 mb-4 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-400">
                  {addError}
                </div>
              )}

              <form onSubmit={handleAddTarget} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                    TARGET IP ADDRESS OR URL *
                  </label>
                  <input
                    type="text"
                    required
                    value={newTarget}
                    onChange={(e) => setNewTarget(e.target.value)}
                    placeholder="e.g. 140.245.14.175 or https://mycompany.com"
                    className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl px-3.5 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                  />
                  <div className="flex gap-2 mt-2">
                    <button
                      type="button"
                      onClick={() => setNewTarget("140.245.14.175")}
                      className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 font-mono text-[10px] transition-colors"
                    >
                      Fill Test IP: 140.245.14.175
                    </button>
                    <button
                      type="button"
                      onClick={() => setNewTarget("http://140.245.14.175/")}
                      className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 font-mono text-[10px] transition-colors"
                    >
                      Fill Test URL
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                    FRIENDLY NAME / LABEL
                  </label>
                  <input
                    type="text"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    placeholder="e.g. Production Oracle Cloud VPS"
                    className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl px-3.5 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                    MONITORING CADENCE
                  </label>
                  <div className="grid grid-cols-4 gap-2 bg-[#0B0F19] p-1.5 rounded-xl border border-[#1E293B]">
                    {[
                      { val: 1, label: "1 Min" },
                      { val: 5, label: "5 Min" },
                      { val: 15, label: "15 Min" },
                      { val: 60, label: "1 Hour" }
                    ].map((opt) => (
                      <button
                        key={opt.val}
                        type="button"
                        onClick={() => setNewInterval(opt.val)}
                        className={`py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                          newInterval === opt.val
                            ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40"
                            : "text-slate-400 hover:text-white"
                        }`}
                      >
                        {opt.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="p-3 bg-[#0B0F19] rounded-xl border border-[#1E293B] text-[11px] text-slate-400 space-y-1">
                  <div className="text-white font-semibold font-mono text-xs">Automated Defense Capabilities:</div>
                  <div>✓ Continuous SHA-256 DOM hash integrity & defacement check</div>
                  <div>✓ TCP SYN port probing on database & admin listeners</div>
                  <div>✓ DDoS latency spike & HTTP timeout monitoring</div>
                  <div>✓ Automated incident response CLI command derivation</div>
                </div>

                <div className="flex justify-end gap-3 pt-3 border-t border-[#1E293B]">
                  <button
                    type="button"
                    onClick={() => setShowAddModal(false)}
                    className="px-4 py-2 bg-slate-800 text-slate-300 rounded-xl text-xs font-semibold hover:bg-slate-700"
                  >
                    Cancel
                  </button>
                  <motion.button
                    whileHover={{ scale: 1.03 }}
                    whileTap={{ scale: 0.97 }}
                    type="submit"
                    disabled={addingTarget}
                    className="px-5 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-xl text-xs font-bold shadow-md glow-cyan"
                  >
                    {addingTarget ? "Initializing Baseline..." : "Activate Threat Radar"}
                  </motion.button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

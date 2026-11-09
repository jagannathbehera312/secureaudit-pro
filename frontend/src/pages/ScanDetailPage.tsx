import React, { useState, useEffect, useRef } from "react";
import { useParams, Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  Radar,
  StopCircle,
  RotateCw,
  FileText,
  ShieldAlert,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Layers,
  ArrowRight,
  GitCompare,
  Network,
  ShieldCheck,
  Server,
  AlertCircle,
  Download,
  Copy,
  Check,
  Code2,
  Maximize2,
  Minimize2,
  Sparkles
} from "lucide-react";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { scansApi, vulnerabilitiesApi, reportsApi } from "../services/api";

const SCAN_STAGES_LIST = [
  "Target Validation",
  "Authorization & SSRF Gate",
  "DNS Resolution & Security",
  "Technology Fingerprinting",
  "HTTP Security Analysis",
  "SSL/TLS Assessment",
  "Open Port & Perimeter Discovery",
  "Exposed Resource Detection",
  "OWASP Top 10 Assessment",
  "API Security Assessment",
  "Additional Security Testing",
  "Vulnerability Verification",
  "Result Normalization & Deduplication",
  "Security Score Calculation",
  "Scan Finalization"
];

const OWASP_CATEGORIES = [
  { code: "A01:2025", title: "Broken Access Control" },
  { code: "A02:2025", title: "Security Misconfiguration" },
  { code: "A03:2025", title: "Injection Weaknesses" },
  { code: "A04:2025", title: "Insecure Design" },
  { code: "A05:2025", title: "Security Headers & Cryptography" },
  { code: "A06:2025", title: "Vulnerable Components" },
  { code: "A07:2025", title: "Authentication Failures" },
  { code: "A08:2025", title: "Data Integrity Failures" },
  { code: "A09:2025", title: "Logging & Monitoring Failures" },
  { code: "A10:2025", title: "Server-Side Request Forgery" },
];

export const ScanDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<any | null>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [resultsData, setResultsData] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [terminalExpanded, setTerminalExpanded] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [terminalFilter, setTerminalFilter] = useState<"all" | "commands" | "traces" | "outputs">("all");
  const logEndRef = useRef<HTMLDivElement>(null);

  const handleCopyText = (key: string, text: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedId(key);
    setTimeout(() => setCopiedId(null), 2500);
  };

  const handleDownloadTerminalLog = () => {
    let content = `SECUREAUDIT PRO - PENETRATION TESTING CLI SESSION LOG\n`;
    content += `Target: ${scan?.target_url || "Target"}\n`;
    content += `Domain: ${scan?.domain || "Host"}\n`;
    content += `Profile: ${scan?.profile || "Standard"}\n`;
    content += `Started: ${scan?.created_at || new Date().toISOString()}\n`;
    content += `Status: ${scan?.status}\n`;
    content += `---------------------------------------------------------\n\n`;

    events.forEach((ev) => {
      content += `[${new Date(ev.timestamp).toLocaleTimeString()}] [${ev.stage_name}] (${ev.progress || 0}%)\n`;
      if (ev.command) content += `root@secureaudit-vapt:~# ${ev.command}\n`;
      if (ev.trace) content += `[*] ${ev.trace}\n`;
      if (ev.output) content += `${ev.output}\n`;
      if (ev.message && !ev.command && !ev.output) content += `${ev.message}\n`;
      content += `\n`;
    });

    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `terminal_session_${scan?.domain || "target"}_${scan?.id?.slice(-6)}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const fetchScanState = async () => {
    if (!id) return;
    try {
      const [jobRes, evRes, resRes, vRes] = await Promise.all([
        scansApi.get(id),
        scansApi.getEvents(id),
        scansApi.getResults(id).catch(() => ({ data: null })),
        vulnerabilitiesApi.list({ scan_id: id }).catch(() => ({ data: [] }))
      ]);

      setScan(jobRes.data);
      setEvents(evRes.data.events || []);
      setResultsData(resRes?.data);
      setFindings(vRes?.data || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScanState();
    // Fast real-time polling during active scan
    const interval = setInterval(() => {
      if (scan?.status === "running" || scan?.status === "pending") {
        fetchScanState();
      }
    }, 1200);
    return () => clearInterval(interval);
  }, [id, scan?.status]);

  useEffect(() => {
    if (autoScroll && logEndRef.current && (scan?.status === "running" || scan?.status === "pending")) {
      logEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [events.length, autoScroll]);

  const filteredEvents = events.filter((ev) => {
    if (terminalFilter === "commands") return !!ev.command;
    if (terminalFilter === "traces") return !!ev.trace;
    if (terminalFilter === "outputs") return !!ev.output;
    return true;
  });

  const handleStop = async () => {
    if (!id) return;
    setActionLoading(true);
    try {
      await scansApi.stop(id);
      fetchScanState();
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(false);
    }
  };

  const handleRetry = async () => {
    if (!id) return;
    setActionLoading(true);
    try {
      const res = await scansApi.retry(id);
      window.location.href = `/scans/${res.data.id}`;
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(false);
    }
  };

  const isRunning = scan?.status === "running" || scan?.status === "pending";
  const isCompleted = scan?.status === "completed";

  const handleDownloadPdf = async () => {
    if (!scan?.id) return;
    try {
      const res = await reportsApi.downloadBlob(scan.id, "pdf");
      const blob = new Blob([res.data], { type: "application/pdf" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `SecureAudit_Report_${scan.domain || "target"}_${scan.id.slice(-6)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      window.open(reportsApi.getDownloadUrl(scan.id, "pdf"), "_blank");
    }
  };

  // Discovered open ports
  const openPorts: any[] = scan?.open_ports || resultsData?.open_ports || [];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
      className="space-y-6"
    >
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
              <Radar className={`h-6 w-6 text-cyan-400 ${isRunning ? "animate-spin-slow" : ""}`} />
              Scan Assessment Report
            </h1>
            <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono uppercase font-bold tracking-wider ${
              scan?.status === "completed"
                ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                : isRunning
                ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 animate-pulse"
                : "bg-red-500/10 text-red-400 border border-red-500/30"
            }`}>
              {scan?.status || "Loading..."}
            </span>
          </div>
          <div className="text-xs text-slate-400 mt-1 font-mono flex items-center gap-2">
            <span>TARGET:</span>
            <span className="text-cyan-400 font-bold">{scan?.target_url || "—"}</span>
            <span className="text-slate-600">|</span>
            <span>PROFILE:</span>
            <span className="text-white uppercase">{scan?.profile}</span>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          {scan?.security_score !== null && scan?.security_score !== undefined && (
            <div className="px-3.5 py-1.5 bg-[#111827] border border-[#1E293B] rounded-xl flex items-center gap-2 shadow-sm">
              <span className="text-xs text-slate-400">Security Score:</span>
              <span className={`font-mono font-bold text-sm ${
                scan.security_score >= 80 ? "text-emerald-400" : scan.security_score >= 60 ? "text-amber-400" : "text-red-400"
              }`}>
                {scan.security_score}/100
              </span>
            </div>
          )}

          {isRunning && (
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              onClick={handleStop}
              disabled={actionLoading}
              className="px-4 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 rounded-xl text-xs font-semibold transition-all flex items-center gap-2"
            >
              <StopCircle className="h-4 w-4" /> Terminate Scan
            </motion.button>
          )}

          {!isRunning && (
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              onClick={handleRetry}
              disabled={actionLoading}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700/60 rounded-xl text-xs font-semibold transition-all flex items-center gap-2 shadow-sm"
            >
              <RotateCw className="h-4 w-4" /> Re-run Scan
            </motion.button>
          )}

          {isCompleted && (
            <>
              <motion.button
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                onClick={handleDownloadPdf}
                className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-cyan-900/30 transition-all flex items-center gap-2 cursor-pointer glow-cyan"
              >
                <Download className="h-4 w-4" /> Download PDF Report
              </motion.button>
              <motion.div whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
                <Link
                  to="/reports"
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-xl text-xs font-semibold transition-all flex items-center gap-2 shadow-sm"
                >
                  <FileText className="h-4 w-4" /> Export Options
                </Link>
              </motion.div>
            </>
          )}
        </div>
      </div>

      {/* Progress & Stage Status */}
      <div className="bg-[#111827] border border-[#1E293B] rounded-2xl p-5 space-y-3">
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-white">Current Stage:</span>
            <span className="text-cyan-400 font-mono font-bold">{scan?.current_stage}</span>
          </div>
          <span className="text-white font-mono font-bold text-sm">{scan?.progress || 0}%</span>
        </div>

        {/* Progress Bar */}
        <div className="h-2 w-full bg-[#0B0F19] rounded-full overflow-hidden border border-[#1E293B]">
          <div
            className="h-full bg-gradient-to-r from-cyan-500 via-teal-400 to-blue-500 rounded-full transition-all duration-500"
            style={{ width: `${scan?.progress || 0}%` }}
          />
        </div>

        {/* 15-Stage Progressive Pills */}
        <div className="pt-2 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
          {SCAN_STAGES_LIST.map((stageName, idx) => {
            const stageNum = idx + 1;
            const currentProgress = scan?.progress || 0;
            const stagePctThreshold = (stageNum / 15) * 100;
            const isPassed = currentProgress >= stagePctThreshold;
            const isCurrent = scan?.current_stage?.toLowerCase().includes(stageName.toLowerCase());

            return (
              <div
                key={stageName}
                className={`p-2 rounded-lg border text-[11px] font-mono flex items-center gap-2 transition-all ${
                  isPassed
                    ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                    : isCurrent
                    ? "bg-cyan-500/20 border-cyan-500/40 text-cyan-300 animate-pulse font-bold"
                    : "bg-[#0B0F19] border-[#1E293B] text-slate-500"
                }`}
              >
                <span className={`h-4 w-4 rounded-full flex items-center justify-center text-[9px] ${
                  isPassed ? "bg-emerald-500 text-black font-bold" : isCurrent ? "bg-cyan-400 text-black" : "bg-slate-800 text-slate-400"
                }`}>
                  {isPassed ? "✓" : stageNum}
                </span>
                <span className="truncate">{stageName}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Live Terminal & Discovered Findings Grid */}
      <div className={terminalExpanded ? "space-y-6" : "grid lg:grid-cols-2 gap-6"}>
        {/* Professional Pentest Virtual Terminal */}
        <motion.div
          layout
          transition={{ type: "spring", damping: 30, stiffness: 300 }}
          className={`bg-[#070A12] border border-cyan-500/30 rounded-2xl flex flex-col shadow-2xl glow-cyan overflow-hidden ${
            terminalExpanded ? "h-[620px]" : "h-[460px]"
          }`}
        >
          {/* Terminal Title Bar */}
          <div className="flex items-center justify-between px-4 py-2.5 bg-[#0D1322] border-b border-cyan-950/90 select-none">
            <div className="flex items-center gap-2 min-w-0">
              {/* Unix Window Dots */}
              <div className="flex items-center gap-1.5 mr-2 shrink-0">
                <span className="w-3 h-3 rounded-full bg-red-500/80 inline-block shadow-sm"></span>
                <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block shadow-sm"></span>
                <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block shadow-sm"></span>
              </div>
              <Terminal className="h-4 w-4 text-cyan-400 shrink-0" />
              <span className="text-xs font-mono font-bold text-slate-200 truncate">
                bash — root@secureaudit-vapt:~ (Session: {scan?.domain || "Target"} | PID: {scan?.id?.slice(-6)})
              </span>
            </div>

            {/* Terminal Control Actions */}
            <div className="flex items-center gap-2 shrink-0">
              <select
                value={terminalFilter}
                onChange={(e) => setTerminalFilter(e.target.value as any)}
                className="bg-[#060911] border border-slate-700/80 rounded px-2 py-0.5 text-[10px] font-mono text-cyan-300 focus:outline-none cursor-pointer"
              >
                <option value="all">View: All Stream</option>
                <option value="commands">View: Commands ($)</option>
                <option value="traces">View: Connections (*)</option>
                <option value="outputs">View: Tool Outputs</option>
              </select>

              <button
                type="button"
                onClick={() => setAutoScroll(!autoScroll)}
                className={`px-2 py-0.5 rounded text-[10px] font-mono transition-colors border cursor-pointer ${
                  autoScroll
                    ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                    : "bg-slate-800 border-slate-700 text-slate-400"
                }`}
                title="Toggle Auto-Scroll"
              >
                Scroll: {autoScroll ? "ON" : "OFF"}
              </button>

              <button
                type="button"
                onClick={handleDownloadTerminalLog}
                className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer"
                title="Download Terminal Session Log"
              >
                <Download className="h-3.5 w-3.5 text-cyan-400" />
              </button>

              <button
                type="button"
                onClick={() => setTerminalExpanded(!terminalExpanded)}
                className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer"
                title={terminalExpanded ? "Collapse View" : "Maximize Terminal"}
              >
                {terminalExpanded ? <Minimize2 className="h-3.5 w-3.5 text-amber-400" /> : <Maximize2 className="h-3.5 w-3.5 text-cyan-400" />}
              </button>
            </div>
          </div>

          {/* Terminal Console Output Stream */}
          <div className="flex-1 bg-[#04060C] p-4 overflow-y-auto space-y-2.5 font-mono text-xs select-text selection:bg-cyan-500/30 border-t border-black">
            {/* Session Header Banner */}
            <div className="text-slate-500 pb-2 border-b border-slate-900 text-[11px] leading-relaxed">
              <div className="text-cyan-400 font-bold">[+] SecureAudit Pro Virtual Security Assessment Console v2.0</div>
              <div>[+] Target Host: <span className="text-white font-semibold">{scan?.target_url || "Target"}</span> ({scan?.domain || "Host"})</div>
              <div>[+] Execution Profile: <span className="text-amber-400 uppercase font-semibold">{scan?.profile}</span> | Engine: Multi-Adapter Native + Nuclei + ZAP</div>
              <div>[+] Establishing socket connect & live command execution pipeline...</div>
            </div>

            {filteredEvents.length === 0 ? (
              <div className="text-slate-600 text-center py-16 font-mono text-xs">
                [*] Initializing SecureAudit Pro virtual security terminal...
                <br />
                [*] Awaiting connection handshake with target...
              </div>
            ) : (
              <>
                {filteredEvents.map((ev, index) => (
                  <div key={index} className="space-y-1.5 pt-1">
                    {/* Timestamp & Stage Tag */}
                    <div className="flex items-center gap-2 text-[10px] text-slate-500 select-none">
                      <span>[{new Date(ev.timestamp).toLocaleTimeString([], { hour12: false })}]</span>
                      <span className="text-cyan-400 font-bold">[{ev.stage_name}]</span>
                      <span className="text-slate-600">({ev.progress || 0}%)</span>
                    </div>

                    {/* Exact CLI Command Line */}
                    {ev.command && (
                      <div className="flex items-start gap-2 bg-[#090E1B] px-3 py-1.5 rounded-lg border border-cyan-950 text-xs">
                        <span className="text-emerald-400 font-bold select-none shrink-0 font-mono">root@secureaudit-vapt:~#</span>
                        <span className="text-white font-mono font-bold tracking-wide break-all">{ev.command}</span>
                      </div>
                    )}

                    {/* Server Connection Trace */}
                    {ev.trace && (
                      <div className="text-amber-300 text-[11px] whitespace-pre-wrap pl-3 border-l-2 border-amber-500/60 bg-amber-500/5 py-1.5 rounded-r font-mono leading-relaxed">
                        {ev.trace}
                      </div>
                    )}

                    {/* Exact Command Output */}
                    {ev.output && (
                      <div className="text-slate-200 text-[11px] whitespace-pre-wrap bg-[#070A12] p-3 rounded-lg border border-slate-800/80 leading-relaxed font-mono shadow-inner overflow-x-auto">
                        {ev.output}
                      </div>
                    )}

                    {/* Standard Message if no command or output */}
                    {!ev.command && !ev.output && !ev.trace && (
                      <div className={`text-xs pl-2 ${
                        ev.level === "error" ? "text-red-400" : ev.level === "warning" ? "text-amber-400" : "text-slate-300"
                      }`}>
                        {ev.message}
                      </div>
                    )}
                  </div>
                ))}

                {/* Live Running Prompt Cursor */}
                {isRunning && (
                  <div className="flex items-center gap-2 text-emerald-400 font-mono text-xs pt-3">
                    <span className="text-cyan-400 select-none">root@secureaudit-vapt:~#</span>
                    <span className="text-slate-400 italic text-[11px]">Executing security probes & capturing responses...</span>
                    <span className="w-2 h-4 bg-emerald-400 animate-pulse inline-block align-middle ml-1"></span>
                  </div>
                )}

                <div ref={logEndRef} />
              </>
            )}
          </div>
        </motion.div>

        {/* Discovered Findings Feed */}
        <div className="bg-[#111827] border border-[#1E293B] rounded-2xl p-5 flex flex-col h-[450px]">
          <div className="flex items-center justify-between pb-3 border-b border-[#1E293B] mb-3">
            <h3 className="text-xs font-bold text-white flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-cyan-400" /> DISCOVERED FINDINGS ({findings.length})
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">Real-Time Detections</span>
          </div>

          <div className="flex-1 overflow-y-auto space-y-3 pr-1">
            {findings.length === 0 ? (
              <div className="text-slate-500 text-center py-10 text-xs">
                {isRunning ? "Scanner analyzing targets in real time..." : "No vulnerabilities reported for this run."}
              </div>
            ) : (
              findings.map((f) => {
                const fixText = f.fix_command || (f.remediation ? f.remediation.split("Verification:")[0].trim() : "");
                const isCopied = copiedId === f.id;

                return (
                  <motion.div
                    key={f.id}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    whileHover={{ scale: 1.01 }}
                    className="p-3 bg-[#0B0F19] border border-[#1E293B] hover:border-cyan-500/40 rounded-xl transition-all space-y-2 shadow-sm"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <Link to={`/vulnerabilities/${f.id}`} className="min-w-0 hover:text-cyan-400 group">
                        <div className="text-xs font-semibold text-white group-hover:text-cyan-300 transition-colors truncate">{f.title}</div>
                        <div className="text-[10px] text-slate-400 font-mono mt-0.5 truncate">{f.affected_url}</div>
                      </Link>
                      <SeverityBadge severity={f.severity} size="sm" />
                    </div>

                    {fixText && (
                      <div className="bg-[#070A12] border border-cyan-900/40 rounded-lg p-2 font-mono text-[11px] text-cyan-300">
                        <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1">
                          <span className="text-cyan-400 font-bold uppercase flex items-center gap-1">
                            <Code2 className="h-3 w-3" /> Fix Command / Rule:
                          </span>
                          <motion.button
                            whileHover={{ scale: 1.05 }}
                            whileTap={{ scale: 0.95 }}
                            type="button"
                            onClick={() => handleCopyText(f.id, fixText)}
                            className="px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white flex items-center gap-1 text-[10px] transition-colors cursor-pointer"
                          >
                            {isCopied ? (
                              <>
                                <Check className="h-2.5 w-2.5 text-emerald-400" />
                                <span className="text-emerald-400">Copied</span>
                              </>
                            ) : (
                              <>
                                <Copy className="h-2.5 w-2.5" />
                                <span>Copy</span>
                              </>
                            )}
                          </motion.button>
                        </div>
                        <div className="overflow-x-auto whitespace-pre-wrap word-break leading-tight text-slate-300 text-[10px]">
                          {fixText}
                        </div>
                      </div>
                    )}
                  </motion.div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Network Perimeter & Open Ports Discovery Card */}
      <div className="bg-[#111827] border border-[#1E293B] rounded-2xl p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#1E293B]">
          <div className="flex items-center gap-2">
            <Network className="h-5 w-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">
              Open Ports & Perimeter Services Discovered ({openPorts.length})
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Target Host: <strong className="text-cyan-400">{scan?.domain || "Host"}</strong>
          </span>
        </div>

        {openPorts.length === 0 ? (
          <div className="p-6 text-center text-xs text-slate-500 font-mono bg-[#0B0F19] rounded-xl border border-[#1E293B]">
            {isRunning
              ? "Executing TCP perimeter port probing across web and infrastructure listeners..."
              : "No non-standard open ports exposed on the public perimeter."}
          </div>
        ) : (
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {openPorts.map((p, idx) => {
              const portKey = `port-${p.port}`;
              const isCopied = copiedId === portKey;
              const containCmd = `sudo ufw deny ${p.port}/tcp`;

              return (
                <div
                  key={idx}
                  className="p-3.5 rounded-xl bg-[#0B0F19] border border-[#1E293B] flex flex-col justify-between space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 font-mono text-xs font-bold border border-cyan-500/30">
                      Port {p.port} / TCP
                    </span>
                    <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" title="Port Open" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-white">{p.service}</div>
                    <div className="text-[10px] text-slate-400 mt-0.5 truncate">{p.desc}</div>
                  </div>
                  {p.banner && (
                    <div className="text-[10px] font-mono text-slate-500 truncate bg-slate-900/60 px-2 py-1 rounded border border-slate-800">
                      Banner: {p.banner}
                    </div>
                  )}
                  <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
                    <span className="text-[9px] text-slate-500 font-mono">Firewall:</span>
                    <button
                      type="button"
                      onClick={() => handleCopyText(portKey, containCmd)}
                      className="px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 font-mono text-[9px] flex items-center gap-1 transition-colors"
                      title="Copy firewall containment rule"
                    >
                      <span className="truncate max-w-[120px]">{containCmd}</span>
                      {isCopied ? <Check className="h-2.5 w-2.5 text-emerald-400" /> : <Copy className="h-2.5 w-2.5" />}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* OWASP Top 10:2025 Assessment Breakdown */}
      <div className="bg-[#111827] border border-[#1E293B] rounded-2xl p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#1E293B]">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-purple-400" />
            <h3 className="text-sm font-bold text-white">
              OWASP Top 10:2025 Category Compliance
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">Comprehensive Threat Taxonomy</span>
        </div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {OWASP_CATEGORIES.map((cat) => {
            const relatedFindings = findings.filter((f) =>
              (f.owasp_category || "").toLowerCase().includes(cat.code.toLowerCase().slice(0, 3)) ||
              (f.owasp_category || "").toLowerCase().includes(cat.title.toLowerCase().slice(0, 10))
            );
            const hasIssues = relatedFindings.length > 0;

            return (
              <div
                key={cat.code}
                className={`p-3 rounded-xl border flex flex-col justify-between ${
                  hasIssues
                    ? "bg-red-500/5 border-red-500/30 text-red-300"
                    : "bg-[#0B0F19] border-[#1E293B] text-slate-400"
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono font-bold text-slate-400">{cat.code}</span>
                  {hasIssues ? (
                    <span className="text-[9px] px-1.5 py-0.5 rounded font-mono bg-red-500/20 text-red-400 font-bold border border-red-500/30">
                      {relatedFindings.length} ISSUES
                    </span>
                  ) : (
                    <span className="text-[9px] px-1.5 py-0.5 rounded font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      CLEAN
                    </span>
                  )}
                </div>
                <div className="text-xs font-semibold text-slate-200 mt-1 line-clamp-1">{cat.title}</div>
              </div>
            );
          })}
        </div>
      </div>
    </motion.div>
  );
};

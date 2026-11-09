import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FileText, Download, Plus, Eye, CheckCircle2, AlertCircle, FileCode, Table, ShieldCheck, Sparkles, X } from "lucide-react";
import { reportsApi, scansApi } from "../services/api";

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

export const ReportsPage: React.FC = () => {
  const [reports, setReports] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [format, setFormat] = useState("pdf");
  const [reportType, setReportType] = useState("detailed");
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchReports = async () => {
    try {
      const res = await reportsApi.list();
      setReports(res.data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchReports();
    scansApi.list().then((res) => {
      setScans(res.data.filter((s: any) => s.status === "completed"));
      if (res.data.length > 0) setSelectedScanId(res.data[0].id);
    });
  }, []);

  const handleDownloadReport = async (r: any) => {
    try {
      const res = await reportsApi.downloadBlob(r.id, r.format || 'pdf');
      const blob = new Blob([res.data], {
        type: r.format === 'pdf' ? 'application/pdf' : r.format === 'json' ? 'application/json' : 'text/html'
      });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `SecureAudit_${r.domain || 'report'}_${r.id?.slice(-6)}.${r.format || 'pdf'}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      window.open(reportsApi.getDownloadUrl(r.id, r.format || 'pdf'), '_blank');
    }
  };

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedScanId) return;
    setError(null);
    setGenerating(true);
    try {
      await reportsApi.generate({
        scan_id: selectedScanId,
        format,
        report_type: reportType,
      });
      setShowGenerateModal(false);
      fetchReports();
    } catch (err: any) {
      setError(err.response?.data?.error || "Failed to generate report.");
    } finally {
      setGenerating(false);
    }
  };

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="space-y-6"
    >
      <motion.div variants={itemVariants} className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
            <FileText className="h-6 w-6 text-cyan-400" /> Security Assessment Reports
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            CONSULTING-GRADE PDF DOCUMENTS, EXECUTIVE AUDITS, AND CSV / JSON EXPORTS
          </p>
        </div>

        <motion.button
          whileHover={{ scale: 1.03 }}
          whileTap={{ scale: 0.97 }}
          onClick={() => setShowGenerateModal(true)}
          className="px-4 py-2.5 bg-gradient-to-r from-cyan-600 via-teal-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-cyan-900/30 transition-all flex items-center gap-2 glow-cyan"
        >
          <Plus className="h-4 w-4" /> Generate New Report
        </motion.button>
      </motion.div>

      {/* Report Formats Feature Cards */}
      <motion.div variants={itemVariants} className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="glass-panel p-4 rounded-xl border border-red-500/20 bg-red-950/10">
          <div className="text-red-400 font-mono font-bold text-xs uppercase flex items-center gap-1.5 mb-1">
            <FileText className="h-4 w-4" /> PDF Audit
          </div>
          <p className="text-[11px] text-slate-400">Formal multi-page executive security document with perimeter tables & remediation.</p>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-cyan-500/20 bg-cyan-950/10">
          <div className="text-cyan-400 font-mono font-bold text-xs uppercase flex items-center gap-1.5 mb-1">
            <Eye className="h-4 w-4" /> HTML Interactive
          </div>
          <p className="text-[11px] text-slate-400">Standalone cyber dashboard report with filterable flaw catalog and code snippets.</p>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-emerald-500/20 bg-emerald-950/10">
          <div className="text-emerald-400 font-mono font-bold text-xs uppercase flex items-center gap-1.5 mb-1">
            <FileCode className="h-4 w-4" /> JSON Schema
          </div>
          <p className="text-[11px] text-slate-400">Machine-readable structured schema for SIEM/SOAR and CI/CD automated gates.</p>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-blue-500/20 bg-blue-950/10">
          <div className="text-blue-400 font-mono font-bold text-xs uppercase flex items-center gap-1.5 mb-1">
            <Table className="h-4 w-4" /> CSV Sheet
          </div>
          <p className="text-[11px] text-slate-400">Spreadsheet-ready tabular dump for audit tracking, Jira imports, and compliance.</p>
        </div>
      </motion.div>

      {/* Reports Table */}
      <motion.div variants={itemVariants} className="bg-[#111827]/80 backdrop-blur-md border border-[#1E293B] rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0B0F19]/90 border-b border-[#1E293B] text-slate-400 uppercase font-mono text-[10px]">
              <tr>
                <th className="py-3.5 px-4">Target Website</th>
                <th className="py-3.5 px-4">Type</th>
                <th className="py-3.5 px-4">Format</th>
                <th className="py-3.5 px-4">Findings</th>
                <th className="py-3.5 px-4">Score</th>
                <th className="py-3.5 px-4">Generated Date</th>
                <th className="py-3.5 px-4 text-right">Download</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]/60">
              {reports.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-slate-500 font-mono">
                    <FileText className="h-8 w-8 mx-auto mb-2 text-slate-600 opacity-60" />
                    No reports generated yet. Click "Generate New Report" to create an executive PDF or export.
                  </td>
                </tr>
              ) : (
                reports.map((r, idx) => (
                  <motion.tr
                    key={r.id}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.25, delay: idx * 0.03 }}
                    className="hover:bg-slate-800/30 transition-colors group"
                  >
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-white group-hover:text-cyan-300 transition-colors">{r.website_name}</div>
                      <div className="text-[10px] text-cyan-400 font-mono">{r.domain}</div>
                    </td>
                    <td className="py-3.5 px-4 font-mono capitalize text-slate-300">
                      {r.report_type} Assessment
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        r.format === 'pdf' ? 'bg-red-500/10 text-red-400 border border-red-500/30' :
                        r.format === 'html' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' :
                        'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {r.format}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono font-bold text-white">
                      {r.findings_count}
                    </td>
                    <td className="py-3.5 px-4 font-mono text-cyan-400 font-bold">
                      {r.security_score !== null && r.security_score !== undefined ? `${r.security_score}/100` : "-"}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <motion.button
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                        onClick={() => handleDownloadReport(r)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-cyan-500/15 border border-slate-700 hover:border-cyan-500/30 text-white hover:text-cyan-300 rounded-lg text-xs font-semibold transition-all cursor-pointer shadow-sm"
                      >
                        <Download className="h-3.5 w-3.5" /> Download
                      </motion.button>
                    </td>
                  </motion.tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </motion.div>

      {/* Generate Report Modal with AnimatePresence */}
      <AnimatePresence>
        {showGenerateModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setShowGenerateModal(false)}
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
                  <FileText className="h-5 w-5 text-cyan-400" /> Generate Assessment Report
                </h3>
                <button
                  onClick={() => setShowGenerateModal(false)}
                  className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              {error && (
                <div className="p-3 mb-4 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-400">
                  {error}
                </div>
              )}

              <form onSubmit={handleGenerate} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">SELECT COMPLETED SCAN</label>
                  <select
                    value={selectedScanId}
                    onChange={(e) => setSelectedScanId(e.target.value)}
                    className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    {scans.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.website_name} ({s.profile}) - Score: {s.security_score ?? 'N/A'}/100
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">EXPORT FORMAT</label>
                  <div className="grid grid-cols-4 gap-2 bg-[#0B0F19] p-1.5 rounded-xl border border-[#1E293B]">
                    {["pdf", "html", "json", "csv"].map((f) => {
                      const isActive = format === f;
                      return (
                        <button
                          key={f}
                          type="button"
                          onClick={() => setFormat(f)}
                          className={`relative py-2 rounded-lg text-xs font-mono uppercase font-bold transition-colors ${
                            isActive ? "text-cyan-300" : "text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          {isActive && (
                            <motion.div
                              layoutId="activeModalReportFormat"
                              className="absolute inset-0 bg-cyan-500/20 border border-cyan-500/40 rounded-lg shadow-sm"
                              transition={{ type: "spring", stiffness: 450, damping: 32 }}
                            />
                          )}
                          <span className="relative z-10">{f}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">REPORT SCOPE</label>
                  <div className="grid grid-cols-2 gap-2 bg-[#0B0F19] p-1.5 rounded-xl border border-[#1E293B]">
                    {[
                      { id: "detailed", label: "Detailed Technical" },
                      { id: "executive", label: "Executive Summary" }
                    ].map((scope) => {
                      const isActive = reportType === scope.id;
                      return (
                        <button
                          key={scope.id}
                          type="button"
                          onClick={() => setReportType(scope.id)}
                          className={`relative py-2 px-3 rounded-lg text-xs font-semibold transition-colors ${
                            isActive ? "text-cyan-300" : "text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          {isActive && (
                            <motion.div
                              layoutId="activeModalReportScope"
                              className="absolute inset-0 bg-cyan-500/20 border border-cyan-500/40 rounded-lg shadow-sm"
                              transition={{ type: "spring", stiffness: 450, damping: 32 }}
                            />
                          )}
                          <span className="relative z-10">{scope.label}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="flex justify-end gap-3 pt-4 border-t border-[#1E293B]">
                  <button
                    type="button"
                    onClick={() => setShowGenerateModal(false)}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold transition-colors"
                  >
                    Cancel
                  </button>
                  <motion.button
                    whileHover={{ scale: 1.03 }}
                    whileTap={{ scale: 0.97 }}
                    type="submit"
                    disabled={generating}
                    className="px-5 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-xl text-xs font-bold shadow-md glow-cyan"
                  >
                    {generating ? "Compiling Document..." : "Generate Document"}
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

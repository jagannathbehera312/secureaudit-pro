import React from "react";
import { VulnerabilitySeverity, VulnerabilityStatus } from "../../types";

export const SeverityBadge: React.FC<{ severity: VulnerabilitySeverity; size?: "sm" | "md" }> = ({
  severity,
  size = "md",
}) => {
  const sev = (severity || "info").toLowerCase();
  
  const styles: Record<string, { bg: string; text: string; dot: string; border: string }> = {
    critical: { bg: "bg-red-500/10", text: "text-red-400", dot: "bg-red-500", border: "border-red-500/30" },
    high: { bg: "bg-orange-500/10", text: "text-orange-400", dot: "bg-orange-500", border: "border-orange-500/30" },
    medium: { bg: "bg-amber-500/10", text: "text-amber-400", dot: "bg-amber-500", border: "border-amber-500/30" },
    low: { bg: "bg-emerald-500/10", text: "text-emerald-400", dot: "bg-emerald-500", border: "border-emerald-500/30" },
    info: { bg: "bg-cyan-500/10", text: "text-cyan-400", dot: "bg-cyan-500", border: "border-cyan-500/30" },
  };

  const style = styles[sev] || styles.info;
  const padding = size === "sm" ? "px-2 py-0.5 text-xs" : "px-2.5 py-1 text-xs font-semibold";

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border ${style.bg} ${style.text} ${style.border} ${padding}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${style.dot} animate-pulse`} />
      <span className="uppercase tracking-wider">{sev}</span>
    </span>
  );
};

export const StatusBadge: React.FC<{ status: VulnerabilityStatus | string }> = ({ status }) => {
  const s = (status || "open").toLowerCase();

  const styles: Record<string, { bg: string; text: string; border: string }> = {
    open: { bg: "bg-red-950/40", text: "text-red-300", border: "border-red-800/40" },
    confirmed: { bg: "bg-purple-950/40", text: "text-purple-300", border: "border-purple-800/40" },
    in_progress: { bg: "bg-amber-950/40", text: "text-amber-300", border: "border-amber-800/40" },
    fixed: { bg: "bg-emerald-950/40", text: "text-emerald-300", border: "border-emerald-800/40" },
    accepted_risk: { bg: "bg-slate-800/40", text: "text-slate-300", border: "border-slate-700/40" },
    false_positive: { bg: "bg-gray-800/40", text: "text-gray-400", border: "border-gray-700/40" },
    reopened: { bg: "bg-rose-950/40", text: "text-rose-300", border: "border-rose-800/40" },
  };

  const style = styles[s] || styles.open;
  const label = s.replace("_", " ");

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${style.bg} ${style.text} ${style.border} capitalize`}>
      {label}
    </span>
  );
};

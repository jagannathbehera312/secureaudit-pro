import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Wrench, CheckCircle2, Clock, AlertTriangle, ArrowRight, Check } from "lucide-react";
import { remediationApi } from "../services/api";
import { SeverityBadge } from "../components/ui/SeverityBadge";

export const RemediationPage: React.FC = () => {
  const [tasks, setTasks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("all");

  const fetchTasks = async () => {
    try {
      const params: any = {};
      if (statusFilter !== "all") params.status = statusFilter;
      const res = await remediationApi.list(params);
      setTasks(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTasks();
  }, [statusFilter]);

  const handleUpdateStatus = async (taskId: string, newStatus: string) => {
    try {
      await remediationApi.update(taskId, { status: newStatus });
      fetchTasks();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
            <Wrench className="h-6 w-6 text-cyan-400" /> Remediation Management
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            VULNERABILITY FIX TICKETS, ASSIGNED DEVELOPERS, RETEST VERIFICATION, AND RESOLUTION LOGS
          </p>
        </div>

        {/* Status Filter Tabs */}
        <div className="flex items-center gap-1.5 bg-[#111827] p-1.5 rounded-xl border border-[#1E293B]">
          {["all", "in_progress", "resolved", "verified"].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3 py-1 rounded-lg text-xs font-semibold capitalize transition-all ${
                statusFilter === st
                  ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
                  : "text-slate-400 hover:bg-slate-800"
              }`}
            >
              {st.replace("_", " ")}
            </button>
          ))}
        </div>
      </div>

      {/* Task List */}
      <div className="grid md:grid-cols-2 gap-4">
        {tasks.length === 0 ? (
          <div className="col-span-2 bg-[#111827] border border-[#1E293B] rounded-2xl p-12 text-center text-xs text-slate-500 font-mono">
            No remediation tasks found in this status category.
          </div>
        ) : (
          tasks.map((task) => (
            <div key={task.id} className="bg-[#111827] border border-[#1E293B] rounded-2xl p-5 flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <SeverityBadge severity={task.severity} size="sm" />
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase ${
                    task.status === "verified" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30" :
                    task.status === "resolved" ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30" :
                    "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                  }`}>
                    {task.status.replace("_", " ")}
                  </span>
                </div>

                <h3 className="text-sm font-bold text-white tracking-wide">{task.vuln_title}</h3>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">{task.notes || "No notes provided."}</p>

                <div className="mt-3 grid grid-cols-2 gap-2 text-[11px] bg-[#0B0F19] p-2.5 rounded-xl border border-[#1E293B] font-mono">
                  <div>
                    <span className="text-slate-500 block text-[9px] uppercase">Assignee</span>
                    <span className="text-slate-300 truncate block">{task.assigned_to}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[9px] uppercase">Deadline</span>
                    <span className="text-amber-400">{task.due_date || "Open"}</span>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="pt-3 border-t border-[#1E293B] flex items-center justify-between">
                <Link
                  to={`/vulnerabilities/${task.vulnerability_id}`}
                  className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold"
                >
                  Inspect Finding <ArrowRight className="h-3 w-3" />
                </Link>

                <div className="flex items-center gap-2">
                  {task.status !== "resolved" && task.status !== "verified" && (
                    <button
                      onClick={() => handleUpdateStatus(task.id, "resolved")}
                      className="px-2.5 py-1 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 rounded-lg text-xs font-semibold transition-colors"
                    >
                      Mark Resolved
                    </button>
                  )}
                  {task.status !== "verified" && (
                    <button
                      onClick={() => handleUpdateStatus(task.id, "verified")}
                      className="px-2.5 py-1 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 rounded-lg text-xs font-semibold flex items-center gap-1 transition-colors"
                    >
                      <Check className="h-3 w-3" /> Verify & Close
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

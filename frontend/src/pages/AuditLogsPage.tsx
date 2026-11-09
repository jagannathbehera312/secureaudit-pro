import React, { useState, useEffect } from "react";
import { ScrollText, ArrowLeft, Search } from "lucide-react";
import { Link } from "react-router-dom";
import { adminApi } from "../services/api";

export const AuditLogsPage: React.FC = () => {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  useEffect(() => {
    adminApi.getAuditLogs().then((res) => {
      setLogs(res.data);
      setLoading(false);
    });
  }, []);

  const filteredLogs = logs.filter((l) => {
    if (search && !l.action?.toLowerCase().includes(search.toLowerCase()) && !l.user_id?.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
            <ScrollText className="h-6 w-6 text-cyan-400" /> Platform Security Audit Trail
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            IMMUTABLE RECORDS OF ACCESS ATTEMPTS, DOMAIN AUTHORIZATIONS, AND SCAN INITIATIONS
          </p>
        </div>
        <Link
          to="/admin"
          className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold flex items-center gap-2 transition-colors self-start sm:self-auto"
        >
          <ArrowLeft className="h-4 w-4" /> Administration
        </Link>
      </div>

      <div className="bg-[#111827] border border-[#1E293B] rounded-2xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-[#1E293B]">
          <div className="flex items-center gap-2 max-w-sm bg-[#0B0F19] px-3 py-1.5 rounded-lg border border-[#1E293B]">
            <Search className="h-4 w-4 text-slate-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search audit actions..."
              className="bg-transparent text-xs text-white focus:outline-none w-full"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#0B0F19] border-b border-[#1E293B] text-slate-400 uppercase text-[10px]">
              <tr>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Action Event</th>
                <th className="py-3 px-4">User ID</th>
                <th className="py-3 px-4">Client IP</th>
                <th className="py-3 px-4">Payload Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="text-center py-8 text-slate-500 font-sans">
                    No matching audit records found.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/20 transition-colors">
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap text-[11px]">
                      {new Date(log.created_at).toISOString().replace("T", " ").slice(0, 19)}
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-cyan-400 font-bold">{log.action}</span>
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      {log.user_id?.slice(-8) || "system"}
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {log.ip_address || "127.0.0.1"}
                    </td>
                    <td className="py-3 px-4 text-slate-400 max-w-xs truncate text-[10px]">
                      {JSON.stringify(log.details)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

import React from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import {
  ShieldAlert,
  LayoutDashboard,
  Globe,
  Radar,
  FileText,
  GitCompare,
  Wrench,
  Settings,
  ScrollText,
  LogOut,
  Bell,
  PlayCircle,
  Radio
} from "lucide-react";
import { useAuth } from "../../contexts/AuthContext";

export const Sidebar: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const navItems = [
    { name: "Overview", path: "/dashboard", icon: LayoutDashboard },
    { name: "Live Attack Radar", path: "/monitoring", icon: Radio, isLive: true },
    { name: "Websites & Assets", path: "/websites", icon: Globe },
    { name: "Launch Scan", path: "/scans/new", icon: PlayCircle },
    { name: "Scan History", path: "/scans", icon: Radar },
    { name: "Scan Comparison", path: "/scans/compare", icon: GitCompare },
    { name: "Vulnerabilities", path: "/vulnerabilities", icon: ShieldAlert },
    { name: "Remediation", path: "/remediation", icon: Wrench },
    { name: "Security Reports", path: "/reports", icon: FileText },
    { name: "Administration", path: "/admin", icon: Settings },
    { name: "Audit Logs", path: "/admin/audit-logs", icon: ScrollText },
  ];

  return (
    <aside className="w-64 bg-[#070A12]/95 backdrop-blur-xl border-r border-[#1E293B]/80 flex flex-col justify-between shrink-0 h-screen sticky top-0 select-none z-30">
      {/* Brand Header */}
      <div>
        <div className="h-16 px-6 flex items-center gap-3 border-b border-[#1E293B]/80">
          <motion.div
            whileHover={{ scale: 1.08, rotate: [0, -5, 5, 0] }}
            whileTap={{ scale: 0.95 }}
            className="h-9 w-9 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/10 border border-cyan-500/40 flex items-center justify-center glow-cyan shadow-lg cursor-pointer"
          >
            <ShieldAlert className="h-5 w-5 text-cyan-400" />
          </motion.div>
          <div>
            <div className="text-base font-extrabold text-white tracking-wide flex items-center gap-1.5">
              SecureAudit <span className="text-[10px] bg-gradient-to-r from-cyan-500 to-blue-500 text-black px-1.5 py-0.5 rounded font-mono font-black shadow-sm">PRO</span>
            </div>
            <div className="text-[9px] text-cyan-400/80 tracking-widest font-mono font-semibold">ENTERPRISE VAPT</div>
          </div>
        </div>

        {/* Navigation Menu */}
        <nav className="p-3 space-y-1 mt-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `relative flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-sm font-medium transition-colors ${
                    isActive
                      ? "text-cyan-300 font-semibold"
                      : "text-slate-400 hover:text-slate-100 hover:bg-slate-800/30"
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    {isActive && (
                      <motion.div
                        layoutId="activeSidebarIndicator"
                        className="absolute inset-0 bg-gradient-to-r from-cyan-500/15 to-blue-500/5 border border-cyan-500/30 rounded-xl glow-cyan shadow-sm"
                        transition={{ type: "spring", stiffness: 380, damping: 30 }}
                      />
                    )}
                    <Icon className={`h-4 w-4 shrink-0 relative z-10 transition-transform ${isActive ? "text-cyan-400 scale-110" : ""}`} />
                    <span className="relative z-10">{item.name}</span>
                    {item.isLive && (
                      <span className="ml-auto relative z-10 px-1.5 py-0.5 rounded font-mono text-[9px] bg-red-500/20 text-red-400 font-bold border border-red-500/30 flex items-center gap-1">
                        <span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-ping" />
                        LIVE
                      </span>
                    )}
                  </>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* User Section */}
      <div className="p-4 border-t border-[#1E293B]/80 bg-[#0B0F19]/60">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="h-8 w-8 rounded-full bg-gradient-to-tr from-cyan-600 to-blue-600 border border-cyan-400/30 flex items-center justify-center text-xs font-bold text-white shadow-md shrink-0">
              {user?.first_name?.[0] || user?.email?.[0] || "U"}
            </div>
            <div className="min-w-0">
              <div className="text-xs font-semibold text-white truncate">
                {user?.first_name ? `${user.first_name} ${user.last_name}` : user?.email}
              </div>
              <div className="text-[10px] text-cyan-400 uppercase tracking-wider font-mono">
                {user?.role?.replace("_", " ")}
              </div>
            </div>
          </div>
          <motion.button
            whileHover={{ scale: 1.15, rotate: 10 }}
            whileTap={{ scale: 0.9 }}
            onClick={logout}
            title="Log Out"
            className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors cursor-pointer"
          >
            <LogOut className="h-4 w-4" />
          </motion.button>
        </div>
      </div>
    </aside>
  );
};

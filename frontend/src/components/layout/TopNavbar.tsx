import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Bell, Search, ShieldCheck, Plus, Check, KeyRound } from "lucide-react";
import { notificationsApi } from "../../services/api";
import { ChangePasswordModal } from "../auth/ChangePasswordModal";

export const TopNavbar: React.FC = () => {
  const navigate = useNavigate();
  const [notifications, setNotifications] = useState<any[]>([]);
  const [showNotifications, setShowNotifications] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [showPasswordModal, setShowPasswordModal] = useState(false);

  useEffect(() => {
    const fetchNotifs = async () => {
      try {
        const res = await notificationsApi.list();
        setNotifications(res.data);
        setUnreadCount(res.data.filter((n: any) => !n.read).length);
      } catch (err) {
        // silent
      }
    };
    fetchNotifs();
    const interval = setInterval(fetchNotifs, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleMarkRead = async (id: string) => {
    try {
      await notificationsApi.markRead(id);
      setNotifications(prev => prev.map(n => n.id === id ? { ...n, read: true } : n));
      setUnreadCount(prev => Math.max(0, prev - 1));
    } catch (e) {
      // silent
    }
  };

  return (
    <header className="h-16 border-b border-[#1E293B]/80 bg-[#070A12]/80 backdrop-blur-xl px-6 flex items-center justify-between sticky top-0 z-40 select-none">
      {/* Left: Status Pill */}
      <div className="flex items-center gap-4">
        <motion.div
          initial={{ opacity: 0, x: -10 }}
          animate={{ opacity: 1, x: 0 }}
          className="flex items-center gap-2 px-3 py-1 bg-emerald-500/10 border border-emerald-500/30 rounded-full text-xs font-medium text-emerald-400 glow-emerald"
        >
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="font-mono tracking-wider font-semibold text-[11px]">VAPT ENGINES ONLINE</span>
        </motion.div>
      </div>

      {/* Right: Actions, Notifications & Profile */}
      <div className="flex items-center gap-3">
        <Link to="/scans/new">
          <motion.button
            whileHover={{ scale: 1.04, boxShadow: "0 0 20px rgba(6, 182, 212, 0.4)" }}
            whileTap={{ scale: 0.96 }}
            className="flex items-center gap-1.5 px-3.5 py-1.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold tracking-wide shadow-md transition-all cursor-pointer"
          >
            <Plus className="h-3.5 w-3.5" />
            New Security Scan
          </motion.button>
        </Link>

        {/* Notifications Popover */}
        <div className="relative">
          <motion.button
            whileHover={{ scale: 1.08 }}
            whileTap={{ scale: 0.92 }}
            onClick={() => setShowNotifications(!showNotifications)}
            className="p-2 text-slate-400 hover:text-white hover:bg-slate-800/60 rounded-xl relative transition-colors cursor-pointer"
          >
            <Bell className="h-4 w-4" />
            {unreadCount > 0 && (
              <span className="absolute top-1.5 right-1.5 h-2 w-2 bg-cyan-400 rounded-full animate-ping" />
            )}
          </motion.button>

          <AnimatePresence>
            {showNotifications && (
              <motion.div
                initial={{ opacity: 0, scale: 0.95, y: -10 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95, y: -10 }}
                transition={{ duration: 0.18, ease: "easeOut" }}
                className="absolute right-0 mt-2 w-80 bg-[#0C101B] border border-cyan-900/40 rounded-2xl shadow-2xl z-50 p-3.5 backdrop-blur-2xl"
              >
                <div className="flex items-center justify-between pb-2 mb-2 border-b border-[#1E293B]">
                  <span className="text-xs font-bold text-white uppercase tracking-wider font-mono">Alerts & Telemetry</span>
                  <span className="text-[10px] text-cyan-400 font-mono bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">{unreadCount} unread</span>
                </div>
                <div className="max-h-64 overflow-y-auto space-y-2 pr-1">
                  {notifications.length === 0 ? (
                    <div className="text-xs text-slate-400 text-center py-4 font-mono">No pending security alerts</div>
                  ) : (
                    notifications.map((n) => (
                      <motion.div
                        key={n.id}
                        whileHover={{ scale: 1.01, x: 2 }}
                        onClick={() => !n.read && handleMarkRead(n.id)}
                        className={`p-2.5 rounded-xl text-xs cursor-pointer transition-colors ${
                          n.read ? "bg-slate-900/40 text-slate-400" : "bg-cyan-500/10 border border-cyan-500/30 text-slate-200"
                        }`}
                      >
                        <div className="font-semibold text-white mb-0.5">{n.title}</div>
                        <div className="text-[11px] text-slate-400 line-clamp-2">{n.message}</div>
                      </motion.div>
                    ))
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Change Password Quick Action */}
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={() => setShowPasswordModal(true)}
          title="Change Account Password"
          className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-slate-300 hover:text-cyan-400 hover:bg-slate-800/60 rounded-xl transition-colors cursor-pointer border border-slate-800 hover:border-cyan-500/30"
        >
          <KeyRound className="h-3.5 w-3.5 text-cyan-400" />
          <span className="hidden md:inline font-medium">Change Password</span>
        </motion.button>

        <Link
          to="/profile"
          className="flex items-center gap-2 pl-3 border-l border-[#1E293B] text-xs font-medium text-slate-300 hover:text-cyan-400 transition-colors"
        >
          <div className="h-7 w-7 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 text-xs font-bold">
            <ShieldCheck className="h-4 w-4" />
          </div>
          <span className="hidden sm:inline">Security Profile</span>
        </Link>
      </div>

      {/* Global Change Password Modal */}
      <ChangePasswordModal
        isOpen={showPasswordModal}
        onClose={() => setShowPasswordModal(false)}
      />
    </header>
  );
};

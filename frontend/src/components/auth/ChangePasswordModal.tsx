import React, { useState } from "react";
import { createPortal } from "react-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  Lock,
  KeyRound,
  Eye,
  EyeOff,
  CheckCircle2,
  AlertCircle,
  X,
  ShieldCheck,
  Loader2,
} from "lucide-react";
import { authApi } from "../../services/api";

interface ChangePasswordModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ChangePasswordModal: React.FC<ChangePasswordModalProps> = ({
  isOpen,
  onClose,
}) => {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Password strength calculation
  const getPasswordStrength = (pass: string) => {
    if (!pass) return { score: 0, label: "Empty", color: "bg-slate-700" };
    let score = 0;
    if (pass.length >= 8) score += 1;
    if (pass.length >= 12) score += 1;
    if (/[A-Z]/.test(pass) && /[a-z]/.test(pass)) score += 1;
    if (/[0-9]/.test(pass)) score += 1;
    if (/[^A-Za-z0-9]/.test(pass)) score += 1;

    if (score <= 2) return { score, label: "Weak", color: "bg-red-500" };
    if (score === 3) return { score, label: "Fair", color: "bg-amber-500" };
    if (score === 4) return { score, label: "Strong", color: "bg-cyan-500" };
    return { score, label: "Enterprise Grade", color: "bg-emerald-500" };
  };

  const strength = getPasswordStrength(newPassword);

  const resetForm = () => {
    setCurrentPassword("");
    setNewPassword("");
    setConfirmPassword("");
    setError(null);
    setSuccess(null);
  };

  const handleClose = () => {
    resetForm();
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    // Client-side validations
    if (!currentPassword) {
      setError("Please enter your current account password.");
      return;
    }

    if (!newPassword) {
      setError("Please enter your new password.");
      return;
    }

    if (newPassword.length < 8) {
      setError("New password must be at least 8 characters long.");
      return;
    }

    if (!confirmPassword) {
      setError("Please confirm your new password.");
      return;
    }

    if (newPassword !== confirmPassword) {
      setError("New password and confirm password do not match.");
      return;
    }

    if (currentPassword === newPassword) {
      setError("New password cannot be identical to your current password.");
      return;
    }

    setLoading(true);
    try {
      const res = await authApi.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setSuccess(res.data.message || "Password changed successfully!");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setTimeout(() => {
        handleClose();
      }, 1800);
    } catch (err: any) {
      const apiErr =
        err.response?.data?.error ||
        err.response?.data?.message ||
        "Failed to change password. Please check your current password.";
      setError(apiErr);
    } finally {
      setLoading(false);
    }
  };

  // Mount directly to document.body to break free from any parent backdrop-filter or containing blocks
  return createPortal(
    <AnimatePresence>
      {isOpen && (
        <div
          className="fixed inset-0 z-[9999] flex items-center justify-center p-3 sm:p-4 bg-black/80 backdrop-blur-md overflow-y-auto"
          onClick={handleClose}
        >
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 15 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 15 }}
            transition={{ duration: 0.2 }}
            onClick={(e) => e.stopPropagation()}
            className="relative w-full max-w-md max-h-[92vh] overflow-y-auto bg-[#0C101B] border border-cyan-500/30 rounded-2xl shadow-2xl p-5 sm:p-6 glow-cyan my-auto z-10"
          >
            {/* Header */}
            <div className="flex items-center justify-between pb-3.5 border-b border-[#1E293B]">
              <div className="flex items-center gap-2.5">
                <div className="h-9 w-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
                  <KeyRound className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white tracking-wide">
                    Change Password
                  </h3>
                  <p className="text-[10px] text-slate-400 font-mono">
                    SECURITY POLICY COMPLIANCE
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={handleClose}
                className="text-slate-400 hover:text-white p-2 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
                title="Close"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-4 mt-4">
              {/* Current Password */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  CURRENT PASSWORD
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-3 h-4 w-4 text-slate-500" />
                  <input
                    type={showCurrent ? "text" : "password"}
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl pl-9 pr-10 py-2.5 text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
                    placeholder="Enter current password"
                  />
                  <button
                    type="button"
                    onClick={() => setShowCurrent(!showCurrent)}
                    className="absolute right-3 top-3 text-slate-500 hover:text-slate-300 p-0.5 cursor-pointer"
                  >
                    {showCurrent ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              {/* New Password */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="block text-xs font-semibold text-slate-300 font-mono">
                    NEW PASSWORD
                  </label>
                  {newPassword && (
                    <span className="text-[10px] font-mono text-slate-400">
                      Strength: <span className="font-bold text-cyan-400">{strength.label}</span>
                    </span>
                  )}
                </div>
                <div className="relative">
                  <KeyRound className="absolute left-3 top-3 h-4 w-4 text-slate-500" />
                  <input
                    type={showNew ? "text" : "password"}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl pl-9 pr-10 py-2.5 text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
                    placeholder="Minimum 8 characters"
                  />
                  <button
                    type="button"
                    onClick={() => setShowNew(!showNew)}
                    className="absolute right-3 top-3 text-slate-500 hover:text-slate-300 p-0.5 cursor-pointer"
                  >
                    {showNew ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>

                {/* Strength Bar */}
                {newPassword && (
                  <div className="mt-2 space-y-1">
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden flex">
                      <div
                        className={`h-full transition-all duration-300 ${strength.color}`}
                        style={{ width: `${(strength.score / 5) * 100}%` }}
                      />
                    </div>
                    <div className="flex flex-wrap items-center gap-2 sm:gap-3 text-[10px] text-slate-400 font-mono">
                      <span className={newPassword.length >= 8 ? "text-emerald-400" : "text-slate-500"}>
                        ✓ 8+ chars
                      </span>
                      <span className={/[0-9]/.test(newPassword) ? "text-emerald-400" : "text-slate-500"}>
                        ✓ Number
                      </span>
                      <span className={/[A-Z]/.test(newPassword) ? "text-emerald-400" : "text-slate-500"}>
                        ✓ Uppercase
                      </span>
                      <span className={/[^A-Za-z0-9]/.test(newPassword) ? "text-emerald-400" : "text-slate-500"}>
                        ✓ Symbol
                      </span>
                    </div>
                  </div>
                )}
              </div>

              {/* Confirm New Password */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  CONFIRM NEW PASSWORD
                </label>
                <div className="relative">
                  <ShieldCheck className="absolute left-3 top-3 h-4 w-4 text-slate-500" />
                  <input
                    type={showConfirm ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className={`w-full bg-[#0B0F19] border rounded-xl pl-9 pr-10 py-2.5 text-sm text-white focus:outline-none transition-colors ${
                      confirmPassword && confirmPassword !== newPassword
                        ? "border-red-500 focus:border-red-500"
                        : "border-[#1E293B] focus:border-cyan-500"
                    }`}
                    placeholder="Re-type new password"
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirm(!showConfirm)}
                    className="absolute right-3 top-3 text-slate-500 hover:text-slate-300 p-0.5 cursor-pointer"
                  >
                    {showConfirm ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
                {confirmPassword && confirmPassword !== newPassword && (
                  <p className="mt-1 text-[11px] text-red-400">Passwords do not match.</p>
                )}
                {confirmPassword && confirmPassword === newPassword && (
                  <p className="mt-1 text-[11px] text-emerald-400 flex items-center gap-1">
                    ✓ Passwords match
                  </p>
                )}
              </div>

              {/* In-view feedback messages right above actions */}
              <AnimatePresence>
                {error && (
                  <motion.div
                    initial={{ opacity: 0, y: -4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -4 }}
                    className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 flex items-start gap-2 text-xs text-red-400"
                  >
                    <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                    <span>{error}</span>
                  </motion.div>
                )}

                {success && (
                  <motion.div
                    initial={{ opacity: 0, y: -4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -4 }}
                    className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-start gap-2 text-xs text-emerald-400"
                  >
                    <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" />
                    <span>{success}</span>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Actions */}
              <div className="flex items-center justify-end gap-3 pt-3 border-t border-[#1E293B]">
                <button
                  type="button"
                  onClick={handleClose}
                  className="px-4 py-2.5 text-xs font-semibold text-slate-400 hover:text-white transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold transition-all shadow-md disabled:opacity-50 flex items-center gap-2 cursor-pointer"
                >
                  {loading ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      <span>Updating Password...</span>
                    </>
                  ) : (
                    <span>Update Password</span>
                  )}
                </button>
              </div>
            </form>
          </motion.div>
        </div>
      )}
    </AnimatePresence>,
    document.body
  );
};
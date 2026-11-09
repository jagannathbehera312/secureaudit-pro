import React, { useState } from "react";
import { ShieldCheck, KeyRound, Lock, User as UserIcon, CheckCircle2, AlertCircle, Copy, Check } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { authApi } from "../services/api";

export const ProfilePage: React.FC = () => {
  const { user, refreshUser } = useAuth();

  // Password change state
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [pwMsg, setPwMsg] = useState<string | null>(null);
  const [pwError, setPwError] = useState<string | null>(null);
  const [pwSubmitting, setPwSubmitting] = useState(false);

  // 2FA state
  const [totpSetupData, setTotpSetupData] = useState<any | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [totpMsg, setTotpMsg] = useState<string | null>(null);
  const [totpError, setTotpError] = useState<string | null>(null);
  const [totpSubmitting, setTotpSubmitting] = useState(false);
  const [copied, setCopied] = useState(false);

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwMsg(null);
    setPwError(null);
    setPwSubmitting(true);
    try {
      const res = await authApi.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setPwMsg(res.data.message || "Password changed successfully.");
      setCurrentPassword("");
      setNewPassword("");
    } catch (err: any) {
      setPwError(err.response?.data?.error || "Error changing password.");
    } finally {
      setPwSubmitting(false);
    }
  };

  const handleStart2FA = async () => {
    setTotpMsg(null);
    setTotpError(null);
    try {
      const res = await authApi.setup2FA();
      setTotpSetupData(res.data);
    } catch (err: any) {
      setTotpError("Failed to initiate 2FA setup.");
    }
  };

  const handleVerify2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    setTotpMsg(null);
    setTotpError(null);
    setTotpSubmitting(true);
    try {
      const res = await authApi.verify2FA(totpCode);
      setTotpMsg(res.data.message || "2FA verified and enabled!");
      setTotpSetupData(null);
      setTotpCode("");
      refreshUser();
    } catch (err: any) {
      setTotpError(err.response?.data?.error || "Invalid 6-digit TOTP code.");
    } finally {
      setTotpSubmitting(false);
    }
  };

  const copySecret = () => {
    if (totpSetupData?.secret) {
      navigator.clipboard.writeText(totpSetupData.secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
          <ShieldCheck className="h-6 w-6 text-cyan-400" /> Security Analyst Profile
        </h1>
        <p className="text-xs text-slate-400 mt-1 font-mono">
          ACCOUNT IDENTITY, ROLE PERMISSIONS, PASSWORD SECURITY, AND TWO-FACTOR AUTHENTICATION
        </p>
      </div>

      {/* User Information Card */}
      <div className="bg-[#111827] border border-[#1E293B] rounded-2xl p-6">
        <h2 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
          <UserIcon className="h-4 w-4 text-cyan-400" /> Identity Details
        </h2>

        <div className="grid sm:grid-cols-2 gap-4 text-xs font-mono">
          <div className="bg-[#0B0F19] p-3 rounded-xl border border-[#1E293B]">
            <span className="text-slate-500 block uppercase text-[10px]">Email Address</span>
            <span className="text-white font-bold">{user?.email}</span>
          </div>
          <div className="bg-[#0B0F19] p-3 rounded-xl border border-[#1E293B]">
            <span className="text-slate-500 block uppercase text-[10px]">Assigned Role</span>
            <span className="text-cyan-400 font-bold uppercase">{user?.role?.replace("_", " ")}</span>
          </div>
          <div className="bg-[#0B0F19] p-3 rounded-xl border border-[#1E293B]">
            <span className="text-slate-500 block uppercase text-[10px]">Full Name</span>
            <span className="text-slate-200">{user?.first_name ? `${user.first_name} ${user.last_name}` : "Not configured"}</span>
          </div>
          <div className="bg-[#0B0F19] p-3 rounded-xl border border-[#1E293B]">
            <span className="text-slate-500 block uppercase text-[10px]">Two-Factor (TOTP)</span>
            <span className={`font-bold ${user?.totp_enabled ? "text-emerald-400" : "text-amber-400"}`}>
              {user?.totp_enabled ? "ENABLED & ACTIVE" : "NOT CONFIGURED"}
            </span>
          </div>
        </div>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        {/* Change Password */}
        <div className="bg-[#111827] border border-[#1E293B] rounded-2xl p-6 space-y-4">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Lock className="h-4 w-4 text-cyan-400" /> Change Account Password
          </h2>

          {pwMsg && (
            <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-400 flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4" /> {pwMsg}
            </div>
          )}

          {pwError && (
            <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-400">
              {pwError}
            </div>
          )}

          <form onSubmit={handlePasswordChange} className="space-y-3">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Current Password</label>
              <input
                type="password"
                required
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">New Password (Min 8 chars)</label>
              <input
                type="password"
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <button
              type="submit"
              disabled={pwSubmitting}
              className="w-full mt-2 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
            >
              {pwSubmitting ? "Updating..." : "Update Password"}
            </button>
          </form>
        </div>

        {/* 2FA Configuration */}
        <div className="bg-[#111827] border border-[#1E293B] rounded-2xl p-6 space-y-4">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-cyan-400" /> Two-Factor Authentication (TOTP)
          </h2>

          <p className="text-xs text-slate-400 leading-relaxed">
            Protect your analyst session with RFC 6238 time-based one-time passwords (Google Authenticator, Microsoft Authenticator, 1Password).
          </p>

          {totpMsg && (
            <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-400 flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4" /> {totpMsg}
            </div>
          )}

          {totpError && (
            <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-400">
              {totpError}
            </div>
          )}

          {!totpSetupData ? (
            <button
              onClick={handleStart2FA}
              className="w-full py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-lg text-xs font-bold transition-all shadow-md"
            >
              {user?.totp_enabled ? "Reconfigure 2FA Secret" : "Setup Authenticator App"}
            </button>
          ) : (
            <form onSubmit={handleVerify2FA} className="space-y-3 bg-[#0B0F19] p-4 rounded-xl border border-[#1E293B]">
              <div className="text-[11px] text-slate-300 font-semibold">1. Enter Secret Key into Authenticator:</div>
              <div className="flex items-center gap-2 bg-black/60 p-2 rounded border border-[#1E293B]">
                <code className="text-xs text-cyan-400 font-mono flex-1 select-all">{totpSetupData.secret}</code>
                <button type="button" onClick={copySecret} className="text-slate-400 hover:text-white">
                  {copied ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                </button>
              </div>

              <div className="text-[10px] text-slate-500 font-mono">
                Sample current code: <strong className="text-cyan-300">{totpSetupData.sample_current_code}</strong>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">2. Confirm 6-Digit Code</label>
                <input
                  type="text"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  placeholder="000000"
                  className="w-full bg-[#111827] border border-[#1E293B] rounded-lg px-3 py-2 text-xs text-white font-mono tracking-widest text-center focus:outline-none focus:border-cyan-500"
                />
              </div>

              <button
                type="submit"
                disabled={totpSubmitting || totpCode.length !== 6}
                className="w-full py-2 bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-lg text-xs font-bold disabled:opacity-40"
              >
                {totpSubmitting ? "Verifying..." : "Confirm & Enable 2FA"}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

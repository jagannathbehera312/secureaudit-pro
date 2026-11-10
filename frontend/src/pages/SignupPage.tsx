import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldAlert,
  Lock,
  Mail,
  User,
  Building,
  KeyRound,
  Eye,
  EyeOff,
  ArrowRight,
  AlertCircle,
  CheckCircle2,
  ShieldCheck,
} from "lucide-react";
import { useAuth } from "../contexts/AuthContext";

export const SignupPage: React.FC = () => {
  const navigate = useNavigate();
  const { register } = useAuth();

  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [role, setRole] = useState("security_analyst");

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Strength score
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

  const strength = getPasswordStrength(password);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (password.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);

    try {
      await register({
        email,
        password,
        first_name: firstName,
        last_name: lastName,
        organization_name: organizationName,
        role,
      });

      setSuccess("Account created successfully! Initializing SOC workspace...");
      setTimeout(() => {
        navigate("/dashboard");
      }, 1500);
    } catch (err: any) {
      setError(
        err.response?.data?.error || "Registration failed. An account with this email may already exist."
      );
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] flex flex-col justify-center py-10 px-6 lg:px-8 relative selection:bg-cyan-500/30 overflow-hidden">
      {/* Background glow orbs & cyber grid */}
      <div className="fixed inset-0 pointer-events-none bg-grid-cyber opacity-35 z-0" />
      <div className="fixed -top-24 -left-24 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="fixed -bottom-24 -right-24 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

      {/* Brand & Heading */}
      <motion.div
        initial={{ opacity: 0, y: -15 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="sm:mx-auto sm:w-full sm:max-w-xl text-center relative z-10"
      >
        <Link to="/" className="inline-block group">
          <motion.div
            whileHover={{ scale: 1.08, rotate: 10 }}
            className="inline-flex h-12 w-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 items-center justify-center glow-cyan mb-3"
          >
            <ShieldAlert className="h-6 w-6 text-cyan-400" />
          </motion.div>
        </Link>
        <h2 className="text-2xl font-extrabold text-white tracking-tight">Create SecureAudit Pro Account</h2>
        <p className="mt-1 text-xs text-slate-400 font-mono">SOC ANALYST ONBOARDING & ENTERPRISE ACCESS</p>
      </motion.div>

      {/* Form Card */}
      <motion.div
        initial={{ opacity: 0, scale: 0.96, y: 15 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.1 }}
        className="mt-6 sm:mx-auto sm:w-full sm:max-w-xl relative z-10"
      >
        <div className="glass-panel border border-[#1E293B] py-7 px-6 shadow-2xl rounded-2xl sm:px-10 glow-cyan">
          <AnimatePresence>
            {error && (
              <motion.div
                initial={{ opacity: 0, y: -8, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -8, scale: 0.98 }}
                className="mb-5 p-3 rounded-xl bg-red-500/10 border border-red-500/30 flex items-start gap-2 text-xs text-red-400"
              >
                <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                <span>{error}</span>
              </motion.div>
            )}

            {success && (
              <motion.div
                initial={{ opacity: 0, y: -8, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -8, scale: 0.98 }}
                className="mb-5 p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-start gap-2 text-xs text-emerald-400"
              >
                <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" />
                <span>{success}</span>
              </motion.div>
            )}
          </AnimatePresence>

          <form className="space-y-4" onSubmit={handleSubmit}>
            {/* First & Last Name */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  FIRST NAME
                </label>
                <div className="relative">
                  <User className="absolute left-3.5 top-2.5 h-4 w-4 text-slate-500" />
                  <input
                    type="text"
                    required
                    value={firstName}
                    onChange={(e) => setFirstName(e.target.value)}
                    className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl pl-10 pr-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                    placeholder="Alex"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  LAST NAME
                </label>
                <div className="relative">
                  <User className="absolute left-3.5 top-2.5 h-4 w-4 text-slate-500" />
                  <input
                    type="text"
                    required
                    value={lastName}
                    onChange={(e) => setLastName(e.target.value)}
                    className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl pl-10 pr-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                    placeholder="Vance"
                  />
                </div>
              </div>
            </div>

            {/* Work Email */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                WORK EMAIL ADDRESS
              </label>
              <div className="relative">
                <Mail className="absolute left-3.5 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl pl-10 pr-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                  placeholder="analyst@organization.com"
                />
              </div>
            </div>

            {/* Organization & Role */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  ORGANIZATION / COMPANY
                </label>
                <div className="relative">
                  <Building className="absolute left-3.5 top-2.5 h-4 w-4 text-slate-500" />
                  <input
                    type="text"
                    value={organizationName}
                    onChange={(e) => setOrganizationName(e.target.value)}
                    className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl pl-10 pr-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                    placeholder="Acme Security Labs"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  SECURITY ROLE
                </label>
                <div className="relative">
                  <ShieldCheck className="absolute left-3.5 top-2.5 h-4 w-4 text-slate-500" />
                  <select
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl pl-10 pr-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                  >
                    <option value="security_analyst">Security Analyst</option>
                    <option value="org_admin">Organization Admin</option>
                    <option value="read_only">Read-Only Auditor</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Password */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="block text-xs font-semibold text-slate-300 font-mono">
                  ACCOUNT PASSWORD
                </label>
                {password && (
                  <span className="text-[10px] font-mono text-slate-400">
                    Strength: <span className="font-bold text-cyan-400">{strength.label}</span>
                  </span>
                )}
              </div>
              <div className="relative">
                <Lock className="absolute left-3.5 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  type={showPassword ? "text" : "password"}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl pl-10 pr-10 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                  placeholder="At least 8 characters"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>

              {/* Password strength visual */}
              {password && (
                <div className="mt-2 space-y-1">
                  <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden flex">
                    <div
                      className={`h-full transition-all duration-300 ${strength.color}`}
                      style={{ width: `${(strength.score / 5) * 100}%` }}
                    />
                  </div>
                  <div className="flex items-center gap-3 text-[10px] text-slate-400">
                    <span className={password.length >= 8 ? "text-emerald-400" : "text-slate-500"}>
                      ✓ 8+ chars
                    </span>
                    <span className={/[0-9]/.test(password) ? "text-emerald-400" : "text-slate-500"}>
                      ✓ Number
                    </span>
                    <span className={/[A-Z]/.test(password) ? "text-emerald-400" : "text-slate-500"}>
                      ✓ Uppercase
                    </span>
                    <span className={/[^A-Za-z0-9]/.test(password) ? "text-emerald-400" : "text-slate-500"}>
                      ✓ Symbol
                    </span>
                  </div>
                </div>
              )}
            </div>

            {/* Confirm Password */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                CONFIRM PASSWORD
              </label>
              <div className="relative">
                <KeyRound className="absolute left-3.5 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  type={showConfirmPassword ? "text" : "password"}
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className={`w-full bg-[#0B0F19] border rounded-xl pl-10 pr-10 py-2 text-sm text-white focus:outline-none transition-colors ${
                    confirmPassword && confirmPassword !== password
                      ? "border-red-500 focus:border-red-500"
                      : "border-[#1E293B] focus:border-cyan-500"
                  }`}
                  placeholder="Repeat your password"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300"
                >
                  {showConfirmPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {confirmPassword && confirmPassword !== password && (
                <p className="mt-1 text-[11px] text-red-400">Passwords do not match.</p>
              )}
              {confirmPassword && confirmPassword === password && (
                <p className="mt-1 text-[11px] text-emerald-400 flex items-center gap-1">
                  ✓ Passwords match
                </p>
              )}
            </div>

            {/* In-view error right above submit button for mobile viewports */}
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
            </AnimatePresence>

            {/* Submit button */}
            <motion.button
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.99 }}
              type="submit"
              disabled={loading}
              className="w-full mt-2 py-3 px-4 bg-gradient-to-r from-cyan-600 via-teal-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-sm font-bold shadow-lg shadow-cyan-900/30 transition-all flex items-center justify-center gap-2 disabled:opacity-50 glow-cyan cursor-pointer"
            >
              {loading ? (
                <>
                  <div className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                  <span>Creating Account...</span>
                </>
              ) : (
                <>
                  <span>Create Account & Enter SOC</span>
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </motion.button>
          </form>

          {/* Links / Navigation */}
          <div className="mt-6 pt-5 border-t border-[#1E293B] flex flex-col sm:flex-row items-center justify-between text-xs text-slate-400 gap-2 font-mono">
            <span>Already have an account?</span>
            <Link
              to="/login"
              className="text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1 transition-colors"
            >
              Sign In to SOC <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
        </div>
      </motion.div>
    </div>
  );
};
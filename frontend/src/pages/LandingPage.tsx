import React from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  ShieldAlert,
  Radar,
  Lock,
  FileCheck,
  Server,
  Zap,
  ArrowRight,
  CheckCircle2,
  Globe,
  Terminal,
  Cpu,
  Layers,
  Sparkles,
  ShieldCheck,
  Activity
} from "lucide-react";

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.15
    }
  }
};

const itemVariants = {
  hidden: { opacity: 0, y: 16 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.45, ease: "easeOut" }
  }
};

export const LandingPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-[#0B0F19] text-[#F8FAFC] relative overflow-hidden selection:bg-cyan-500/30">
      {/* Background cyber grid & glow orbs */}
      <div className="fixed inset-0 pointer-events-none bg-grid-cyber opacity-40 z-0" />
      <div className="fixed top-0 left-1/4 w-96 h-96 bg-cyan-600/10 rounded-full blur-3xl pointer-events-none -z-10" />
      <div className="fixed bottom-10 right-1/4 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none -z-10" />

      {/* Navigation */}
      <header className="border-b border-[#1E293B]/80 bg-[#0B0F19]/80 backdrop-blur-md sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 group">
            <motion.div
              whileHover={{ rotate: 15 }}
              className="h-9 w-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center glow-cyan"
            >
              <ShieldAlert className="h-5 w-5 text-cyan-400" />
            </motion.div>
            <div className="font-bold text-lg text-white tracking-wide flex items-center gap-1.5">
              SecureAudit <span className="text-xs bg-cyan-500/20 text-cyan-400 px-1.5 py-0.5 rounded font-mono">PRO</span>
            </div>
          </Link>

          <div className="flex items-center gap-4">
            <Link to="/login" className="text-xs font-semibold text-slate-300 hover:text-white transition-colors">
              Sign In
            </Link>
            <motion.div whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.96 }}>
              <Link
                to="/signup"
                className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold tracking-wide shadow-lg shadow-cyan-900/30 transition-all flex items-center gap-2 glow-cyan"
              >
                Sign Up / Register <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </motion.div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative pt-20 pb-20 overflow-hidden px-6 z-10">
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="max-w-5xl mx-auto text-center"
        >
          <motion.div variants={itemVariants} className="inline-flex items-center gap-2 px-3.5 py-1.5 bg-cyan-500/10 border border-cyan-500/30 rounded-full text-xs font-semibold text-cyan-400 mb-8 shadow-sm">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
            <span>OWASP TOP 10:2025 & API PENETRATION TESTING ENGINE</span>
          </motion.div>

          <motion.h1 variants={itemVariants} className="text-4xl sm:text-6xl font-extrabold text-white tracking-tight leading-tight">
            Discover Vulnerabilities. <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-blue-500">
              Strengthen Security Posture.
            </span> <br />
            Protect Enterprise Assets.
          </motion.h1>

          <motion.p variants={itemVariants} className="mt-6 text-base sm:text-lg text-slate-400 max-w-2xl mx-auto leading-relaxed">
            Enterprise-grade automated vulnerability assessment and penetration testing suite.
            Multi-engine scanning powered by native Python security probes, OWASP ZAP Automation Framework, and safe curated Nuclei templates.
          </motion.p>

          <motion.div variants={itemVariants} className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
            <motion.div whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.96 }} className="w-full sm:w-auto">
              <Link
                to="/login"
                className="w-full px-7 py-3.5 bg-gradient-to-r from-cyan-600 via-teal-600 to-blue-600 text-white rounded-xl text-sm font-bold shadow-xl shadow-cyan-900/40 flex items-center justify-center gap-2 glow-cyan"
              >
                Launch Live Assessment <ArrowRight className="h-4 w-4" />
              </Link>
            </motion.div>
            <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }} className="w-full sm:w-auto">
              <a
                href="#features"
                className="w-full px-6 py-3.5 bg-slate-900/90 hover:bg-slate-800 border border-slate-700/80 text-slate-200 rounded-xl text-sm font-semibold flex items-center justify-center gap-2 transition-colors"
              >
                Explore Scanning Pipeline
              </a>
            </motion.div>
          </motion.div>

          {/* Cyber Radar Terminal Preview Mockup */}
          <motion.div
            variants={itemVariants}
            className="mt-14 max-w-3xl mx-auto rounded-2xl border border-cyan-500/30 bg-[#0B0F19]/90 backdrop-blur-xl p-4 shadow-2xl glow-cyan text-left font-mono text-xs"
          >
            <div className="flex items-center justify-between pb-3 border-b border-[#1E293B]">
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full bg-red-500/80 inline-block" />
                <span className="h-3 w-3 rounded-full bg-amber-500/80 inline-block" />
                <span className="h-3 w-3 rounded-full bg-emerald-500/80 inline-block" />
                <span className="text-[11px] text-slate-400 ml-2 font-mono">root@secureaudit-vapt:~#</span>
              </div>
              <div className="text-[10px] text-cyan-400 font-mono flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" /> ENGINE ONLINE
              </div>
            </div>
            <div className="py-3 text-slate-300 space-y-1.5 font-mono text-[11px]">
              <div className="text-cyan-400">$ secureaudit-vapt --target https://demo.secureaudit.pro --profile full_audit</div>
              <div className="text-slate-400">[*] [INIT] Target URL canonicalized: https://demo.secureaudit.pro:443</div>
              <div className="text-slate-400">[*] [PORT-SCAN] Probing top 20 TCP perimeter ports with SYN handshake...</div>
              <div className="text-emerald-400">[+] [NMAP-OK] Discovered open ports: 80/tcp (http), 443/tcp (https), 8080/tcp (api-alt)</div>
              <div className="text-amber-400">[!] [VULN-FOUND] Missing Content-Security-Policy & HSTS header (Severity: HIGH)</div>
              <div className="text-cyan-300">[*] [FIX-DERIVED] sudo ufw deny 8080/tcp && nginx -s reload</div>
            </div>
          </motion.div>
        </motion.div>
      </section>

      {/* Feature Highlights Grid */}
      <section id="features" className="py-16 px-6 max-w-7xl mx-auto border-t border-[#1E293B] relative z-10">
        <div className="text-center mb-12">
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">Enterprise Penetration Testing Architecture</h2>
          <p className="text-xs text-slate-400 mt-2 font-mono">FULL-SPECTRUM RECONNAISSANCE, PERIMETER DISCOVERY, AND EXPLOITATION RESISTANCE</p>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          <motion.div
            whileHover={{ y: -6, scale: 1.02 }}
            transition={{ duration: 0.25 }}
            className="glass-panel border border-[#1E293B] rounded-2xl p-6 hover:border-cyan-500/40 transition-colors shadow-lg"
          >
            <div className="h-10 w-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 mb-4 glow-cyan">
              <Radar className="h-5 w-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">15-Stage Scanning Pipeline</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Real-time progress monitoring through DNS resolution, TCP port scanning, SSL/TLS handshake, security headers, CORS, fuzzing, OWASP Top 10, and API security.
            </p>
          </motion.div>

          <motion.div
            whileHover={{ y: -6, scale: 1.02 }}
            transition={{ duration: 0.25 }}
            className="glass-panel border border-[#1E293B] rounded-2xl p-6 hover:border-red-500/40 transition-colors shadow-lg"
          >
            <div className="h-10 w-10 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400 mb-4">
              <Lock className="h-5 w-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">Strict Scanner Safety & SSRF Gate</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Mandatory domain authorization via DNS TXT or HTTP challenges. Automated blocking of loopback, RFC 1918, and AWS metadata IP ranges before probe execution.
            </p>
          </motion.div>

          <motion.div
            whileHover={{ y: -6, scale: 1.02 }}
            transition={{ duration: 0.25 }}
            className="glass-panel border border-[#1E293B] rounded-2xl p-6 hover:border-emerald-500/40 transition-colors shadow-lg"
          >
            <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mb-4 glow-emerald">
              <FileCheck className="h-5 w-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">Consulting-Grade PDF Reports</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Executive and technical PDF reports with cover page, methodology, open port perimeter table, CVSS scores, curl reproduction steps, and remediation roadmaps.
            </p>
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-[#1E293B] py-8 px-6 text-center text-xs text-slate-500 relative z-10 font-mono">
        SecureAudit Pro Platform &copy; 2026. Built for Cyber Security Teams & Enterprise Auditing.
      </footer>
    </div>
  );
};

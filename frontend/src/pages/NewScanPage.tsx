import React, { useState, useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  Radar,
  Globe,
  ShieldAlert,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ArrowLeft,
  Zap,
  Lock,
  Layers,
  CheckSquare,
  Search,
  Server,
  Network
} from "lucide-react";
import { websitesApi, scansApi } from "../services/api";

export const NewScanPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const preselectedWebsiteId = searchParams.get("website_id");
  const prefilledUrl = searchParams.get("url") || "";

  // Target Mode: "direct" allows entering any URL; "inventory" picks from registered sites
  const [targetMode, setTargetMode] = useState<"direct" | "inventory">(preselectedWebsiteId ? "inventory" : "direct");
  const [customUrl, setCustomUrl] = useState(prefilledUrl);
  const [customName, setCustomName] = useState("");
  const [customEnv, setCustomEnv] = useState<"production" | "staging" | "development">("production");

  const [websites, setWebsites] = useState<any[]>([]);
  const [selectedSiteId, setSelectedSiteId] = useState(preselectedWebsiteId || "");
  const [profile, setProfile] = useState("standard");
  const [step, setStep] = useState(1);

  // Configuration options
  const [crawlDepth, setCrawlDepth] = useState(3);
  const [rateLimit, setRateLimit] = useState(50);
  const [timeoutSec, setTimeoutSec] = useState(5);
  const [customHeaders, setCustomHeaders] = useState("");
  const [scanPorts, setScanPorts] = useState(true);
  const [scanOwasp, setScanOwasp] = useState(true);
  const [authorizedConsent, setAuthorizedConsent] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadWebsites = async () => {
      try {
        const res = await websitesApi.list();
        setWebsites(res.data);
        if (!selectedSiteId && res.data.length > 0) {
          setSelectedSiteId(res.data[0].id);
        }
      } catch (err) {
        console.error(err);
      }
    };
    loadWebsites();
  }, []);

  const selectedSite = websites.find((w) => w.id === selectedSiteId);

  // Derive domain from customUrl for preview
  const getDomainFromUrl = (url: string) => {
    try {
      const normalized = url.startsWith("http://") || url.startsWith("https://") ? url : `https://${url}`;
      return new URL(normalized).hostname;
    } catch {
      return url || "—";
    }
  };

  const handleLaunch = async () => {
    if (!authorizedConsent) {
      setError("You must confirm scan authorization before initiating security testing.");
      return;
    }
    if (targetMode === "direct" && !customUrl.trim()) {
      setError("Please enter a valid target website URL.");
      return;
    }
    if (targetMode === "inventory" && !selectedSiteId) {
      setError("Please select a target website from your inventory.");
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const payload: any = {
        profile,
        options: {
          crawl_depth: crawlDepth,
          rate_limit: rateLimit,
          timeout: timeoutSec,
          custom_headers: customHeaders,
          scan_open_ports: scanPorts,
          owasp_top10: scanOwasp,
        },
      };

      if (targetMode === "direct") {
        payload.target_url = customUrl.trim();
        payload.website_name = customName.trim() || undefined;
        payload.environment = customEnv;
      } else {
        payload.website_id = selectedSiteId;
      }

      const res = await scansApi.create(payload);
      navigate(`/scans/${res.data.id}`);
    } catch (err: any) {
      setError(err.response?.data?.error || "Failed to trigger scan execution.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
          <Radar className="h-6 w-6 text-cyan-400" /> New Security Assessment Wizard
        </h1>
        <p className="text-xs text-slate-400 mt-1 font-mono">
          ENTER ANY TARGET URL, CONFIGURE OPEN PORT PROBING, OWASP TOP 10 AUDITS, AND SAFETY GATES
        </p>
      </div>

      {/* Step Indicator Progress Bar */}
      <div className="grid grid-cols-4 gap-2 pt-2">
        {[
          { num: 1, title: "Target URL / Asset" },
          { num: 2, title: "Scan Profile" },
          { num: 3, title: "Configuration" },
          { num: 4, title: "Safety & Authorization" },
        ].map((s) => (
          <div
            key={s.num}
            className={`p-3 rounded-xl border text-xs font-semibold transition-all ${
              step === s.num
                ? "bg-cyan-500/10 border-cyan-500/40 text-cyan-300"
                : step > s.num
                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                : "bg-slate-900/50 border-[#1E293B] text-slate-500"
            }`}
          >
            <div className="flex items-center gap-2">
              <span className={`h-5 w-5 rounded-full flex items-center justify-center text-[10px] font-mono ${
                step === s.num ? "bg-cyan-500 text-black font-bold" : step > s.num ? "bg-emerald-500 text-black" : "bg-slate-800 text-slate-400"
              }`}>
                {step > s.num ? "✓" : s.num}
              </span>
              <span className="truncate">{s.title}</span>
            </div>
          </div>
        ))}
      </div>

      {error && (
        <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-400 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {/* Multi-Step Wizard Cards with AnimatePresence */}
      <AnimatePresence mode="wait">
        {/* Step 1: Select Target */}
        {step === 1 && (
          <motion.div
            key="step1"
            initial={{ opacity: 0, x: 18 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -18 }}
            transition={{ duration: 0.22, ease: "easeOut" }}
            className="bg-[#111827] border border-[#1E293B] rounded-2xl p-6 space-y-5 shadow-xl"
          >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1E293B] pb-4">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Globe className="h-5 w-5 text-cyan-400" /> Step 1: Target Definition
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Scan any custom website/URL on-demand or select from your registered inventory.
              </p>
            </div>

            {/* Segmented Mode Selector */}
            <div className="flex bg-[#0B0F19] p-1 rounded-xl border border-[#1E293B] self-start sm:self-auto">
              <button
                type="button"
                onClick={() => setTargetMode("direct")}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                  targetMode === "direct"
                    ? "bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Zap className="h-3.5 w-3.5" /> Direct URL Input
              </button>
              <button
                type="button"
                onClick={() => setTargetMode("inventory")}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                  targetMode === "inventory"
                    ? "bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Server className="h-3.5 w-3.5" /> Registered Inventory ({websites.length})
              </button>
            </div>
          </div>

          {/* Mode A: Direct URL Input */}
          {targetMode === "direct" && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Target Website URL or Hostname <span className="text-cyan-400">*</span>
                </label>
                <div className="relative">
                  <Globe className="absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
                  <input
                    type="text"
                    required
                    value={customUrl}
                    onChange={(e) => setCustomUrl(e.target.value)}
                    placeholder="https://example.com or http://target-api.internal"
                    className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl pl-10 pr-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
                  />
                </div>
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Accepts standard web URLs (e.g. https://example.com, https://api.apexfintech.internal, http://localhost:8080)
                </span>
              </div>

              {/* Quick Preset Buttons */}
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <span className="text-[11px] text-slate-400 font-mono">Quick Targets:</span>
                {[
                  { label: "Example.com", url: "https://example.com" },
                  { label: "Banking Portal (Demo)", url: "https://banking.apexfintech.internal" },
                  { label: "API Gateway (Demo)", url: "https://api.apexfintech.internal" },
                  { label: "HTTPBin Testing", url: "https://httpbin.org" },
                ].map((preset) => (
                  <button
                    key={preset.url}
                    type="button"
                    onClick={() => {
                      setCustomUrl(preset.url);
                      setCustomName(preset.label);
                    }}
                    className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-[#1E293B] text-[11px] text-cyan-400 hover:text-cyan-300 font-mono transition-all"
                  >
                    + {preset.label}
                  </button>
                ))}
              </div>

              <div className="grid sm:grid-cols-2 gap-4 pt-2">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Target Asset Name (Optional)
                  </label>
                  <input
                    type="text"
                    value={customName}
                    onChange={(e) => setCustomName(e.target.value)}
                    placeholder={getDomainFromUrl(customUrl) || "My Production Web Application"}
                    className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Target Environment
                  </label>
                  <select
                    value={customEnv}
                    onChange={(e: any) => setCustomEnv(e.target.value)}
                    className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-xl px-3.5 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="production">Production Environment</option>
                    <option value="staging">Staging / UAT Environment</option>
                    <option value="development">Development / Internal Sandbox</option>
                  </select>
                </div>
              </div>

              {/* Real-time Scope Preview Box */}
              {customUrl.trim() && (
                <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-500/30 space-y-2">
                  <div className="text-xs font-bold text-cyan-300 flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-cyan-400" /> Target Scope Ready
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono text-slate-300 pt-1">
                    <div>
                      <span className="text-slate-500 block">Domain:</span>
                      <span className="text-white font-bold">{getDomainFromUrl(customUrl)}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Perimeter Checks:</span>
                      <span className="text-emerald-400">Open Ports (80, 443, 8080+)</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">OWASP Scope:</span>
                      <span className="text-cyan-400">OWASP Top 10:2025</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Auto-Save:</span>
                      <span className="text-purple-400">Saved to Inventory</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Mode B: Choose from Registered Inventory */}
          {targetMode === "inventory" && (
            <div className="space-y-3">
              <div className="grid md:grid-cols-2 gap-3.5">
                {websites.map((w) => (
                  <div
                    key={w.id}
                    onClick={() => setSelectedSiteId(w.id)}
                    className={`p-4 rounded-xl border cursor-pointer transition-all ${
                      selectedSiteId === w.id
                        ? "bg-cyan-500/10 border-cyan-500/50 text-white shadow-lg shadow-cyan-950/20"
                        : "bg-[#0B0F19] border-[#1E293B] text-slate-400 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-sm font-bold text-white">{w.name}</span>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-mono uppercase ${
                        w.verification_status === "verified" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30" : "bg-amber-500/10 text-amber-400"
                      }`}>
                        {w.verification_status}
                      </span>
                    </div>
                    <div className="text-xs font-mono text-cyan-400 truncate">{w.url}</div>
                    <div className="flex items-center justify-between mt-3 text-[11px] text-slate-500 border-t border-[#1E293B] pt-2">
                      <span>Env: {w.environment}</span>
                      <span>Score: {w.security_score || 100}/100</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="flex justify-end pt-4 border-t border-[#1E293B]">
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              onClick={() => setStep(2)}
              disabled={targetMode === "direct" ? !customUrl.trim() : !selectedSiteId}
              className="px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold flex items-center gap-2 disabled:opacity-40 shadow-lg shadow-cyan-950/30 cursor-pointer"
            >
              Continue to Scan Profiles <ArrowRight className="h-4 w-4" />
            </motion.button>
          </div>
        </motion.div>
      )}

      {/* Step 2: Select Profile */}
      {step === 2 && (
        <motion.div
          key="step2"
          initial={{ opacity: 0, x: 18 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -18 }}
          transition={{ duration: 0.22, ease: "easeOut" }}
          className="bg-[#111827] border border-[#1E293B] rounded-2xl p-6 space-y-4 shadow-xl"
        >
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Layers className="h-5 w-5 text-cyan-400" /> Step 2: Select VAPT Scan Profile
          </h2>
          <p className="text-xs text-slate-400">
            Choose the testing depth and security modules for this assessment run.
          </p>

          <div className="space-y-3 pt-2">
            {[
              {
                id: "quick",
                name: "A. Quick Security Audit",
                desc: "Network perimeter open port checks, HTTP headers, SSL/TLS validation, cookie security flags, and safe passive misconfigurations.",
                intensity: "Very Low (Passive + Safe Port Audit)",
                speed: "~30-60 seconds"
              },
              {
                id: "standard",
                name: "B. Standard VAPT Scan (Recommended)",
                desc: "Open port probing, full OWASP Top 10:2025 assessment, safe crawling, endpoint discovery, CORS evaluation, exposed resource probes (.env, .git), and API security.",
                intensity: "Low / Non-destructive Active",
                speed: "~2-3 minutes"
              },
              {
                id: "comprehensive",
                name: "C. Comprehensive Full VAPT Scan",
                desc: "Full authorized crawling, OWASP Top 10:2025 + OWASP API Security checks, open port & service banner discovery, session token analysis, and safe injection heuristics.",
                intensity: "Moderate (Safe validation)",
                speed: "~5-8 minutes"
              },
              {
                id: "custom",
                name: "D. Custom Security Assessment",
                desc: "Fine-tune individual vulnerability modules and custom testing scope.",
                intensity: "Configurable",
                speed: "Variable"
              }
            ].map((p) => (
              <div
                key={p.id}
                onClick={() => setProfile(p.id)}
                className={`p-4 rounded-xl border cursor-pointer transition-all ${
                  profile === p.id
                    ? "bg-cyan-500/10 border-cyan-500/50 text-white shadow-lg shadow-cyan-950/20"
                    : "bg-[#0B0F19] border-[#1E293B] text-slate-400 hover:border-slate-700"
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <h3 className="text-sm font-bold text-white">{p.name}</h3>
                  <span className="text-[10px] font-mono text-cyan-400">{p.speed}</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">{p.desc}</p>
                <div className="mt-2 text-[10px] text-slate-500 font-mono">
                  Intensity: <strong className="text-slate-300">{p.intensity}</strong>
                </div>
              </div>
            ))}
          </div>

          <div className="flex justify-between pt-4 border-t border-[#1E293B]">
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              onClick={() => setStep(1)}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold flex items-center gap-2 cursor-pointer transition-colors"
            >
              <ArrowLeft className="h-4 w-4" /> Back
            </motion.button>
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              onClick={() => setStep(3)}
              className="px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold flex items-center gap-2 cursor-pointer shadow-md"
            >
              Continue to Configuration <ArrowRight className="h-4 w-4" />
            </motion.button>
          </div>
        </motion.div>
      )}

      {/* Step 3: Configuration */}
      {step === 3 && (
        <motion.div
          key="step3"
          initial={{ opacity: 0, x: 18 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -18 }}
          transition={{ duration: 0.22, ease: "easeOut" }}
          className="bg-[#111827] border border-[#1E293B] rounded-2xl p-6 space-y-4 shadow-xl"
        >
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Sliders className="h-5 w-5 text-cyan-400" /> Step 3: Security Modules & Performance Parameters
          </h2>

          {/* Module Toggles */}
          <div className="grid sm:grid-cols-2 gap-3 pt-1">
            <label className="flex items-center gap-3 p-3 rounded-xl bg-[#0B0F19] border border-[#1E293B] cursor-pointer">
              <input
                type="checkbox"
                checked={scanPorts}
                onChange={(e) => setScanPorts(e.target.checked)}
                className="h-4 w-4 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
              />
              <div>
                <div className="text-xs font-bold text-white flex items-center gap-1.5">
                  <Network className="h-3.5 w-3.5 text-cyan-400" /> Open Port & Perimeter Audit
                </div>
                <span className="text-[10px] text-slate-400">Probes 80, 443, 8080, 8000, 3306, 6379, 27017, etc.</span>
              </div>
            </label>

            <label className="flex items-center gap-3 p-3 rounded-xl bg-[#0B0F19] border border-[#1E293B] cursor-pointer">
              <input
                type="checkbox"
                checked={scanOwasp}
                onChange={(e) => setScanOwasp(e.target.checked)}
                className="h-4 w-4 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
              />
              <div>
                <div className="text-xs font-bold text-white flex items-center gap-1.5">
                  <ShieldAlert className="h-3.5 w-3.5 text-purple-400" /> OWASP Top 10:2025 Deep Checks
                </div>
                <span className="text-[10px] text-slate-400">Tests A01 Broken Access to A10 Web Vulnerabilities</span>
              </div>
            </label>
          </div>

          <div className="grid md:grid-cols-3 gap-4 pt-2">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Crawl Depth Limit</label>
              <input
                type="number"
                min={1}
                max={5}
                value={crawlDepth}
                onChange={(e) => setCrawlDepth(parseInt(e.target.value) || 2)}
                className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Maximum link recursion depth</span>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Rate Limit (Req / Sec)</label>
              <input
                type="number"
                min={5}
                max={200}
                value={rateLimit}
                onChange={(e) => setRateLimit(parseInt(e.target.value) || 50)}
                className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Safe rate limiting to prevent overload</span>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Request Timeout (Sec)</label>
              <input
                type="number"
                min={2}
                max={30}
                value={timeoutSec}
                onChange={(e) => setTimeoutSec(parseInt(e.target.value) || 5)}
                className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Connection timeout threshold</span>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">Custom HTTP Headers (Optional)</label>
            <textarea
              value={customHeaders}
              onChange={(e) => setCustomHeaders(e.target.value)}
              rows={2}
              className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 font-mono"
              placeholder="X-Security-Scan: SecureAudit-Pro&#10;Authorization: Bearer test_token"
            />
          </div>

          <div className="flex justify-between pt-4 border-t border-[#1E293B]">
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              onClick={() => setStep(2)}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold flex items-center gap-2 cursor-pointer transition-colors"
            >
              <ArrowLeft className="h-4 w-4" /> Back
            </motion.button>
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              onClick={() => setStep(4)}
              className="px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold flex items-center gap-2 cursor-pointer shadow-md"
            >
              Proceed to Safety Review <ArrowRight className="h-4 w-4" />
            </motion.button>
          </div>
        </motion.div>
      )}

      {/* Step 4: Safety & Authorization */}
      {step === 4 && (
        <motion.div
          key="step4"
          initial={{ opacity: 0, x: 18 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -18 }}
          transition={{ duration: 0.22, ease: "easeOut" }}
          className="bg-[#111827] border border-[#1E293B] rounded-2xl p-6 space-y-5 shadow-xl"
        >
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Lock className="h-5 w-5 text-cyan-400" /> Step 4: Scanner Safety & Authorization Declaration
          </h2>

          <div className="p-4 rounded-xl bg-[#0B0F19] border border-[#1E293B] space-y-2.5 text-xs text-slate-300">
            <div className="flex items-center justify-between font-mono pb-2 border-b border-[#1E293B]">
              <span className="text-slate-400">Target Asset URL:</span>
              <span className="text-cyan-400 font-bold truncate max-w-md">
                {targetMode === "direct" ? customUrl : selectedSite?.url}
              </span>
            </div>
            <div className="flex items-center justify-between font-mono pb-2 border-b border-[#1E293B]">
              <span className="text-slate-400">Target Domain:</span>
              <span className="text-white font-bold">
                {targetMode === "direct" ? getDomainFromUrl(customUrl) : selectedSite?.domain}
              </span>
            </div>
            <div className="flex items-center justify-between font-mono pb-2 border-b border-[#1E293B]">
              <span className="text-slate-400">Selected Profile:</span>
              <span className="text-cyan-400 font-bold uppercase">{profile} Scan</span>
            </div>
            <div className="flex items-center justify-between font-mono pb-2 border-b border-[#1E293B]">
              <span className="text-slate-400">Active Modules:</span>
              <span className="text-emerald-400 font-bold">
                Open Ports: {scanPorts ? "YES" : "NO"} | OWASP Top 10: {scanOwasp ? "YES" : "NO"}
              </span>
            </div>
            <div className="flex items-center justify-between font-mono">
              <span className="text-slate-400">Rate Limit & Boundary:</span>
              <span className="text-slate-200">{rateLimit} req/sec | SSRF Protected</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-xs text-amber-300 space-y-2">
            <div className="font-bold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" /> Ethical Security Testing Notice
            </div>
            <p className="leading-relaxed">
              SecureAudit Pro executes non-destructive security probes designed to assess vulnerabilities safely.
              You must have explicit, verified authorization from the asset owner to test this application.
            </p>
          </div>

          <label className="flex items-start gap-3 cursor-pointer pt-1">
            <input
              type="checkbox"
              checked={authorizedConsent}
              onChange={(e) => setAuthorizedConsent(e.target.checked)}
              className="mt-1 h-4 w-4 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
            />
            <span className="text-xs text-slate-300 leading-relaxed">
              I certify that I am explicitly authorized to perform vulnerability testing on this target ({targetMode === "direct" ? customUrl : selectedSite?.url}) and that all activities comply with organizational security policies and applicable laws.
            </span>
          </label>

          <div className="flex justify-between pt-4 border-t border-[#1E293B]">
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              onClick={() => setStep(3)}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold flex items-center gap-2 cursor-pointer transition-colors"
            >
              <ArrowLeft className="h-4 w-4" /> Back
            </motion.button>
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              onClick={handleLaunch}
              disabled={loading || !authorizedConsent}
              className="px-6 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-cyan-900/30 flex items-center gap-2 disabled:opacity-40 cursor-pointer"
            >
              {loading ? "Dispatching Job..." : "Launch Security Assessment"}
              <ArrowRight className="h-4 w-4" />
            </motion.button>
          </div>
        </motion.div>
      )}
      </AnimatePresence>
    </div>
  );
};

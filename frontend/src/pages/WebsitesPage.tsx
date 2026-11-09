import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Globe, Plus, ShieldCheck, ShieldAlert, ArrowRight, CheckCircle2, Clock, Trash2, X, ExternalLink, Radar } from "lucide-react";
import { websitesApi } from "../services/api";

export const WebsitesPage: React.FC = () => {
  const [websites, setWebsites] = useState<any[]>([]);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showVerifyModal, setShowVerifyModal] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  // Add form state
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [env, setEnv] = useState("production");
  const [criticality, setCriticality] = useState("medium");
  const [description, setDescription] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Verification state
  const [verifyMethod, setVerifyMethod] = useState("dns");
  const [verifyMsg, setVerifyMsg] = useState<string | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);

  const fetchWebsites = async () => {
    try {
      const res = await websitesApi.list();
      setWebsites(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchWebsites();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setSubmitting(true);
    try {
      await websitesApi.create({
        name,
        url,
        environment: env,
        business_criticality: criticality,
        description,
        contact_email: contactEmail,
      });
      setShowAddModal(false);
      setName("");
      setUrl("");
      fetchWebsites();
    } catch (err: any) {
      setFormError(err.response?.data?.error || "Error registering website.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleVerify = async () => {
    if (!showVerifyModal) return;
    setVerifyMsg(null);
    setVerifyError(null);
    setVerifying(true);
    try {
      const res = await websitesApi.verify(showVerifyModal.id, verifyMethod);
      setVerifyMsg(res.data.message || "Domain verified successfully!");
      fetchWebsites();
    } catch (err: any) {
      setVerifyError(err.response?.data?.error || "Verification failed. Ensure challenge token is active.");
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">Registered Websites & Assets</h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            AUTHORIZED SCOPES, VERIFICATION CHALLENGES, AND POSTURE INDEX
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-lg text-xs font-bold tracking-wide shadow-md transition-all flex items-center gap-2 self-start sm:self-auto"
        >
          <Plus className="h-4 w-4" /> Register New Target
        </button>
      </div>

      {/* Grid of Registered Websites */}
      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-5">
        {websites.length === 0 && !loading && (
          <div className="col-span-full p-8 rounded-2xl bg-[#111827] border border-[#1E293B] text-center space-y-4">
            <div className="h-12 w-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mx-auto text-cyan-400">
              <Globe className="h-6 w-6" />
            </div>
            <div className="space-y-1">
              <h3 className="text-base font-bold text-white">No Target Websites Registered Yet</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Your inventory is clean. You can register an authorized website scope or audit any custom target URL directly with the New Scan Wizard.
              </p>
            </div>
            <div className="flex items-center justify-center gap-3 pt-2">
              <button
                onClick={() => setShowAddModal(true)}
                className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-lg text-xs font-bold tracking-wide shadow-md transition-all flex items-center gap-2"
              >
                <Plus className="h-4 w-4" /> Register Target Scope
              </button>
              <Link
                to="/scans/new"
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-cyan-400 rounded-lg text-xs font-semibold transition-all flex items-center gap-2"
              >
                <Radar className="h-4 w-4" /> Direct URL Scan Wizard
              </Link>
            </div>
          </div>
        )}
        {websites.map((site) => {
          const isVerified = site.verification_status === "verified";
          return (
            <motion.div
              key={site.id}
              whileHover={{ y: -4, scale: 1.015 }}
              transition={{ type: "spring", stiffness: 350, damping: 25 }}
              className="glass-panel glass-panel-hover rounded-2xl p-5 flex flex-col justify-between shadow-lg"
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-3">
                  <div>
                    <h3 className="text-sm font-bold text-white tracking-wide">{site.name}</h3>
                    <a
                      href={site.url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-xs text-cyan-400 font-mono hover:underline flex items-center gap-1 mt-0.5"
                    >
                      {site.domain} <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-semibold uppercase ${
                    site.business_criticality === 'critical' ? 'bg-red-500/10 text-red-400 border border-red-500/30' :
                    site.business_criticality === 'high' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/30' :
                    'bg-slate-800 text-slate-300'
                  }`}>
                    {site.business_criticality}
                  </span>
                </div>

                <p className="text-xs text-slate-400 line-clamp-2 mb-4 leading-relaxed">
                  {site.description || "No description provided."}
                </p>

                <div className="grid grid-cols-2 gap-2 text-xs bg-[#0B0F19] p-2.5 rounded-xl border border-[#1E293B] mb-4">
                  <div>
                    <span className="text-[10px] text-slate-500 block uppercase font-mono">Environment</span>
                    <span className="font-semibold text-slate-200 capitalize">{site.environment}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 block uppercase font-mono">Security Score</span>
                    <span className="font-mono font-bold text-cyan-400">{site.security_score || 100}/100</span>
                  </div>
                </div>
              </div>

              <div className="pt-3 border-t border-[#1E293B] flex items-center justify-between">
                {isVerified ? (
                  <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400 font-semibold font-mono">
                    <CheckCircle2 className="h-4 w-4" /> Verified Scope
                  </span>
                ) : (
                  <button
                    onClick={() => setShowVerifyModal(site)}
                    className="inline-flex items-center gap-1.5 text-xs text-amber-400 font-semibold hover:underline cursor-pointer"
                  >
                    <Clock className="h-4 w-4 animate-spin" /> Verify Ownership
                  </button>
                )}

                <Link
                  to={`/scans/new?website_id=${site.id}`}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-cyan-500/20 border border-slate-700 hover:border-cyan-500/40 text-white hover:text-cyan-300 rounded-xl text-xs font-semibold transition-all flex items-center gap-1 cursor-pointer"
                >
                  Scan Now <ArrowRight className="h-3 w-3" />
                </Link>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Add Website Modal */}
      <AnimatePresence>
        {showAddModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md"
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.94, y: 15 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.94, y: 15 }}
              transition={{ type: "spring", stiffness: 350, damping: 25 }}
              className="bg-[#0C101B] border border-cyan-900/50 rounded-2xl max-w-lg w-full p-6 shadow-2xl"
            >
              <div className="flex items-center justify-between pb-3 border-b border-[#1E293B] mb-4">
                <h3 className="text-base font-bold text-white">Register Target Website</h3>
                <button onClick={() => setShowAddModal(false)} className="text-slate-400 hover:text-white cursor-pointer">
                  <X className="h-5 w-5" />
                </button>
              </div>

            {formError && (
              <div className="p-3 mb-4 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-400">
                {formError}
              </div>
            )}

            <form onSubmit={handleCreate} className="space-y-3.5">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Target Name</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  placeholder="e.g. Apex Customer Portal"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Website URL (HTTP / HTTPS)</label>
                <input
                  type="url"
                  required
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 font-mono"
                  placeholder="https://example.com"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Environment</label>
                  <select
                    value={env}
                    onChange={(e) => setEnv(e.target.value)}
                    className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Development</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Criticality</label>
                  <select
                    value={criticality}
                    onChange={(e) => setCriticality(e.target.value)}
                    className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Contact Email</label>
                <input
                  type="email"
                  value={contactEmail}
                  onChange={(e) => setContactEmail(e.target.value)}
                  className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  placeholder="security@company.com"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Scope Description</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={2}
                  className="w-full bg-[#0B0F19] border border-[#1E293B] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  placeholder="Description of target system and business scope"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold cursor-pointer transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold cursor-pointer shadow-md"
                >
                  {submitting ? "Registering..." : "Confirm & Register Target"}
                </button>
              </div>
            </form>
          </motion.div>
        </motion.div>
      )}
      </AnimatePresence>

      {/* Domain Verification Modal */}
      <AnimatePresence>
        {showVerifyModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md"
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.94, y: 15 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.94, y: 15 }}
              transition={{ type: "spring", stiffness: 350, damping: 25 }}
              className="bg-[#0C101B] border border-cyan-900/50 rounded-2xl max-w-lg w-full p-6 shadow-2xl"
            >
              <div className="flex items-center justify-between pb-3 border-b border-[#1E293B] mb-4">
                <h3 className="text-base font-bold text-white">Domain Ownership Verification</h3>
                <button onClick={() => setShowVerifyModal(null)} className="text-slate-400 hover:text-white cursor-pointer">
                  <X className="h-5 w-5" />
                </button>
              </div>

              <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                To prevent unauthorized testing, prove ownership of <strong className="text-white font-mono">{showVerifyModal.domain}</strong> before active penetration testing.
              </p>

              <div className="flex gap-2 mb-4">
                <button
                  onClick={() => setVerifyMethod("dns")}
                  className={`flex-1 py-1.5 px-3 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                    verifyMethod === "dns" ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40" : "bg-slate-800 text-slate-400"
                  }`}
                >
                  DNS TXT Record
                </button>
                <button
                  onClick={() => setVerifyMethod("http")}
                  className={`flex-1 py-1.5 px-3 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                    verifyMethod === "http" ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40" : "bg-slate-800 text-slate-400"
                  }`}
                >
                  HTTP File Challenge
                </button>
                <button
                  onClick={() => setVerifyMethod("manual_admin")}
                  className={`flex-1 py-1.5 px-3 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                    verifyMethod === "manual_admin" ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40" : "bg-slate-800 text-slate-400"
                  }`}
                >
                  Admin Override
                </button>
              </div>

              {verifyMethod === "dns" && (
                <div className="bg-[#0B0F19] border border-[#1E293B] p-3 rounded-xl space-y-2 mb-4 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block">Record Type:</span>
                    <span className="text-white font-bold">TXT</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Host / Name:</span>
                    <span className="text-cyan-400 select-all">{showVerifyModal.verification_tokens?.dns_record_name || `_secureaudit.${showVerifyModal.domain}`}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Value / Content:</span>
                    <span className="text-emerald-400 select-all">{showVerifyModal.verification_tokens?.dns_txt_value || "secureaudit-verification=..."}</span>
                  </div>
                </div>
              )}

              {verifyMethod === "http" && (
                <div className="bg-[#0B0F19] border border-[#1E293B] p-3 rounded-xl space-y-2 mb-4 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block">Upload File Path:</span>
                    <span className="text-cyan-400 select-all">/.well-known/secureaudit-challenge.txt</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Expected File Content:</span>
                    <span className="text-emerald-400 select-all">{showVerifyModal.verification_tokens?.http_challenge_content}</span>
                  </div>
                </div>
              )}

              {verifyMethod === "manual_admin" && (
                <div className="bg-[#0B0F19] border border-amber-500/30 p-3 rounded-xl mb-4 text-xs text-amber-300">
                  Authorized administrators can approve target ownership under certified internal authorization rules.
                </div>
              )}

              {verifyMsg && (
                <div className="p-3 mb-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-400 flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4" /> {verifyMsg}
                </div>
              )}

              {verifyError && (
                <div className="p-3 mb-4 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-400">
                  {verifyError}
                </div>
              )}

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowVerifyModal(null)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold cursor-pointer"
                >
                  Close
                </button>
                <button
                  onClick={handleVerify}
                  disabled={verifying}
                  className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold cursor-pointer"
                >
                  {verifying ? "Checking Records..." : "Verify Ownership Now"}
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

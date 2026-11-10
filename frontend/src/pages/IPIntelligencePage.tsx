import React, { useState } from 'react';
import {
  Binary,
  Search,
  Shield,
  Server,
  Globe2,
  AlertTriangle,
  Download,
  Building,
  KeyRound,
  Compass,
} from 'lucide-react';
import { api } from '../services/api';
import { IPAnalysisResponse } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';

export const IPIntelligencePage: React.FC = () => {
  const [ipInput, setIpInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<IPAnalysisResponse | null>(null);

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ipInput.trim()) return;

    try {
      setLoading(true);
      setError(null);
      const data = await api.analyzeIp(ipInput.trim());
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'IP Analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  const getThreatColor = (score: number) => {
    if (score >= 75) return 'text-rose-400 border-rose-800 bg-rose-950/40';
    if (score >= 45) return 'text-orange-400 border-orange-800 bg-orange-950/40';
    if (score >= 20) return 'text-amber-400 border-amber-800 bg-amber-950/40';
    return 'text-cyan-400 border-cyan-800 bg-cyan-950/40';
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <Binary className="w-6 h-6 text-cyan-400" />
          IP Intelligence Analyzer
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          IPv4 / IPv6 network classification, BGP autonomous system profiling, reverse DNS, and multi-source threat reputation.
        </p>
      </div>

      {/* Input Form */}
      <div className="p-6 rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl">
        <form onSubmit={handleAnalyze} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-grow">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              <Binary className="w-4 h-4" />
            </div>
            <input
              type="text"
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              placeholder="Enter IPv4 or IPv6 address (e.g. 8.8.8.8 or 2001:4860:4860::8888)"
              className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-slate-700 bg-slate-900/80 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-all font-mono"
              disabled={loading}
            />
          </div>
          <button
            type="submit"
            disabled={loading || !ipInput.trim()}
            className="flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-sm transition-all shadow-lg shadow-cyan-950/50 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {loading ? (\n              <>\n                <Search className="w-4 h-4 animate-spin" />
                Analyzing Address...
              </>
            ) : (
              <>
                <Search className="w-4 h-4" />
                Analyze IP
              </>
            )}
          </button>
        </form>

        <div className="mt-3 flex items-center gap-2 text-[11px] text-slate-500">
          <Shield className="w-3.5 h-3.5 text-cyan-500" />
          <span>Zero external hard-dependencies: Operates 100% offline via local RFC classification & cached threat databases.</span>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-rose-900/80 bg-rose-950/40 text-rose-300 text-xs flex items-center gap-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Result Section */}
      {result && (
        <div className="space-y-6">
          {/* Executive IP Card */}
          <div className="p-6 rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
                <span>IPv{result.ip_version} ADDRESS</span>
                <span>•</span>
                <span className="uppercase text-slate-400">{result.classification}</span>
                <span>•</span>
                <span className="text-slate-400">{new Date(result.created_at).toLocaleString()}</span>
              </div>
              <h2 className="text-xl font-mono font-bold text-white break-all">{result.ip_address}</h2>
              <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 pt-1">
                <span>PTR: <code className="text-cyan-300 font-mono">{result.reverse_dns}</code></span>
                <span>•</span>
                <span>ASN: <span className="font-semibold text-white">{result.asn}</span></span>
                <span>•</span>
                <span>Organization: <span className="font-semibold text-white">{result.as_org}</span></span>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <div className={`p-4 rounded-2xl border text-center ${getThreatColor(result.reputation_score)}`}>
                <div className="text-3xl font-extrabold tracking-tight">{result.reputation_score}</div>
                <div className="text-[10px] font-bold uppercase tracking-wider mt-0.5">Threat Score</div>
              </div>

              <div className="flex flex-col gap-2">
                <a
                  href={api.getIpReportPdfUrl(result.id)}
                  download
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900/80 hover:bg-slate-800 text-xs font-medium text-slate-200 transition-colors"
                >
                  <Download className="w-3.5 h-3.5 text-cyan-400" />
                  PDF Report
                </a>
                <a
                  href={api.getIpReportJsonUrl(result.id)}
                  download
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900/80 hover:bg-slate-800 text-xs font-medium text-slate-200 transition-colors"
                >
                  <Download className="w-3.5 h-3.5 text-slate-400" />
                  JSON Export
                </a>
              </div>
            </div>
          </div>

          {/* Classification & Telemetry Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Geolocation Card */}
            <div className="p-5 rounded-xl border border-slate-800 bg-[#0c1220]/80">
              <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-3">
                <Globe2 className="w-4 h-4" />
                Approximate Geolocation
              </div>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-400">Country:</span>
                  <span className="text-white font-medium">{result.country_name || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">City / Subnet:</span>
                  <span className="text-white font-medium">{result.city || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Country Code:</span>
                  <span className="text-white font-mono">{result.country_code || '--'}</span>
                </div>
              </div>
            </div>

            {/* Network Infrastructure Card */}
            <div className="p-5 rounded-xl border border-slate-800 bg-[#0c1220]/80">
              <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-3">
                <Server className="w-4 h-4" />
                Network Classification
              </div>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-400">Datacenter / Hosting:</span>
                  <span className={result.is_datacenter ? 'text-amber-400 font-semibold' : 'text-slate-300'}>
                    {result.is_datacenter ? 'Detected' : 'No'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Commercial VPN:</span>
                  <span className={result.is_vpn ? 'text-amber-400 font-semibold' : 'text-slate-300'}>
                    {result.is_vpn ? 'Detected' : 'No'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Public Proxy:</span>
                  <span className={result.is_proxy ? 'text-amber-400 font-semibold' : 'text-slate-300'}>
                    {result.is_proxy ? 'Detected' : 'No'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Tor Exit Node:</span>
                  <span className={result.is_tor ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                    {result.is_tor ? 'Confirmed' : 'No'}
                  </span>
                </div>
              </div>
            </div>

            {/* Intelligence Providers Card */}
            <div className="p-5 rounded-xl border border-slate-800 bg-[#0c1220]/80">
              <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-3">
                <Building className="w-4 h-4" />
                Source Attribution
              </div>
              <div className="space-y-2 text-xs">
                {Object.entries(result.provider_sources).map(([key, sourceName]) => (
                  <div key={key} className="flex justify-between items-center">
                    <span className="text-slate-400 font-mono text-[11px] uppercase">{key}:</span>
                    <span className="text-cyan-300 truncate max-w-[170px] text-right">{sourceName}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Threat Signals Breakdown */}
          <div className="rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl overflow-hidden">
            <div className="p-5 border-b border-slate-800">
              <h3 className="text-sm font-semibold text-white tracking-wide">
                Observable Threat & Reputation Signals ({result.signals.length})
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Measurable indicators with source verification. Datacenter or VPN usage is not proof of malice.
              </p>
            </div>

            <div className="divide-y divide-slate-800">
              {result.signals.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-500">
                  No adverse reputation reports or anonymization signals recorded for this address.
                </div>
              ) : (
                result.signals.map((sig, i) => (
                  <div key={i} className="p-5 hover:bg-slate-900/30 transition-colors space-y-1.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2.5">
                        <span className="text-sm font-bold text-white">{sig.indicator}</span>
                        <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                          {sig.category}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono text-slate-400">Source: {sig.source}</span>
                        <SeverityBadge severity={sig.severity} />
                      </div>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">{sig.details}</p>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Disclaimer Footer */}
          <div className="p-4 rounded-xl border border-slate-800/80 bg-slate-900/30 text-[11px] text-slate-500 leading-relaxed">
            {result.disclaimer}
          </div>
        </div>
      )}
    </div>
  );
};

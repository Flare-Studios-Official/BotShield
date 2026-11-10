import React, { useState } from 'react';
import {
  Globe,
  Search,
  Shield,
  Lock,
  FileText,
  Clock,
  ArrowRight,
  Download,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Layers,
} from 'lucide-react';
import { api } from '../services/api';
import { WebsiteScanResponse } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';

export const WebsiteScannerPage: React.FC = () => {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<WebsiteScanResponse | null>(null);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) return;

    try {
      setLoading(true);
      setError(null);
      const scanData = await api.scanWebsite(urlInput.trim());
      setResult(scanData);
    } catch (err: any) {
      setError(err.message || 'Scan failed.');
    } finally {
      setLoading(false);
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-emerald-400 border-emerald-800 bg-emerald-950/40';
    if (score >= 50) return 'text-amber-400 border-amber-800 bg-amber-950/40';
    return 'text-rose-400 border-rose-800 bg-rose-950/40';
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <Globe className="w-6 h-6 text-cyan-400" />
          Website Security Scanner
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          SSRF-defended passive security inspection: TLS posture, HTTP headers, robots.txt, rate limits, and bot defense profiling.
        </p>
      </div>

      {/* Input Form */}
      <div className="p-6 rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl">
        <form onSubmit={handleScan} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-grow">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              <Globe className="w-4 h-4" />
            </div>
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter website target (e.g. https://example.com or scanme.nmap.org)"
              className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-slate-700 bg-slate-900/80 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-all font-mono"
              disabled={loading}
            />
          </div>
          <button
            type="submit"
            disabled={loading || !urlInput.trim()}
            className="flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-sm transition-all shadow-lg shadow-cyan-950/50 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {loading ? (
              <>
                <Search className="w-4 h-4 animate-spin" />
                Scanning Target...
              </>
            ) : (
              <>
                <Search className="w-4 h-4" />
                Inspect Website
              </>
            )}
          </button>
        </form>

        <div className="mt-3 flex items-center gap-2 text-[11px] text-slate-500">
          <Shield className="w-3.5 h-3.5 text-cyan-500" />
          <span>SSRF Guard active: Private RFC 1918, loopback, and cloud metadata targets are strictly blocked.</span>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-rose-900/80 bg-rose-950/40 text-rose-300 text-xs flex items-center gap-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 text-rose-400" />
          <div>
            <div className="font-semibold text-rose-200">Security Check Rejection / Error</div>
            <div className="mt-0.5">{error}</div>
          </div>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          {/* Executive Overview Banner */}
          <div className="p-6 rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
                <span>AUDIT TARGET</span>
                <span>•</span>
                <span className="text-slate-400">{new Date(result.created_at).toLocaleString()}</span>
              </div>
              <h2 className="text-lg font-bold text-white break-all">{result.target_url}</h2>
              <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 pt-1">
                <span>Resolved IP: <code className="text-cyan-300 font-mono">{result.resolved_ip}</code></span>
                <span>•</span>
                <span>HTTP Status: <span className="font-semibold text-white">{result.status_code}</span></span>
                <span>•</span>
                <span>Latency: <span className="font-semibold text-white">{result.response_time_ms} ms</span></span>
                <span>•</span>
                <span>Redirects: <span className="font-semibold text-white">{result.redirect_count}</span></span>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <div className={`p-4 rounded-2xl border text-center ${getScoreColor(result.security_score)}`}>
                <div className="text-3xl font-extrabold tracking-tight">{result.security_score}</div>
                <div className="text-[10px] font-bold uppercase tracking-wider mt-0.5">Security Score</div>
              </div>

              <div className="flex flex-col gap-2">
                <a
                  href={api.getWebsiteReportPdfUrl(result.id)}
                  download
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900/80 hover:bg-slate-800 text-xs font-medium text-slate-200 transition-colors"
                >
                  <Download className="w-3.5 h-3.5 text-cyan-400" />
                  PDF Report
                </a>
                <a
                  href={api.getWebsiteReportJsonUrl(result.id)}
                  download
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900/80 hover:bg-slate-800 text-xs font-medium text-slate-200 transition-colors"
                >
                  <Download className="w-3.5 h-3.5 text-slate-400" />
                  JSON Export
                </a>
              </div>
            </div>
          </div>

          {/* Key Infrastructure Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* TLS & HTTPS Card */}
            <div className="p-5 rounded-xl border border-slate-800 bg-[#0c1220]/80">
              <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-3">
                <Lock className="w-4 h-4" />
                TLS & HTTPS Security
              </div>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-400">HTTPS Enforced:</span>
                  <span className={result.https_enforced ? 'text-emerald-400 font-semibold' : 'text-rose-400 font-semibold'}>
                    {result.https_enforced ? 'Yes' : 'No'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">TLS Protocol:</span>
                  <span className="text-white font-mono">{result.tls_version || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Certificate Issuer:</span>
                  <span className="text-white truncate max-w-[150px]">{result.tls_cert_issuer || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Cert Expiry:</span>
                  <span className="text-white font-mono text-[11px]">{result.tls_cert_expiry || 'N/A'}</span>
                </div>
              </div>
            </div>

            {/* Server & Transport */}
            <div className="p-5 rounded-xl border border-slate-800 bg-[#0c1220]/80">
              <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-3">
                <Layers className="w-4 h-4" />
                Transport Details
              </div>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-400">Server Header:</span>
                  <span className="text-white font-mono">{result.server_header || 'Hidden'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Content Type:</span>
                  <span className="text-white truncate max-w-[150px]">{result.content_type}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Payload Size:</span>
                  <span className="text-white font-mono">{(result.content_length / 1024).toFixed(1)} KB</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Final Destination:</span>
                  <span className="text-white font-mono text-[11px] truncate max-w-[150px]">{result.final_url}</span>
                </div>
              </div>
            </div>

            {/* Redirect Traversal Chain */}
            <div className="p-5 rounded-xl border border-slate-800 bg-[#0c1220]/80">
              <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-3">
                <ArrowRight className="w-4 h-4" />
                Redirect Traversal ({result.redirect_chain.length} hop{result.redirect_chain.length !== 1 ? 's' : ''})
              </div>
              <div className="space-y-1.5 text-xs max-h-32 overflow-y-auto pr-1">
                {result.redirect_chain.map((hop, i) => (
                  <div key={i} className="flex items-center gap-2 text-[11px] font-mono text-slate-300">
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 text-[10px]">
                      {hop.status_code}
                    </span>
                    <span className="truncate">{hop.url}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Detailed Findings Matrix */}
          <div className="rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl overflow-hidden">
            <div className="p-5 border-b border-slate-800">
              <h3 className="text-sm font-semibold text-white tracking-wide">
                Security Findings & Recommendations ({result.findings.length})
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Evaluated security headers, crawl directives, rate limits, and perimeter signatures.
              </p>
            </div>

            <div className="divide-y divide-slate-800">
              {result.findings.map((f) => (
                <div key={f.id} className="p-5 hover:bg-slate-900/30 transition-colors space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                      <span className="text-sm font-bold text-white">{f.name}</span>
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                        {f.category}
                      </span>
                    </div>
                    <SeverityBadge severity={f.severity} />
                  </div>

                  <div className="text-xs font-mono text-cyan-300 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80 break-all">
                    Observed: {f.observed_value}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs pt-1">
                    <div>
                      <span className="font-semibold text-slate-300">Security Implication:</span>
                      <p className="text-slate-400 mt-0.5 leading-relaxed">{f.implication}</p>
                    </div>
                    <div>
                      <span className="font-semibold text-cyan-400">Recommended Action:</span>
                      <p className="text-slate-300 mt-0.5 leading-relaxed">{f.recommendation}</p>
                    </div>
                  </div>
                </div>
              ))}
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

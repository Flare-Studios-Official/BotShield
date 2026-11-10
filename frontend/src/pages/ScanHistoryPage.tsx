import React, { useEffect, useState } from 'react';
import {
  History,
  Globe,
  Binary,
  Network,
  Download,
  Search,
  RefreshCw,
  ExternalLink,
} from 'lucide-react';
import { api } from '../services/api';
import { IPAnalysisResponse, ProxyTestResponse, WebsiteScanSummary } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';

export const ScanHistoryPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'websites' | 'ips' | 'proxies'>('websites');
  const [websiteScans, setWebsiteScans] = useState<WebsiteScanSummary[]>([]);
  const [ipScans, setIpScans] = useState<IPAnalysisResponse[]>([]);
  const [proxyTests, setProxyTests] = useState<ProxyTestResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  const loadHistory = async () => {
    try {
      setLoading(true);
      const [w, ip, p] = await Promise.all([
        api.listWebsiteScans(50, 0),
        api.getIpHistory(50),
        api.getProxyHistory(50),
      ]);
      setWebsiteScans(w);
      setIpScans(ip);
      setProxyTests(p);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const filteredWebsites = websiteScans.filter((s) =>
    s.target_url.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredIps = ipScans.filter((i) =>
    i.ip_address.includes(searchTerm) || i.as_org.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredProxies = proxyTests.filter((p) =>
    p.proxy_host.includes(searchTerm) || p.target_tested.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <History className="w-6 h-6 text-cyan-400" />
            Audit & Scan History
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Historical repository of website inspections, IP intelligence lookups, and proxy audits.
          </p>
        </div>
        <button
          onClick={loadHistory}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900/60 hover:bg-slate-800 text-xs font-medium text-slate-300 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Tabs & Search Filter */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('websites')}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'websites'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Globe className="w-4 h-4" />
            Websites ({websiteScans.length})
          </button>
          <button
            onClick={() => setActiveTab('ips')}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'ips'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Binary className="w-4 h-4" />
            IP Intelligence ({ipScans.length})
          </button>
          <button
            onClick={() => setActiveTab('proxies')}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'proxies'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Network className="w-4 h-4" />
            Proxies ({proxyTests.length})
          </button>
        </div>

        <div className="relative">
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search targets or hostnames..."
            className="pl-8 pr-4 py-1.5 rounded-lg border border-slate-700 bg-slate-900 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono w-64"
          />
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
        </div>
      </div>

      {/* Website Scans Table */}
      {activeTab === 'websites' && (\n        <div className="rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl overflow-hidden">
          {filteredWebsites.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500">No website scans match query.</div>
          ) : (
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase tracking-wider font-mono text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-5">Target URL</th>
                  <th className="py-3 px-5">Status</th>
                  <th className="py-3 px-5">Security Score</th>
                  <th className="py-3 px-5">Findings</th>
                  <th className="py-3 px-5">Timestamp</th>
                  <th className="py-3 px-5 text-right">Reports</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {filteredWebsites.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3.5 px-5 font-mono text-white font-medium truncate max-w-xs">{s.target_url}</td>
                    <td className="py-3.5 px-5">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 text-[10px] font-bold">
                        {s.status_code}
                      </span>
                    </td>
                    <td className="py-3.5 px-5 font-bold font-mono text-white">{s.security_score}/100</td>
                    <td className="py-3.5 px-5 text-slate-400">{s.finding_count} findings</td>
                    <td className="py-3.5 px-5 text-slate-500">{new Date(s.created_at).toLocaleString()}</td>
                    <td className="py-3.5 px-5 text-right space-x-2">
                      <a
                        href={api.getWebsiteReportPdfUrl(s.id)}
                        download
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 text-[11px] text-cyan-300 font-medium"
                      >
                        <Download className="w-3 h-3" /> PDF
                      </a>
                      <a
                        href={api.getWebsiteReportJsonUrl(s.id)}
                        download
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 text-[11px] text-slate-300 font-medium"
                      >
                        JSON
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* IP Intelligence Table */}
      {activeTab === 'ips' && (
        <div className="rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl overflow-hidden">
          {filteredIps.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500">No IP records match query.</div>
          ) : (
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase tracking-wider font-mono text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-5">IP Address</th>
                  <th className="py-3 px-5">Routing</th>
                  <th className="py-3 px-5">Threat Level</th>
                  <th className="py-3 px-5">Autonomous System</th>
                  <th className="py-3 px-5">Country</th>
                  <th className="py-3 px-5">Timestamp</th>
                  <th className="py-3 px-5 text-right">Reports</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {filteredIps.map((i) => (
                  <tr key={i.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3.5 px-5 font-mono text-white font-medium">{i.ip_address}</td>
                    <td className="py-3.5 px-5 uppercase text-[10px] font-mono text-slate-400">{i.classification}</td>
                    <td className="py-3.5 px-5">
                      <SeverityBadge severity={i.threat_level} />
                    </td>
                    <td className="py-3.5 px-5 text-slate-300 truncate max-w-xs">{i.as_org}</td>
                    <td className="py-3.5 px-5 text-slate-400">{i.country_name || '--'}</td>
                    <td className="py-3.5 px-5 text-slate-500">{new Date(i.created_at).toLocaleString()}</td>
                    <td className="py-3.5 px-5 text-right space-x-2">
                      <a
                        href={api.getIpReportPdfUrl(i.id)}
                        download
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 text-[11px] text-cyan-300 font-medium"
                      >
                        <Download className="w-3 h-3" /> PDF
                      </a>
                      <a
                        href={api.getIpReportJsonUrl(i.id)}
                        download
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 text-[11px] text-slate-300 font-medium"
                      >
                        JSON
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Proxy Audits Table */}
      {activeTab === 'proxies' && (
        <div className="rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl overflow-hidden">
          {filteredProxies.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500">No proxy tests match query.</div>
          ) : (
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase tracking-wider font-mono text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-5">Proxy Endpoint</th>
                  <th className="py-3 px-5">Protocol</th>
                  <th className="py-3 px-5">Status</th>
                  <th className="py-3 px-5">Latency</th>
                  <th className="py-3 px-5">Egress IP</th>
                  <th className="py-3 px-5">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {filteredProxies.map((p) => (
                  <tr key={p.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3.5 px-5 font-mono text-white font-medium">{p.proxy_host}:{p.proxy_port}</td>
                    <td className="py-3.5 px-5 uppercase font-mono text-cyan-400 text-[10px]">{p.proxy_scheme}</td>
                    <td className="py-3.5 px-5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        p.success ? 'bg-emerald-950 text-emerald-400' : 'bg-rose-950 text-rose-400'
                      }`}>
                        {p.success ? 'ONLINE' : 'FAILED'}
                      </span>
                    </td>
                    <td className="py-3.5 px-5 text-slate-300 font-mono">{p.latency_ms} ms</td>
                    <td className="py-3.5 px-5 font-mono text-cyan-300">{p.egress_ip || 'None'}</td>
                    <td className="py-3.5 px-5 text-slate-500">{new Date(p.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
};

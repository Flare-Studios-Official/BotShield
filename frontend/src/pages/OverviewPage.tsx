import React, { useEffect, useState } from 'react';
import {
  Globe,
  Bot,
  Binary,
  Network,
  Activity,
  ShieldCheck,
  AlertTriangle,
  ArrowUpRight,
  RefreshCw,
} from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';
import { api } from '../services/api';
import { BotDashboardSummary, WebsiteScanSummary } from '../types';
import { MetricCard } from '../components/MetricCard';
import { SeverityBadge } from '../components/SeverityBadge';
import { NavItem } from '../components/Sidebar';

interface Props {
  onNavigate: (tab: NavItem) => void;
}

export const OverviewPage: React.FC<Props> = ({ onNavigate }) => {
  const [summary, setSummary] = useState<BotDashboardSummary | null>(null);
  const [recentScans, setRecentScans] = useState<WebsiteScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [sumData, scansData] = await Promise.all([
        api.getBotSummary(),
        api.listWebsiteScans(5, 0),
      ]);
      setSummary(sumData);
      setRecentScans(scansData);
    } catch (err: any) {
      setError(err.message || 'Failed to load telemetry data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const riskChartData = summary
    ? [
        { name: 'Low', count: summary.risk_distribution.low || 0, color: '#06b6d4' },
        { name: 'Moderate', count: summary.risk_distribution.moderate || 0, color: '#f59e0b' },
        { name: 'High', count: summary.risk_distribution.high || 0, color: '#f97316' },
        { name: 'Critical', count: summary.risk_distribution.critical || 0, color: '#f43f5e' },
      ]
    : [];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Security Operations Overview</h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time defensive posture, behavioral telemetry stream, and intelligence summary.
          </p>
        </div>
        <button
          onClick={loadData}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900/60 hover:bg-slate-800 text-xs font-medium text-slate-300 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-rose-900/80 bg-rose-950/40 text-rose-300 text-xs flex items-center gap-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Telemetry Events"
          value={summary ? summary.total_events.toLocaleString() : '0'}
          subtitle="Processed request logs"
          icon={<Activity className="w-5 h-5" />}
          badge="Live"
          badgeColor="emerald"
        />
        <MetricCard
          title="Velocity (RPM)"
          value={summary ? summary.requests_per_minute.toFixed(1) : '0.0'}
          subtitle="Requests per minute"
          icon={<Bot className="w-5 h-5" />}
          badge="60s window"
          badgeColor="cyan"
        />
        <MetricCard
          title="Unique Source IPs"
          value={summary ? summary.unique_ips : '0'}
          subtitle="Monitored client addresses"
          icon={<Binary className="w-5 h-5" />}
          badgeColor="cyan"
        />
        <MetricCard
          title="Suspicious Clients"
          value={summary ? summary.suspicious_count : '0'}
          subtitle="Triggered heuristic thresholds"
          icon={<AlertTriangle className="w-5 h-5" />}
          badge={summary && summary.suspicious_count > 0 ? 'Review Needed' : 'Clean'}
          badgeColor={summary && summary.suspicious_count > 0 ? 'rose' : 'emerald'}
        />
      </div>

      {/* Core Modules Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div
          onClick={() => onNavigate('websites')}
          className="group cursor-pointer p-5 rounded-xl border border-slate-800 bg-[#0c1220]/60 hover:border-cyan-500/50 hover:bg-slate-900/40 transition-all shadow-md"
        >
          <div className="flex items-center justify-between text-cyan-400 mb-3">
            <Globe className="w-6 h-6" />
            <ArrowUpRight className="w-4 h-4 opacity-50 group-hover:opacity-100 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
          </div>
          <h3 className="font-semibold text-white text-sm">Website Security</h3>
          <p className="text-xs text-slate-400 mt-1">Audit security headers, TLS posture, robots.txt, and bot defenses.</p>
        </div>

        <div
          onClick={() => onNavigate('ips')}
          className="group cursor-pointer p-5 rounded-xl border border-slate-800 bg-[#0c1220]/60 hover:border-cyan-500/50 hover:bg-slate-900/40 transition-all shadow-md"
        >
          <div className="flex items-center justify-between text-cyan-400 mb-3">
            <Binary className="w-6 h-6" />
            <ArrowUpRight className="w-4 h-4 opacity-50 group-hover:opacity-100 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
          </div>
          <h3 className="font-semibold text-white text-sm">IP Intelligence</h3>
          <p className="text-xs text-slate-400 mt-1">Investigate ASN, geolocation, reverse DNS, and threat reputation feeds.</p>
        </div>

        <div
          onClick={() => onNavigate('bots')}
          className="group cursor-pointer p-5 rounded-xl border border-slate-800 bg-[#0c1220]/60 hover:border-cyan-500/50 hover:bg-slate-900/40 transition-all shadow-md"
        >
          <div className="flex items-center justify-between text-cyan-400 mb-3">
            <Bot className="w-6 h-6" />
            <ArrowUpRight className="w-4 h-4 opacity-50 group-hover:opacity-100 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
          </div>
          <h3 className="font-semibold text-white text-sm">Bot Detection</h3>
          <p className="text-xs text-slate-400 mt-1">Inspect behavioral anomalies, 404 fuzzing, and burst clustering.</p>
        </div>

        <div
          onClick={() => onNavigate('lab')}
          className="group cursor-pointer p-5 rounded-xl border border-slate-800 bg-[#0c1220]/60 hover:border-cyan-500/50 hover:bg-slate-900/40 transition-all shadow-md"
        >
          <div className="flex items-center justify-between text-cyan-400 mb-3">
            <Network className="w-6 h-6" />
            <ArrowUpRight className="w-4 h-4 opacity-50 group-hover:opacity-100 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
          </div>
          <h3 className="font-semibold text-white text-sm">Detection Lab</h3>
          <p className="text-xs text-slate-400 mt-1">Benchmark rules with reproducible, isolated local attack simulations.</p>
        </div>
      </div>

      {/* Charts & Recent Scans Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution Chart */}
        <div className="rounded-xl border border-slate-800 bg-[#0c1220]/80 p-5 shadow-lg">
          <h3 className="text-sm font-semibold text-white tracking-wide mb-1">Evaluated Client Risk Tiers</h3>
          <p className="text-xs text-slate-400 mb-4">Distribution of analyzed clients across risk categories.</p>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskChartData}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {riskChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent Website Scans */}
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-[#0c1220]/80 p-5 shadow-lg flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-semibold text-white tracking-wide">Recent Website Assessments</h3>
                <p className="text-xs text-slate-400 mt-0.5">Latest passive target inspections.</p>
              </div>
              <button
                onClick={() => onNavigate('websites')}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
              >
                New Scan <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {recentScans.length === 0 ? (
              <div className="h-44 flex flex-col items-center justify-center text-center p-6 border border-dashed border-slate-800 rounded-lg">
                <Globe className="w-8 h-8 text-slate-600 mb-2" />
                <div className="text-xs text-slate-400 font-medium">No website scans on record.</div>
                <div className="text-[11px] text-slate-500 mt-1 max-w-sm">
                  Run a non-invasive passive security inspection on any authorized target website.
                </div>
              </div>
            ) : (\n              <div className="divide-y divide-slate-800/80">
                {recentScans.map((s) => (
                  <div key={s.id} className="py-3 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded bg-slate-900 border border-slate-800 text-cyan-400">
                        <Globe className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-white truncate max-w-xs">{s.target_url}</div>
                        <div className="text-[10px] text-slate-500">
                          {new Date(s.created_at).toLocaleString()} • {s.finding_count} finding(s)
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="text-right">
                        <div className="text-xs font-bold text-white">{s.security_score}/100</div>
                        <div className="text-[10px] text-slate-400">Score</div>
                      </div>
                      <SeverityBadge
                        severity={
                          s.security_score >= 80 ? 'low' : s.security_score >= 50 ? 'medium' : 'high'
                        }
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

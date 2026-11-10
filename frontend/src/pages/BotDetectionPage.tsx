import React, { useEffect, useState } from 'react';
import {
  Bot,
  AlertTriangle,
  Activity,
  CheckCircle,
  Eye,
  RefreshCw,
  Search,
  Filter,
  CheckCheck,
} from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';
import { api } from '../services/api';
import { BotDashboardSummary, BotDetectionResult, BotEvent } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';

export const BotDetectionPage: React.FC = () => {
  const [summary, setSummary] = useState<BotDashboardSummary | null>(null);
  const [events, setEvents] = useState<BotEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedDetection, setSelectedDetection] = useState<BotDetectionResult | null>(null);
  const [filterIp, setFilterIp] = useState('');

  // Review Modal state
  const [reviewModalOpen, setReviewModalOpen] = useState(false);
  const [analystName, setAnalystName] = useState('');
  const [reviewNotes, setReviewNotes] = useState('');
  const [isFalsePositive, setIsFalsePositive] = useState(false);
  const [submittingReview, setSubmittingReview] = useState(false);

  const loadData = async () => {
    try {
      setLoading(true);
      const [sumData, eventData] = await Promise.all([
        api.getBotSummary(),
        api.listBotEvents(50, filterIp || undefined),
      ]);
      setSummary(sumData);
      setEvents(eventData);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const timer = setInterval(() => {
      api.getBotSummary().then(setSummary).catch(() => {});
      api.listBotEvents(50, filterIp || undefined).then(setEvents).catch(() => {});
    }, 6000); // 6-second auto-poll
    return () => clearInterval(timer);
  }, [filterIp]);

  const handleOpenReview = (detection: BotDetectionResult) => {
    setSelectedDetection(detection);
    setAnalystName(detection.reviewed_by || 'Security Analyst');
    setReviewNotes(detection.review_notes || '');
    setIsFalsePositive(detection.is_false_positive || false);
    setReviewModalOpen(true);
  };

  const submitReview = async () => {
    if (!selectedDetection) return;
    try {
      setSubmittingReview(true);
      const updated = await api.reviewDetection(
        selectedDetection.id,
        analystName,
        reviewNotes,
        isFalsePositive
      );
      setSelectedDetection(updated);
      setReviewModalOpen(false);
      loadData();
    } catch (err) {
      console.error(err);
    } finally {
      setSubmittingReview(false);
    }
  };

  const statusColors: Record<number, string> = {
    200: '#10b981',
    404: '#f59e0b',
    429: '#f43f5e',
    403: '#f97316',
    500: '#ef4444',
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <Bot className="w-6 h-6 text-cyan-400" />
            Behavioral Bot Detection Engine
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time multi-signal request telemetry: burst velocity, 404 probing, automation markers, and rate-limit violations.
          </p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900/60 hover:bg-slate-800 text-xs font-medium text-slate-300 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Feed
        </button>
      </div>

      {/* Top Suspicious IPs Leaderboard */}
      <div className="rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white tracking-wide">
              Top Suspicious Sources ({summary ? summary.top_suspicious_ips.length : 0})
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Clients flagged for exceeding behavioral heuristics and threat thresholds.
            </p>
          </div>
        </div>

        {summary && summary.top_suspicious_ips.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">
            No anomalous traffic patterns flagged. Normal traffic observed.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase tracking-wider font-mono text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-5">Source IP</th>
                  <th className="py-3 px-5">Risk Tier</th>
                  <th className="py-3 px-5">Threat Score</th>
                  <th className="py-3 px-5">Request Volume</th>
                  <th className="py-3 px-5">Last Activity</th>
                  <th className="py-3 px-5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {summary?.top_suspicious_ips.map((ip) => (
                  <tr key={ip.source_ip} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3.5 px-5 font-mono font-medium text-white">{ip.source_ip}</td>
                    <td className="py-3.5 px-5">
                      <SeverityBadge severity={ip.risk_level} />
                    </td>
                    <td className="py-3.5 px-5 font-mono font-bold text-cyan-400">{ip.risk_score}/100</td>
                    <td className="py-3.5 px-5 text-slate-300">{ip.request_count} reqs</td>
                    <td className="py-3.5 px-5 text-slate-400">{new Date(ip.last_seen).toLocaleTimeString()}</td>
                    <td className="py-3.5 px-5 text-right">
                      <button
                        onClick={() => {
                          const det = summary?.recent_detections.find((d) => d.source_ip === ip.source_ip);
                          if (det) setSelectedDetection(det);
                        }}
                        className="px-2.5 py-1 rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 text-[11px] text-cyan-300 font-medium transition-colors"
                      >
                        Inspect Evidence
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Telemetry Charts & Paths Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Status Distribution */}
        <div className="rounded-xl border border-slate-800 bg-[#0c1220]/80 p-5 shadow-lg">
          <h3 className="text-sm font-semibold text-white tracking-wide mb-1">HTTP Response Status Codes</h3>
          <p className="text-xs text-slate-400 mb-4">Real distribution of server responses (200, 404, 429).</p>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={summary?.status_distribution || []}>
                <XAxis dataKey="status_code" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {summary?.status_distribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={statusColors[entry.status_code] || '#3b82f6'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Requested Endpoints */}
        <div className="rounded-xl border border-slate-800 bg-[#0c1220]/80 p-5 shadow-lg">
          <h3 className="text-sm font-semibold text-white tracking-wide mb-1">Top Requested Paths</h3>
          <p className="text-xs text-slate-400 mb-4">Endpoints experiencing highest query density.</p>
          <div className="space-y-2">
            {summary?.top_paths.slice(0, 5).map((p, i) => (\n              <div key={i} className="flex items-center justify-between text-xs p-2 rounded bg-slate-900/50 border border-slate-800/80 font-mono">
                <span className="text-slate-300 truncate max-w-xs">{p.path}</span>
                <span className="text-cyan-400 font-bold px-2 py-0.5 rounded bg-slate-800">{p.count} hits</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Live Request Telemetry Log Table */}
      <div className="rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-white tracking-wide">Live Request Telemetry Stream</h3>
            <p className="text-xs text-slate-400 mt-0.5">Chronological audit log captured by local telemetry collector.</p>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={filterIp}
              onChange={(e) => setFilterIp(e.target.value)}
              placeholder="Filter by Source IP..."
              className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        {events.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">
            No events recorded yet. Run the Detection Lab to simulate controlled live traffic.
          </div>
        ) : (
          <div className="overflow-x-auto max-h-96 overflow-y-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="sticky top-0 bg-slate-900 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-4">Timestamp</th>
                  <th className="py-2.5 px-4">Method</th>
                  <th className="py-2.5 px-4">Path</th>
                  <th className="py-2.5 px-4">Source IP</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">Latency</th>
                  <th className="py-2.5 px-4">User-Agent</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-[11px]">
                {events.map((e) => (
                  <tr key={e.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-2.5 px-4 text-slate-400">{new Date(e.timestamp).toLocaleTimeString()}</td>
                    <td className="py-2.5 px-4 font-bold text-cyan-400">{e.http_method}</td>
                    <td className="py-2.5 px-4 text-slate-200 truncate max-w-xs">{e.path}</td>
                    <td className="py-2.5 px-4 text-slate-300">{e.source_ip}</td>
                    <td className="py-2.5 px-4">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        e.response_status === 200 ? 'bg-emerald-950 text-emerald-400' :
                        e.response_status === 404 ? 'bg-amber-950 text-amber-400' :
                        e.response_status === 429 ? 'bg-rose-950 text-rose-400' : 'bg-slate-800 text-slate-300'
                      }`}>
                        {e.response_status}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-400">{e.duration_ms} ms</td>
                    <td className="py-2.5 px-4 text-slate-500 truncate max-w-[200px]">{e.user_agent || 'Empty'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Detection Evidence Modal */}
      {selectedDetection && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="max-w-2xl w-full rounded-2xl border border-slate-700 bg-[#0d1322] shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div>
                <div className="text-xs font-mono text-cyan-400">BEHAVIORAL EVIDENCE AUDIT</div>
                <h3 className="text-base font-bold text-white mt-0.5 font-mono">{selectedDetection.source_ip}</h3>
              </div>
              <SeverityBadge severity={selectedDetection.risk_level} size="md" />
            </div>

            <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto">
              {/* Score & Review Header */}
              <div className="flex items-center justify-between p-4 rounded-xl bg-slate-900 border border-slate-800">
                <div>
                  <div className="text-xs text-slate-400">Risk Indicator Score</div>
                  <div className="text-2xl font-extrabold text-cyan-400 font-mono mt-0.5">
                    {selectedDetection.risk_score} / 100
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-xs text-slate-400">Review Status</div>
                  <div className="text-xs font-semibold mt-0.5">
                    {selectedDetection.reviewed ? (
                      <span className="text-emerald-400 flex items-center gap-1 justify-end">
                        <CheckCheck className="w-3.5 h-3.5" /> Reviewed by {selectedDetection.reviewed_by}
                      </span>
                    ) : (
                      <span className="text-amber-400">Pending Review</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Triggered Rules Breakdown */}
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
                  Triggered Detection Rules ({selectedDetection.triggered_rules.length})
                </h4>
                <div className="space-y-2">
                  {selectedDetection.triggered_rules.map((rule, idx) => (
                    <div key={idx} className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/60 text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white">{rule.rule_name}</span>
                        <span className="font-mono text-cyan-400 font-bold">+{rule.points_awarded} pts</span>
                      </div>
                      <p className="text-slate-400 leading-relaxed">{rule.explanation}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Behavioral Evidence */}
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Measurable Evidence</h4>
                <ul className="list-disc list-inside text-xs text-slate-300 space-y-1 bg-slate-950 p-3 rounded-lg border border-slate-800">
                  {selectedDetection.evidence.map((ev, i) => (
                    <li key={i}>{ev}</li>
                  ))}
                </ul>
              </div>

              {selectedDetection.reviewed && selectedDetection.review_notes && (
                <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/40 text-xs">
                  <span className="font-semibold text-slate-300">Analyst Review Notes:</span>
                  <p className="text-slate-400 mt-1">{selectedDetection.review_notes}</p>
                  {selectedDetection.is_false_positive && (
                    <span className="inline-block mt-2 px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-bold">
                      Flagged as False Positive
                    </span>
                  )}
                </div>
              )}
            </div>

            <div className="p-4 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between">
              <button
                onClick={() => handleOpenReview(selectedDetection)}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition-colors"
              >
                Analyst Review / Dismiss
              </button>
              <button
                onClick={() => setSelectedDetection(null)}
                className="px-4 py-2 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Review Modal */}
      {reviewModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="max-w-md w-full rounded-2xl border border-slate-700 bg-[#0d1322] shadow-2xl p-6 space-y-4">
            <h3 className="text-sm font-bold text-white">Record Analyst Review</h3>
            <p className="text-xs text-slate-400">
              Document false positive rationales or manual review decisions.
            </p>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Analyst Identifier</label>
                <input
                  type="text"
                  value={analystName}
                  onChange={(e) => setAnalystName(e.target.value)}
                  placeholder="e.g. sec-analyst-1"
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-900 text-white font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Review Notes / Justification</label>
                <textarea
                  value={reviewNotes}
                  onChange={(e) => setReviewNotes(e.target.value)}
                  placeholder="Explain why this detection was reviewed or why it is a false positive..."
                  rows={3}
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-900 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="fp-check"
                  checked={isFalsePositive}
                  onChange={(e) => setIsFalsePositive(e.target.checked)}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-0"
                />
                <label htmlFor="fp-check" className="text-slate-300 select-none cursor-pointer">
                  Dismiss as False Positive (Legitimate client activity)
                </label>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setReviewModalOpen(false)}
                className="px-3.5 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={submitReview}
                disabled={submittingReview || !analystName.trim() || !reviewNotes.trim()}
                className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold disabled:opacity-50"
              >
                {submittingReview ? 'Saving...' : 'Save Review'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

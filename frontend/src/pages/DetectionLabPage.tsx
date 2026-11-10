import React, { useState } from 'react';
import {
  FlaskConical,
  Play,
  RotateCcw,
  Bot,
  Activity,
  ShieldAlert,
  Zap,
  Layers,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { api } from '../services/api';
import { LabSimulationResult } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';

export const DetectionLabPage: React.FC = () => {
  const [selectedScenario, setSelectedScenario] = useState('normal_browser');
  const [requestCount, setRequestCount] = useState(25);
  const [intervalMs, setIntervalMs] = useState(50);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<LabSimulationResult | null>(null);
  const [resetMessage, setResetMessage] = useState<string | null>(null);

  const scenarios = [
    {
      id: 'normal_browser',
      title: 'Normal Browser Client',
      badge: 'Legitimate Baseline',
      badgeColor: 'cyan',
      description: 'Simulates genuine human browsing with standard Chrome/Safari User-Agents, organic paths, and 200 OK responses.',
      icon: <Activity className="w-5 h-5 text-emerald-400" />,
      expectedRisk: 'Low Risk (Score 0-15)',
    },
    {
      id: 'automated_scraper',
      title: 'Automated Content Scraper',
      badge: 'Automation Marker',
      badgeColor: 'amber',
      description: 'Simulates high-velocity catalog pagination using python-requests with deterministic sub-50ms timing intervals.',
      icon: <Bot className="w-5 h-5 text-amber-400" />,
      expectedRisk: 'Moderate to High Risk',
    },
    {
      id: 'burst_bot',
      title: 'High-Velocity Burst Bot',
      badge: 'Burst Clustering',
      badgeColor: 'rose',
      description: 'Simulates a rapid flash-sale bot sending a cluster of 20+ checkout requests within a tight 10-second window.',
      icon: <Zap className="w-5 h-5 text-rose-400" />,
      expectedRisk: 'High Risk',
    },
    {
      id: 'endpoint_enumeration',
      title: 'Endpoint Enumeration Scanner',
      badge: 'Vulnerability Prober',
      badgeColor: 'rose',
      description: 'Simulates path fuzzing across sensitive targets (.env, /wp-admin, /actuator/env) generating high volumes of 404 errors.',
      icon: <ShieldAlert className="w-5 h-5 text-rose-400" />,
      expectedRisk: 'High to Critical Risk',
    },
    {
      id: 'rate_limit_offender',
      title: 'Rate-Limit Violation Offender',
      badge: 'Threshold Disregard',
      badgeColor: 'rose',
      description: 'Simulates an aggressive client that continues hammering login endpoints despite receiving repeated HTTP 429 Too Many Requests.',
      icon: <Layers className="w-5 h-5 text-rose-400" />,
      expectedRisk: 'High Risk',
    },
  ];

  const handleRun = async () => {
    try {
      setRunning(true);
      setResetMessage(null);
      const res = await api.runLabScenario(selectedScenario, requestCount, intervalMs);
      setResult(res);
    } catch (err: any) {
      alert(`Simulation failed: ${err.message}`);
    } finally {
      setRunning(false);
    }
  };

  const handleReset = async () => {
    if (!confirm('Clear all lab demonstration events? Production telemetry will be preserved.')) return;
    try {
      const res = await api.resetLab();
      setResetMessage(res.message);
      setResult(null);
    } catch (err: any) {
      alert(`Reset failed: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <FlaskConical className="w-6 h-6 text-cyan-400" />
            Detection Lab Simulation Suite
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Reproducible, isolated local test harness to benchmark multi-signal behavioral detection rules against controlled traffic.
          </p>
        </div>
        <button
          onClick={handleReset}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900/60 hover:bg-slate-800 text-xs font-medium text-slate-300 transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          Reset Lab Events
        </button>
      </div>

      {resetMessage && (
        <div className="p-4 rounded-xl border border-emerald-900/80 bg-emerald-950/40 text-emerald-300 text-xs flex items-center gap-3">
          <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-emerald-400" />
          <span>{resetMessage}</span>
        </div>
      )}

      {/* Scenarios Selection Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {scenarios.map((sc) => {
          const selected = selectedScenario === sc.id;
          return (
            <div
              key={sc.id}
              onClick={() => setSelectedScenario(sc.id)}
              className={`p-5 rounded-xl border transition-all cursor-pointer flex flex-col justify-between ${
                selected
                  ? 'border-cyan-500 bg-[#0d1627] shadow-lg shadow-cyan-950/30'
                  : 'border-slate-800 bg-[#0c1220]/70 hover:border-slate-700 hover:bg-slate-900/40'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-3">
                  <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">{sc.icon}</div>
                  <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${
                    selected ? 'bg-cyan-950 text-cyan-300 border-cyan-800' : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}>
                    {sc.badge}
                  </span>
                </div>
                <h3 className="text-sm font-bold text-white mb-1">{sc.title}</h3>
                <p className="text-xs text-slate-400 leading-relaxed mb-4">{sc.description}</p>
              </div>

              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono">
                <span className="text-slate-500">Expected:</span>
                <span className="text-cyan-400 font-semibold">{sc.expectedRisk}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Simulator Execution Controls */}
      <div className="p-6 rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <div className="flex justify-between text-xs text-slate-300 mb-1.5 font-medium">
              <span>Request Batch Count</span>
              <span className="font-mono text-cyan-400">{requestCount} requests</span>
            </div>
            <input
              type="range"
              min="5"
              max="100"
              step="5"
              value={requestCount}
              onChange={(e) => setRequestCount(Number(e.target.value))}
              className="w-full accent-cyan-500"
            />
          </div>

          <div>
            <div className="flex justify-between text-xs text-slate-300 mb-1.5 font-medium">
              <span>Inter-Request Interval</span>
              <span className="font-mono text-cyan-400">{intervalMs} ms</span>
            </div>
            <input
              type="range"
              min="0"
              max="500"
              step="25"
              value={intervalMs}
              onChange={(e) => setIntervalMs(Number(e.target.value))}
              className="w-full accent-cyan-500"
            />
          </div>
        </div>

        <div className="pt-3 flex items-center justify-between border-t border-slate-800">
          <div className="text-xs text-slate-400">
            Target: <code className="text-cyan-300 font-mono">Local Demo Server (127.0.0.1)</code> • No third-party network interaction.
          </div>
          <button
            onClick={handleRun}
            disabled={running}
            className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-sm transition-all shadow-lg shadow-cyan-950/50 disabled:opacity-50 cursor-pointer"
          >
            {running ? (
              <>
                <Play className="w-4 h-4 animate-spin" />
                Executing Simulation...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Trigger Lab Scenario
              </>
            )}
          </button>
        </div>
      </div>

      {/* Lab Results Display */}
      {result && (
        <div className="p-6 rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl space-y-5 animate-in fade-in duration-200">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <div className="text-xs font-mono text-cyan-400">SIMULATION OUTCOME</div>
              <h3 className="text-lg font-bold text-white mt-0.5">
                Scenario: <span className="uppercase">{result.scenario.replace('_', ' ')}</span>
              </h3>
              <div className="text-xs text-slate-400 mt-1">
                Simulated IP: <code className="text-cyan-300 font-mono">{result.simulated_ip}</code> •{' '}
                {result.events_generated} events ingested
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="p-3 rounded-xl border border-slate-800 bg-slate-900/60 text-center">
                <div className="text-2xl font-bold text-cyan-400 font-mono">{result.risk_score}/100</div>
                <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mt-0.5">Risk Score</div>
              </div>
              <SeverityBadge severity={result.risk_level} size="md" />
            </div>
          </div>

          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
              Detection Rules Triggered ({result.triggered_rules.length})
            </h4>
            {result.triggered_rules.length === 0 ? (
              <div className="p-4 rounded-lg bg-emerald-950/30 border border-emerald-900 text-xs text-emerald-300">
                Zero anomaly rules triggered. Client behavior conformed entirely to human browser baseline.
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {result.triggered_rules.map((ruleName, idx) => (
                  <div key={idx} className="p-3 rounded-lg border border-slate-800 bg-slate-900/60 text-xs flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                    <span className="font-semibold text-white">{ruleName}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Detailed Telemetry Evidence</h4>
            <ul className="list-disc list-inside text-xs text-slate-300 space-y-1 bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono">
              {result.evaluation.evidence.map((ev, i) => (
                <li key={i}>{ev}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};

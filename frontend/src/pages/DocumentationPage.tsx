import React from 'react';
import {
  BookOpen,
  Shield,
  Layers,
  Terminal,
  Cpu,
  Lock,
  Code2,
} from 'lucide-react';

export const DocumentationPage: React.FC = () => {
  return (
    <div className="space-y-8 max-w-5xl mx-auto pb-12">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <BookOpen className="w-6 h-6 text-cyan-400" />
          Technical Documentation & Architecture
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Architectural overview, behavioral detection algorithms, defensive SSRF protections, and API specification.
        </p>
      </div>

      {/* Core Principles */}
      <div className="p-6 rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl space-y-4">
        <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
          <Shield className="w-4 h-4" />
          Core Engineering Philosophy
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          BotShield is an open-source cybersecurity toolkit engineered for developers, security researchers, and SOC operators.
          Unlike superficial scanners that fabricate results or rely solely on easily spoofed User-Agent strings, BotShield operates on
          <b> measurable evidence, multi-signal behavioral telemetry, and strict defensive boundaries</b>.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 text-xs">
          <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/60">
            <div className="font-bold text-white mb-1">Zero Fabricated Data</div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Every score, chart point, and finding is computed from actual HTTP responses or stored telemetry logs.
            </p>
          </div>
          <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/60">
            <div className="font-bold text-white mb-1">Full SSRF Defense</div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              DNS pinning, hop-by-hop redirect inspection, and RFC 1918 / cloud metadata blocking prevent lateral exploitation.
            </p>
          </div>
          <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/60">
            <div className="font-bold text-white mb-1">Explainable Heuristics</div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Risk scores (0-100) are broken down into specific triggered rules with mathematical thresholds and analyst review hooks.
            </p>
          </div>
        </div>
      </div>

      {/* Detection Engine Signals Breakdown */}
      <div className="p-6 rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl space-y-4">
        <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
          <Cpu className="w-4 h-4" />
          Behavioral Detection Signals
        </div>
        <div className="divide-y divide-slate-800 text-xs">
          <div className="py-3">
            <div className="font-bold text-white">1. High Request Frequency (Sliding Window)</div>
            <p className="text-slate-400 mt-1">
              Tracks cumulative requests per source IP within a 5-minute sliding window (default threshold: 50 requests).
            </p>
          </div>
          <div className="py-3">
            <div className="font-bold text-white">2. Short-Window Burst Velocity</div>
            <p className="text-slate-400 mt-1">
              Identifies micro-bursts where request density exceeds human interaction speeds (default: &gt;15 requests in 10 seconds).
            </p>
          </div>
          <div className="py-3">
            <div className="font-bold text-white">3. Path & Endpoint Enumeration</div>
            <p className="text-slate-400 mt-1">
              Flags clients visiting abnormal counts of distinct endpoints or probing sensitive administrative paths (e.g. <code>/.env</code>, <code>/wp-login.php</code>, <code>/actuator/env</code>).
            </p>
          </div>
          <div className="py-3">
            <div className="font-bold text-white">4. Repeated 404 Error Cascades</div>
            <p className="text-slate-400 mt-1">
              Detects automated content enumeration and blind fuzzing by tracking clusters of HTTP 404 responses.
            </p>
          </div>
          <div className="py-3">
            <div className="font-bold text-white">5. Automation User-Agent Markers</div>
            <p className="text-slate-400 mt-1">
              Identifies automation frameworks (python-requests, curl, headless Chrome, Puppeteer, Scrapy). Calibrated as a weak corroborative signal, never sole proof.
            </p>
          </div>
          <div className="py-3">
            <div className="font-bold text-white">6. Rate Limit Violations</div>
            <p className="text-slate-400 mt-1">
              Tracks clients that continue sending traffic after receiving HTTP 429 Too Many Requests responses.
            </p>
          </div>
          <div className="py-3">
            <div className="font-bold text-white">7. Unnatural Sequence Timing</div>
            <p className="text-slate-400 mt-1">
              Computes average inter-request delta times. Sub-100ms average intervals trigger programmatic timing penalties.
            </p>
          </div>
        </div>
      </div>

      {/* REST API Reference */}
      <div className="p-6 rounded-2xl border border-slate-800 bg-[#0c1220]/90 shadow-xl space-y-4">
        <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
          <Code2 className="w-4 h-4" />
          Primary REST API Endpoints
        </div>
        <div className="space-y-2 font-mono text-xs">
          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-emerald-400 font-bold mr-3">POST</span>
              <span className="text-slate-200">/api/websites/scan</span>
            </div>
            <span className="text-slate-500 font-sans text-[11px]">Audit security headers, TLS & robots.txt</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-emerald-400 font-bold mr-3">POST</span>
              <span className="text-slate-200">/api/ips/analyze</span>
            </div>
            <span className="text-slate-500 font-sans text-[11px]">IPv4/IPv6 classification, ASN & reputation</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-emerald-400 font-bold mr-3">POST</span>
              <span className="text-slate-200">/api/bots/events</span>
            </div>
            <span className="text-slate-500 font-sans text-[11px]">Ingest telemetry event & run evaluation</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-cyan-400 font-bold mr-3">GET</span>
              <span className="text-slate-200">/api/bots/summary</span>
            </div>
            <span className="text-slate-500 font-sans text-[11px]">Real-time dashboard metrics</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-emerald-400 font-bold mr-3">POST</span>
              <span className="text-slate-200">/api/proxies/test</span>
            </div>
            <span className="text-slate-500 font-sans text-[11px]">Audit authorized proxy connectivity & egress</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-emerald-400 font-bold mr-3">POST</span>
              <span className="text-slate-200">/api/lab/run</span>
            </div>
            <span className="text-slate-500 font-sans text-[11px]">Trigger isolated local attack simulation</span>
          </div>
        </div>
      </div>

      {/* Responsible Security Disclaimer */}
      <div className="p-5 rounded-xl border border-slate-800/80 bg-slate-900/40 text-xs text-slate-400 space-y-2">
        <div className="flex items-center gap-2 font-semibold text-slate-300">
          <Lock className="w-4 h-4 text-cyan-400" />
          Responsible Security & Safe Harbor Statement
        </div>
        <p className="leading-relaxed">
          BotShield is strictly designed for defense, intelligence auditing, and traffic observability. It does not contain capabilities
          for CAPTCHA circumvention, stealth scraping, fingerprint spoofing to evade bans, or denial-of-service flooding.
          Users are responsible for ensuring that website scans and proxy audits target only endpoints they own or have explicit authorization to assess.
        </p>
      </div>
    </div>
  );
};

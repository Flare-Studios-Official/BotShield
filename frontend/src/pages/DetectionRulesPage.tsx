import React, { useEffect, useState } from 'react';
import {
  Sliders,
  Save,
  RotateCcw,
  Shield,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { api } from '../services/api';
import { DetectionRule } from '../types';

export const DetectionRulesPage: React.FC = () => {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [savingRuleId, setSavingRuleId] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const loadRules = async () => {
    try {
      setLoading(true);
      const data = await api.listRules();
      setRules(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
  }, []);

  const handleUpdate = async (rule: DetectionRule) => {
    try {
      setSavingRuleId(rule.id);
      setSuccessMsg(null);
      await api.updateRule(rule.id, {
        weight: rule.weight,
        threshold_value: rule.threshold_value,
        enabled: rule.enabled,
      });
      setSuccessMsg(`Updated rule ${rule.name}`);
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: any) {
      alert(`Update failed: ${err.message}`);
    } finally {
      setSavingRuleId(null);
    }
  };

  const handleFieldChange = (id: string, field: keyof DetectionRule, value: any) => {
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, [field]: value } : r))
    );
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <Sliders className="w-6 h-6 text-cyan-400" />
          Detection Heuristics & Rule Weights
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Customize behavioral scoring weights, trigger thresholds, and enabled status. Changes take effect on incoming requests immediately.
        </p>
      </div>

      {successMsg && (
        <div className="p-4 rounded-xl border border-emerald-900/80 bg-emerald-950/40 text-emerald-300 text-xs flex items-center gap-3">
          <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-emerald-400" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Rules Configuration Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {rules.map((rule) => {
          const isSaving = savingRuleId === rule.id;
          return (
            <div
              key={rule.id}
              className={`p-6 rounded-2xl border transition-all ${
                rule.enabled
                  ? 'border-slate-800 bg-[#0c1220]/90 shadow-lg'
                  : 'border-slate-800/60 bg-slate-950/40 opacity-70'
              }`}
            >
              <div className="flex items-start justify-between gap-4 mb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-white">{rule.name}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400">
                      {rule.id}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">{rule.description}</p>
                </div>

                {/* Enable Toggle Switch */}
                <button
                  type="button"
                  onClick={() => {
                    const nextVal = !rule.enabled;
                    handleFieldChange(rule.id, 'enabled', nextVal);
                  }}
                  className={`w-11 h-6 flex items-center rounded-full p-1 transition-colors flex-shrink-0 cursor-pointer ${
                    rule.enabled ? 'bg-cyan-600' : 'bg-slate-700'
                  }`}
                >
                  <div
                    className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform ${
                      rule.enabled ? 'translate-x-5' : 'translate-x-0'
                    }`}
                  />
                </button>
              </div>

              <div className="space-y-4 pt-2 border-t border-slate-800/80">
                {/* Weight Slider */}
                <div>
                  <div className="flex justify-between text-xs text-slate-300 mb-1">
                    <span>Scoring Penalty Weight</span>
                    <span className="font-mono text-cyan-400 font-bold">+{rule.weight} points</span>
                  </div>
                  <input
                    type="range"
                    min="5"
                    max="50"
                    step="5"
                    value={rule.weight}
                    onChange={(e) => handleFieldChange(rule.id, 'weight', Number(e.target.value))}
                    disabled={!rule.enabled}
                    className="w-full accent-cyan-500"
                  />
                </div>

                {/* Threshold Slider (if applicable) */}
                {rule.id !== 'AUTOMATION_USER_AGENT' && (
                  <div>
                    <div className="flex justify-between text-xs text-slate-300 mb-1">
                      <span>Trigger Threshold Value</span>
                      <span className="font-mono text-cyan-400 font-bold">
                        {rule.id === 'RAPID_SEQUENCE'
                          ? `<${Math.round(rule.threshold_value * 1000)}ms interval`
                          : `>= ${rule.threshold_value}`}
                      </span>
                    </div>
                    <input
                      type="range"
                      min={rule.id === 'RAPID_SEQUENCE' ? 0.05 : 1}
                      max={rule.id === 'RAPID_SEQUENCE' ? 0.5 : 50}
                      step={rule.id === 'RAPID_SEQUENCE' ? 0.05 : 1}
                      value={rule.threshold_value}
                      onChange={(e) => handleFieldChange(rule.id, 'threshold_value', Number(e.target.value))}
                      disabled={!rule.enabled}
                      className="w-full accent-cyan-500"
                    />
                  </div>
                )}

                <div className="flex justify-end pt-1">
                  <button
                    onClick={() => handleUpdate(rule)}
                    disabled={isSaving}
                    className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow transition-all cursor-pointer disabled:opacity-50"
                  >
                    <Save className="w-3.5 h-3.5" />
                    {isSaving ? 'Saving...' : 'Apply Config'}
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

import React from 'react';
import { Severity, RiskLevel } from '../types';

interface Props {
  severity: Severity | RiskLevel | string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<Props> = ({ severity, size = 'sm' }) => {
  const norm = severity.toLowerCase();

  let colors = 'bg-slate-800 text-slate-300 border-slate-700';
  if (norm === 'critical') {
    colors = 'bg-rose-950/60 text-rose-300 border-rose-800/80';
  } else if (norm === 'high') {
    colors = 'bg-orange-950/60 text-orange-300 border-orange-800/80';
  } else if (norm === 'medium' || norm === 'moderate') {
    colors = 'bg-amber-950/60 text-amber-300 border-amber-800/80';
  } else if (norm === 'low') {
    colors = 'bg-cyan-950/60 text-cyan-300 border-cyan-800/80';
  } else if (norm === 'info' || norm === 'observed') {
    colors = 'bg-blue-950/60 text-blue-300 border-blue-800/80';
  }

  const px = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-sm';

  return (
    <span className={`inline-flex items-center font-semibold rounded-md border tracking-wide uppercase ${px} ${colors}`}>
      {severity}
    </span>
  );
};

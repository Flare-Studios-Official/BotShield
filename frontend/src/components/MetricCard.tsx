import React, { ReactNode } from 'react';

interface Props {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: ReactNode;
  trend?: string;
  badge?: string;
  badgeColor?: 'cyan' | 'rose' | 'amber' | 'emerald';
}

export const MetricCard: React.FC<Props> = ({
  title,
  value,
  subtitle,
  icon,
  trend,
  badge,
  badgeColor = 'cyan',
}) => {
  const badgeClasses = {
    cyan: 'bg-cyan-950/60 text-cyan-400 border-cyan-800/60',
    rose: 'bg-rose-950/60 text-rose-400 border-rose-800/60',
    amber: 'bg-amber-950/60 text-amber-400 border-amber-800/60',
    emerald: 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60',
  }[badgeColor];

  return (
    <div className="relative overflow-hidden rounded-xl border border-slate-800/90 bg-[#0c1220]/80 p-5 shadow-lg backdrop-blur transition-all duration-200 hover:border-slate-700 hover:shadow-cyan-950/20">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</span>
        <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-2 text-cyan-400 shadow-inner">
          {icon}
        </div>
      </div>
      <div className="mt-4 flex items-baseline justify-between">
        <span className="text-2xl font-bold tracking-tight text-white">{value}</span>
        {badge && (
          <span className={`rounded border px-2 py-0.5 text-xs font-medium ${badgeClasses}`}>
            {badge}
          </span>
        )}
      </div>
      {(subtitle || trend) && (\n        <div className="mt-2 flex items-center justify-between text-xs text-slate-400">
          <span>{subtitle}</span>
          {trend && <span className="font-medium text-cyan-400">{trend}</span>}
        </div>
      )}
    </div>
  );
};

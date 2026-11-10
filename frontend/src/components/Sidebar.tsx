import React from 'react';
import {
  Shield,
  LayoutDashboard,
  Globe,
  Binary,
  Bot,
  Network,
  FlaskConical,
  History,
  Sliders,
  BookOpen,
} from 'lucide-react';

export type NavItem =
  | 'overview'
  | 'websites'
  | 'ips'
  | 'bots'
  | 'proxies'
  | 'lab'
  | 'history'
  | 'rules'
  | 'docs';

interface Props {
  currentTab: NavItem;
  onSelectTab: (tab: NavItem) => void;
}

export const Sidebar: React.FC<Props> = ({ currentTab, onSelectTab }) => {
  const navItems: { id: NavItem; label: string; icon: React.ReactNode }[] = [\n    { id: 'overview', label: 'Overview', icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: 'websites', label: 'Website Scanner', icon: <Globe className="w-4 h-4" /> },
    { id: 'ips', label: 'IP Intelligence', icon: <Binary className="w-4 h-4" /> },
    { id: 'bots', label: 'Bot Detection', icon: <Bot className="w-4 h-4" /> },
    { id: 'proxies', label: 'Proxy Intelligence', icon: <Network className="w-4 h-4" /> },
    { id: 'lab', label: 'Detection Lab', icon: <FlaskConical className="w-4 h-4" /> },
    { id: 'history', label: 'Scan History', icon: <History className="w-4 h-4" /> },
    { id: 'rules', label: 'Detection Rules', icon: <Sliders className="w-4 h-4" /> },
    { id: 'docs', label: 'Documentation', icon: <BookOpen className="w-4 h-4" /> },
  ];

  return (
    <aside className="w-64 flex-shrink-0 border-r border-slate-800 bg-[#070b13] flex flex-col justify-between select-none">
      <div>
        {/* Brand Header */}
        <div className="h-16 flex items-center px-6 gap-3 border-b border-slate-800/80">
          <div className="p-2 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-600 text-white shadow-md shadow-cyan-900/30">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="font-bold text-white text-base tracking-wide flex items-center gap-1.5">
              BotShield
              <span className="text-[10px] font-mono px-1.5 py-0.2 bg-cyan-950 text-cyan-400 border border-cyan-800/60 rounded">
                v1.0
              </span>
            </div>
            <div className="text-[10px] text-slate-400 font-medium tracking-tight">
              Understand. Detect. Defend.
            </div>
          </div>
        </div>

        {/* Navigation List */}
        <nav className="p-3 space-y-1">
          <div className="px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">
            Security Modules
          </div>
          {navItems.map((item) => {
            const active = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                  active
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-950/40'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                }`}
              >
                <span className={active ? 'text-cyan-400' : 'text-slate-400'}>{item.icon}</span>
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer Info */}
      <div className="p-4 m-3 rounded-xl border border-slate-800/80 bg-slate-900/40 text-[11px] text-slate-400">
        <div className="flex items-center gap-2 text-cyan-400 font-semibold mb-1">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          Engine Active
        </div>
        <div>Passive heuristics & real telemetry stream running.</div>
      </div>
    </aside>
  );
};

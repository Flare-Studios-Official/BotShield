import React from 'react';
import { ShieldCheck, Terminal, Cpu } from 'lucide-react';

interface Props {
  apiStatus: string;
}

export const Navbar: React.FC<Props> = ({ apiStatus }) => {
  const isOnline = apiStatus === 'online';

  return (
    <header className="h-16 border-b border-slate-800 bg-[#090e18]/80 backdrop-blur-md px-8 flex items-center justify-between flex-shrink-0 z-10">
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          <span>SOC COMMAND INTERFACE</span>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-slate-800 bg-slate-900/60 text-xs font-mono">
          <Cpu className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-slate-400">DEFENSIVE ENGINE:</span>
          <span className="text-cyan-400 font-semibold">STRICT SSRF / BEHAVIORAL</span>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-slate-800 bg-slate-900/60 text-xs font-medium">
          <span
            className={`w-2 h-2 rounded-full ${
              isOnline ? 'bg-emerald-400 shadow-sm shadow-emerald-400/50' : 'bg-rose-400'
            }`}
          />
          <span className={isOnline ? 'text-emerald-300' : 'text-rose-300'}>
            {isOnline ? 'API Connected' : 'Backend Offline'}
          </span>
        </div>
      </div>
    </header>
  );
};

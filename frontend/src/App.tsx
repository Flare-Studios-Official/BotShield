import React, { useEffect, useState } from 'react';
import { Navbar } from './components/Navbar';
import { NavItem, Sidebar } from './components/Sidebar';
import { OverviewPage } from './pages/OverviewPage';
import { WebsiteScannerPage } from './pages/WebsiteScannerPage';
import { IPIntelligencePage } from './pages/IPIntelligencePage';
import { BotDetectionPage } from './pages/BotDetectionPage';
import { ProxyIntelligencePage } from './pages/ProxyIntelligencePage';
import { DetectionLabPage } from './pages/DetectionLabPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';
import { DetectionRulesPage } from './pages/DetectionRulesPage';
import { DocumentationPage } from './pages/DocumentationPage';
import { api } from './services/api';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavItem>('overview');
  const [apiStatus, setApiStatus] = useState<string>('checking');

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const health = await api.getHealth();
        setApiStatus(health.status);
      } catch {
        setApiStatus('offline');
      }
    };
    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#080c14] text-slate-100 font-sans">
      {/* Persistent Sidebar */}
      <Sidebar currentTab={currentTab} onSelectTab={setCurrentTab} />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navbar */}
        <Navbar apiStatus={apiStatus} />

        {/* Scrollable Page Body */}
        <main className="flex-1 overflow-y-auto p-8">
          {currentTab === 'overview' && <OverviewPage onNavigate={setCurrentTab} />}
          {currentTab === 'websites' && <WebsiteScannerPage />}
          {currentTab === 'ips' && <IPIntelligencePage />}
          {currentTab === 'bots' && <BotDetectionPage />}
          {currentTab === 'proxies' && <ProxyIntelligencePage />}
          {currentTab === 'lab' && <DetectionLabPage />}
          {currentTab === 'history' && <ScanHistoryPage />}
          {currentTab === 'rules' && <DetectionRulesPage />}
          {currentTab === 'docs' && <DocumentationPage />}
        </main>
      </div>
    </div>
  );
};

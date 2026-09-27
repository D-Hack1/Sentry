import { BrowserRouter as Router, Routes, Route, NavLink, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { Activity, LayoutDashboard, BarChart3, ChevronLeft, ChevronRight } from 'lucide-react';
import React, { useEffect, useState, useRef } from 'react';
import type { ErrorInfo } from 'react';

import LiveSessions from './views/LiveSessions';
import SessionDetail from './views/SessionDetail';
import Stats from './views/Stats';
import Metrics from './views/Metrics';
import Report from './views/Report';
import { getHealth } from './api/health';
import { getSessions } from './api/sessions';
import ThemeToggle from './components/ThemeToggle';
import SpinningNumbers from './components/SpinningNumbers';
import { DEFAULT_BG_SETTINGS } from './types/bgSettings';

const queryClient = new QueryClient();

/* ─── Error Boundary ─── */
class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { hasError: boolean }> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }
  static getDerivedStateFromError() { return { hasError: true }; }
  componentDidCatch(error: Error, errorInfo: ErrorInfo) { console.error('Error boundary caught:', error, errorInfo); }
  render() {
    if (this.state.hasError) {
      return (
        <div className="p-8 text-red-500 bg-red-950/20 border border-red-500 rounded-lg m-8">
          Something went wrong rendering this view.
        </div>
      );
    }
    return this.props.children;
  }
}

/* ─── Status Bar ─── */
function StatusBar({ theme, onToggleTheme }: { theme: 'dark' | 'light'; onToggleTheme: () => void }) {
  const [status, setStatus] = useState<'ok' | 'degraded' | 'down' | 'loading'>('loading');

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await getHealth();
        setStatus(res.status);
      } catch {
        setStatus('down');
      }
    };
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const dotColor =
    status === 'loading' ? 'bg-gray-500' :
    status === 'ok' ? 'bg-[var(--color-severity-low)]' :
    status === 'degraded' ? 'bg-[var(--color-severity-medium)]' :
    'bg-[var(--color-severity-critical)]';

  return (
    <div className="h-8 flex items-center justify-between px-4 bg-[var(--color-surface)] border-b border-[var(--color-border-subtle)] text-xs z-10">
      <div className="flex items-center gap-2">
        <div className={`w-2 h-2 rounded-full ${dotColor}`} />
        <span className="text-gray-400 capitalize font-mono font-medium">API: {status}</span>
      </div>
      <ThemeToggle checked={theme === 'light'} onChange={onToggleTheme} />
    </div>
  );
}

/* ─── Sidebar ─── */
function Sidebar({
  theme,
  collapsed,
  onToggleCollapse,
}: {
  theme: 'dark' | 'light';
  collapsed: boolean;
  onToggleCollapse: () => void;
}) {
  const location = useLocation();
  const [badgeCount, setBadgeCount] = useState(0);
  const seenIds = useRef<Set<string>>(new Set());

  const { data } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => getSessions({ page: 1, page_size: 20 }),
    refetchInterval: 5000,
  });

  useEffect(() => {
    if (location.pathname === '/') {
      setBadgeCount(0);
      if (data) {
        data.items.forEach(s => seenIds.current.add(s.es_id));
      }
    } else if (data) {
      let newAlerts = 0;
      data.items.forEach(s => {
        if (!seenIds.current.has(s.es_id)) {
          seenIds.current.add(s.es_id);
          if (s.severity === 'critical' || s.severity === 'high') {
            newAlerts++;
          }
        }
      });
      if (newAlerts > 0) setBadgeCount(prev => prev + newAlerts);
    }
  }, [data, location.pathname]);

  const titleImg = theme === 'light' ? '/sentry%20title%20light.svg' : '/sentry%20title.svg';
  const logoImg = '/sentry%20logo.svg';

  const navLinkClass = (isActive: boolean) =>
    `flex items-center gap-3 px-3 py-2 rounded-md font-medium text-sm transition-all duration-200 ${
      collapsed ? 'justify-center' : ''
    } ${
      isActive
        ? 'bg-[var(--color-primary)]/10 text-[var(--color-primary)] border border-[var(--color-primary)]/20'
        : 'text-gray-400 hover:text-gray-200 hover:bg-[var(--color-surface-hover)]'
    }`;

  return (
    <div
      className={`bg-[var(--color-surface)] border-r border-[var(--color-border-subtle)] h-full flex flex-col p-4 z-10 shadow-2xl transition-all duration-300 overflow-hidden ${
        collapsed ? 'w-[68px]' : 'w-64'
      }`}
    >
      {/* Logo / Title */}
      <div className="flex items-center justify-between mb-8 mt-1 px-1">
        {collapsed ? (
          <img src={logoImg} alt="Sentry" className="h-8 w-8 mx-auto" />
        ) : (
          <img src={titleImg} alt="Sentry" className="h-12" />
        )}
        <button
          onClick={onToggleCollapse}
          className="p-1 hover:bg-[var(--color-surface-hover)] rounded text-gray-400 hover:text-gray-200 transition-colors flex-shrink-0"
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </button>
      </div>

      {/* Nav links */}
      <nav className="flex flex-col gap-2 flex-1">
        <NavLink to="/" end className={({ isActive }) => navLinkClass(isActive)}>
          <Activity size={18} />
          {!collapsed && <span>Live Feed</span>}
          {badgeCount > 0 && !collapsed && (
            <span className="ml-auto bg-red-500/20 border border-red-500/50 text-red-400 text-[10px] font-bold px-2 py-0.5 rounded-full">
              {badgeCount}
            </span>
          )}
        </NavLink>
        <NavLink to="/stats" className={({ isActive }) => navLinkClass(isActive)}>
          <BarChart3 size={18} />
          {!collapsed && <span>Stats</span>}
        </NavLink>
        <NavLink to="/metrics" className={({ isActive }) => navLinkClass(isActive)}>
          <LayoutDashboard size={18} />
          {!collapsed && <span>Metrics</span>}
        </NavLink>
      </nav>
    </div>
  );
}

/* ─── Layout ─── */
function Layout({
  theme,
  onToggleTheme,
}: {
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
}) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="flex flex-col h-screen overflow-hidden relative">
      {/* SpinningNumbers background - exact settings: Purple, 9% opacity, 105% scale, 0.8x speed, X:53%, Y:53% */}
      <div
        className="absolute inset-0 -z-10 pointer-events-none overflow-hidden"
        style={{ opacity: DEFAULT_BG_SETTINGS.opacity }}
      >
        <SpinningNumbers settings={DEFAULT_BG_SETTINGS} />
      </div>

      <StatusBar theme={theme} onToggleTheme={onToggleTheme} />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          theme={theme}
          collapsed={collapsed}
          onToggleCollapse={() => setCollapsed(c => !c)}
        />
        <main className="flex-1 overflow-y-auto p-8 relative animate-fade-in">
          <ErrorBoundary>
            <Routes>
              <Route path="/" element={<LiveSessions />} />
              <Route path="/sessions/:id" element={<SessionDetail />} />
              <Route path="/stats" element={<Stats />} />
              <Route path="/metrics" element={<Metrics />} />
              <Route path="/report/:id" element={<Report />} />
            </Routes>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}

/* ─── App root ─── */
export default function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  const toggleTheme = () => setTheme(t => (t === 'dark' ? 'light' : 'dark'));

  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <Layout
          theme={theme}
          onToggleTheme={toggleTheme}
        />
      </Router>
    </QueryClientProvider>
  );
}

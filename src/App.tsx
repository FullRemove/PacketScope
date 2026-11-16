import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Cpu,
  FileText,
  Globe,
  HardDrive,
  Layers,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  Radio,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  X,
} from 'lucide-react';
import { signOut } from 'firebase/auth';
import { auth } from './lib/firebase';
import { apiClient, usePacketScopeSocket } from './lib/api';
import { AuthGate } from './components/AuthGate';
import { OverviewView } from './views/OverviewView';
import { LiveTrafficView } from './views/LiveTrafficView';
import { ApplicationIntelligenceView, ProtocolAnalysisView, StunTurnView } from './views/IntelligenceViews';
import { IpIntelligenceView, NetworkGeographyView } from './views/GeographyIpViews';
import { NetworkInventoryView, SensorsView } from './views/SensorsInventoryViews';
import { AdministrationView, AlertsView, AnalyticsView, ReportsView, SettingsView } from './views/OperationsViews';
import type { AuthUser, NavSection, OrganizationSummary, OverviewResponse, TrafficEventItem } from './types/packetscope';
import { LanguageSwitcher, useI18n } from './i18n/I18nContext';
import type { TranslationKey } from './i18n/translations';

const NAV_ITEMS: Array<{ id: NavSection; labelKey: TranslationKey; icon: React.ComponentType<{ className?: string }> }> = [
  { id: 'overview', labelKey: 'navOverview', icon: LayoutDashboard },
  { id: 'live-traffic', labelKey: 'navLiveTraffic', icon: Activity },
  { id: 'applications', labelKey: 'navApplications', icon: Layers },
  { id: 'protocols', labelKey: 'navProtocols', icon: Network },
  { id: 'stun-turn', labelKey: 'navStunTurn', icon: Radio },
  { id: 'geography', labelKey: 'navGeography', icon: Globe },
  { id: 'ip-intelligence', labelKey: 'navIpIntelligence', icon: Search },
  { id: 'sensors', labelKey: 'navSensors', icon: Cpu },
  { id: 'inventory', labelKey: 'navInventory', icon: HardDrive },
  { id: 'alerts', labelKey: 'navAlerts', icon: AlertTriangle },
  { id: 'analytics', labelKey: 'navAnalytics', icon: BarChart3 },
  { id: 'reports', labelKey: 'navReports', icon: FileText },
  { id: 'settings', labelKey: 'navSettings', icon: Settings },
  { id: 'administration', labelKey: 'navAdministration', icon: Shield },
];

export default function App() {
  const { t } = useI18n();
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [orgs, setOrgs] = useState<OrganizationSummary[]>([]);
  const [activeOrgId, setActiveOrgId] = useState<string | null>(null);
  const [activeNav, setActiveNav] = useState<NavSection>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [overviewData, setOverviewData] = useState<OverviewResponse | null>(null);
  const [liveFeed, setLiveFeed] = useState<TrafficEventItem[]>([]);
  const [loadingOverview, setLoadingOverview] = useState(false);
  const [refreshSignal, setRefreshSignal] = useState(0);

  const [creatingOrg, setCreatingOrg] = useState(false);
  const [newOrgName, setNewOrgName] = useState('');

  const handleAuthenticated = useCallback((authToken: string, authUser: AuthUser, userOrgs: OrganizationSummary[]) => {
    const firstOrgId = userOrgs[0]?.id || null;
    apiClient.setCredentials(authToken, firstOrgId);
    setToken(authToken);
    setUser(authUser);
    setOrgs(userOrgs);
    setActiveOrgId(firstOrgId);
    setLiveFeed([]);
  }, []);

  const fetchOverview = useCallback(async () => {
    if (!token || !activeOrgId) return;
    setLoadingOverview(true);
    try {
      const res = await apiClient.request<OverviewResponse>('/api/dashboard/overview');
      setOverviewData(res);
      setLiveFeed(res.recentFeed || []);
    } finally {
      setLoadingOverview(false);
    }
  }, [token, activeOrgId]);

  useEffect(() => {
    if (token && activeOrgId) {
      apiClient.setCredentials(token, activeOrgId);
      void fetchOverview();
    }
  }, [token, activeOrgId, fetchOverview]);

  const wsConnected = usePacketScopeSocket(
    token,
    activeOrgId,
    useCallback(
      (evt) => {
        if (evt.type === 'traffic:ingested' && Array.isArray(evt.data?.recentPackets)) {
          setLiveFeed((prev) => {
            const seen = new Set<string>();
            const merged = [...evt.data.recentPackets, ...prev].filter((item) => {
              if (seen.has(item.id)) return false;
              seen.add(item.id);
              return true;
            });
            return merged.slice(0, 25);
          });
          setRefreshSignal((s) => s + 1);
          void fetchOverview();
        } else if (evt.type === 'sensor:heartbeat' || evt.type === 'alerts:updated') {
          setRefreshSignal((s) => s + 1);
          void fetchOverview();
        }
      },
      [fetchOverview]
    )
  );

  const handleSignOut = async () => {
    try {
      await signOut(auth);
    } catch {
      // ignore if signed in via local operator credentials
    }
    apiClient.setCredentials(null, null);
    setToken(null);
    setUser(null);
    setOrgs([]);
    setActiveOrgId(null);
    setOverviewData(null);
    setLiveFeed([]);
  };

  const handleCreateOrg = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newOrgName.trim()) return;
    const created = await apiClient.request<OrganizationSummary>('/api/organizations', {
      method: 'POST',
      body: JSON.stringify({ name: newOrgName.trim() }),
    });
    setOrgs((prev) => [...prev, created]);
    setActiveOrgId(created.id);
    setNewOrgName('');
    setCreatingOrg(false);
  };

  if (!token || !user || !activeOrgId) {
    return <AuthGate onAuthenticated={handleAuthenticated} />;
  }

  const activeOrg = orgs.find((o) => o.id === activeOrgId);
  const currentNavItem = NAV_ITEMS.find((n) => n.id === activeNav);
  const currentTitle = currentNavItem ? t(currentNavItem.labelKey) : t('navOverview');

  return (
    <div className="min-h-screen bg-[#070B14] text-slate-100 flex">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex lg:w-[260px] lg:flex-col lg:fixed lg:inset-y-0 lg:start-0 bg-[#0A101E] border-e border-slate-800/80">
        <div className="h-16 px-5 flex items-center gap-2.5 border-b border-slate-800/80">
          <div className="w-7 h-7 rounded-md bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <span className="font-display text-base font-semibold tracking-tight text-white whitespace-nowrap">PacketScope</span>
        </div>

        <div className="p-4 border-b border-slate-800/80">
          <label htmlFor="org-switcher" className="block text-[11px] font-medium text-slate-500 mb-1.5">
            {t('orgWorkspace')}
          </label>
          <select
            id="org-switcher"
            value={activeOrgId}
            onChange={(e) => setActiveOrgId(e.target.value)}
            className="w-full px-2.5 py-1.5 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-blue-500"
          >
            {orgs.map((o) => (
              <option key={o.id} value={o.id}>
                {o.name} ({o.role})
              </option>
            ))}
          </select>
          {!creatingOrg ? (
            <button
              type="button"
              onClick={() => setCreatingOrg(true)}
              className="mt-2 text-[11px] text-blue-400 hover:text-blue-300"
            >
              {t('newOrgBtn')}
            </button>
          ) : (
            <form onSubmit={handleCreateOrg} className="mt-2 flex gap-1.5">
              <input
                type="text"
                required
                value={newOrgName}
                onChange={(e) => setNewOrgName(e.target.value)}
                placeholder={t('newOrgPlaceholder')}
                className="flex-1 min-w-0 px-2 py-1 text-xs bg-[#070B14] border border-slate-800 rounded text-white"
              />
              <button type="submit" className="px-2 py-1 text-xs bg-blue-600 rounded text-white">
                {t('commonAdd')}
              </button>
            </form>
          )}
        </div>

        <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto" aria-label="Primary Navigation">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = activeNav === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveNav(item.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-medium rounded-lg transition-colors whitespace-nowrap text-start ${
                  active
                    ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span className="truncate">{t(item.labelKey)}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800/80 flex items-center justify-between gap-2 text-xs">
          <div className="min-w-0">
            <p className="font-medium text-slate-200 truncate">{user.displayName}</p>
            <p className="text-[11px] text-slate-500 truncate" dir="ltr">{user.email}</p>
          </div>
          <button
            type="button"
            onClick={() => void handleSignOut()}
            aria-label={t('signOut')}
            title={t('signOut')}
            className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60 shrink-0"
          >
            <LogOut className="w-4 h-4 rtl:rotate-180" />
          </button>
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="fixed inset-0 bg-black/60" onClick={() => setMobileMenuOpen(false)} />
          <aside className="relative w-72 max-w-[85vw] bg-[#0A101E] border-e border-slate-800 flex flex-col h-full">
            <div className="h-14 px-4 flex items-center justify-between border-b border-slate-800">
              <span className="font-display font-semibold text-white">PacketScope</span>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                aria-label={t('navCloseMenu')}
                className="p-1.5 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-3 border-b border-slate-800 space-y-2.5">
              <div>
                <label htmlFor="mobile-org-switcher" className="block text-[11px] font-medium text-slate-500 mb-1">
                  {t('orgWorkspace')}
                </label>
                <select
                  id="mobile-org-switcher"
                  value={activeOrgId}
                  onChange={(e) => setActiveOrgId(e.target.value)}
                  className="w-full px-2.5 py-1.5 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200"
                >
                  {orgs.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.name} ({o.role})
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-[11px] text-slate-500">{t('languageLabel')}</span>
                <LanguageSwitcher compact />
              </div>
            </div>
            <nav className="flex-1 p-3 space-y-1 overflow-y-auto" aria-label="Mobile Navigation">
              {NAV_ITEMS.map((item) => {
                const Icon = item.icon;
                const active = activeNav === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setActiveNav(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2.5 text-xs font-medium rounded-lg text-start ${
                      active ? 'bg-blue-600/20 text-blue-400' : 'text-slate-300 hover:bg-slate-800/50'
                    }`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{t(item.labelKey)}</span>
                  </button>
                );
              })}
            </nav>
            <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs gap-2">
              <span className="text-slate-300 truncate" dir="ltr">{user.email}</span>
              <button type="button" onClick={() => void handleSignOut()} className="text-red-400 shrink-0">
                {t('signOut')}
              </button>
            </div>
          </aside>
        </div>
      )}

      {/* Main Content */}
      <div className="flex-1 lg:ps-[260px] flex flex-col min-w-0">
        <header className="h-14 px-4 sm:px-6 border-b border-slate-800/80 bg-[#0A101E]/80 backdrop-blur flex items-center justify-between gap-3 sticky top-0 z-30">
          <div className="flex items-center gap-2.5 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label={t('navOpenMenu')}
              className="lg:hidden p-1.5 rounded-lg text-slate-300 hover:bg-slate-800 shrink-0"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2 text-xs text-slate-400 min-w-0">
              <span className="hidden sm:inline text-slate-200 font-medium truncate">{activeOrg?.name}</span>
              <span className="hidden sm:inline" aria-hidden="true">/</span>
              <span className="text-white font-medium truncate">{currentTitle}</span>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs shrink-0">
            <LanguageSwitcher compact />
            <span className="inline-flex items-center gap-1.5 font-mono text-slate-300">
              <span
                className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-emerald-500' : 'bg-amber-500'}`}
                aria-hidden="true"
              />
              <span className="hidden sm:inline">{wsConnected ? t('streamConnected') : t('streamReconnecting')}</span>
              <span className="sm:hidden">{wsConnected ? t('streamLiveShort') : t('streamSyncShort')}</span>
            </span>
          </div>
        </header>

        <main className="flex-1 p-4 sm:p-6 max-w-[1440px] w-full mx-auto">
          {activeNav === 'overview' && (
            <OverviewView
              data={overviewData}
              liveFeed={liveFeed}
              loading={loadingOverview}
              onRefresh={() => void fetchOverview()}
              onNavigate={setActiveNav}
            />
          )}
          {activeNav === 'live-traffic' && <LiveTrafficView refreshSignal={refreshSignal} />}
          {activeNav === 'applications' && <ApplicationIntelligenceView refreshSignal={refreshSignal} />}
          {activeNav === 'protocols' && <ProtocolAnalysisView refreshSignal={refreshSignal} />}
          {activeNav === 'stun-turn' && <StunTurnView refreshSignal={refreshSignal} />}
          {activeNav === 'geography' && <NetworkGeographyView refreshSignal={refreshSignal} />}
          {activeNav === 'ip-intelligence' && <IpIntelligenceView refreshSignal={refreshSignal} />}
          {activeNav === 'sensors' && <SensorsView refreshSignal={refreshSignal} />}
          {activeNav === 'inventory' && <NetworkInventoryView refreshSignal={refreshSignal} />}
          {activeNav === 'alerts' && <AlertsView refreshSignal={refreshSignal} />}
          {activeNav === 'analytics' && <AnalyticsView refreshSignal={refreshSignal} />}
          {activeNav === 'reports' && <ReportsView refreshSignal={refreshSignal} />}
          {activeNav === 'settings' && <SettingsView />}
          {activeNav === 'administration' && <AdministrationView orgId={activeOrgId} />}
        </main>
      </div>
    </div>
  );
}

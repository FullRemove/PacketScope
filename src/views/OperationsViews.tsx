import React, { useCallback, useEffect, useState } from 'react';
import { jsPDF } from 'jspdf';
import { Download, FileText, Plus } from 'lucide-react';
import { apiClient, formatBytes, formatTimestamp } from '../lib/api';
import { HorizontalDistributionList, TrafficVolumeChart } from '../components/Charts';
import { LanguageSwitcher, useI18n } from '../i18n/I18nContext';

export function AlertsView({ refreshSignal }: { refreshSignal: number }) {
  const { t } = useI18n();
  const [alerts, setAlerts] = useState<any[]>([]);
  const [rules, setRules] = useState<any[]>([]);
  const [name, setName] = useState('');
  const [ruleType, setRuleType] = useState('traffic_spike');
  const [threshold, setThreshold] = useState(250);
  const [severity, setSeverity] = useState<'info' | 'warning' | 'critical'>('warning');

  const loadData = useCallback(async () => {
    const [aRes, rRes] = await Promise.all([
      apiClient.request('/api/alerts'),
      apiClient.request('/api/alert-rules'),
    ]);
    setAlerts(aRes.items || []);
    setRules(rRes.items || []);
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData, refreshSignal]);

  const handleAlertStatus = async (id: string, status: 'acknowledged' | 'resolved') => {
    await apiClient.request(`/api/alerts/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
    await loadData();
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    await apiClient.request('/api/alert-rules', {
      method: 'POST',
      body: JSON.stringify({ name: name.trim(), ruleType, threshold: Number(threshold), severity }),
    });
    setName('');
    await loadData();
  };

  const handleToggleRule = async (rule: any) => {
    await apiClient.request(`/api/alert-rules/${rule.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled: !rule.enabled }),
    });
    await loadData();
  };

  const severityLabel = (sev: string) => {
    if (sev === 'critical') return t('alertsSevCrit');
    if (sev === 'warning') return t('alertsSevWarn');
    return t('alertsSevInfo');
  };

  const statusLabel = (st: string) => {
    if (st === 'acknowledged') return t('alertsStatusAck');
    if (st === 'resolved') return t('alertsStatusResolved');
    return t('alertsStatusOpen');
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-xl font-semibold text-white tracking-tight">{t('alertsTitle')}</h2>
        <p className="text-xs text-slate-400 mt-1">
          {t('alertsSubtitle')}
        </p>
      </div>

      <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 overflow-x-auto">
        <h3 className="font-display text-sm font-semibold text-white mb-3">{t('alertsFeedTitle')}</h3>
        <table className="w-full text-start text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2.5 pe-3 font-medium text-start">{t('alertsColTriggered')}</th>
              <th className="py-2.5 px-3 font-medium text-start">{t('alertsColSeverity')}</th>
              <th className="py-2.5 px-3 font-medium text-start">{t('alertsColTitleDetails')}</th>
              <th className="py-2.5 px-3 font-medium text-start">{t('alertsColStatus')}</th>
              <th className="py-2.5 ps-3 font-medium text-end">{t('sensorsColActions')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {alerts.length === 0 ? (
              <tr><td colSpan={5} className="py-8 text-center text-slate-500">{t('alertsNone')}</td></tr>
            ) : (
              alerts.map((a) => (
                <tr key={a.id}>
                  <td className="py-2.5 pe-3 font-mono tabular-nums text-slate-400 whitespace-nowrap" dir="ltr">{formatTimestamp(a.triggeredAt)}</td>
                  <td className="py-2.5 px-3 font-mono">
                    <span className={a.severity === 'critical' ? 'text-red-400' : a.severity === 'warning' ? 'text-amber-400' : 'text-blue-400'}>
                      {severityLabel(a.severity)}
                    </span>
                  </td>
                  <td className="py-2.5 px-3">
                    <p className="text-slate-200 font-medium">{a.title}</p>
                    <p className="text-slate-400 mt-0.5">{a.description}</p>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-300">{statusLabel(a.status)}</td>
                  <td className="py-2.5 ps-3 text-end whitespace-nowrap">
                    {a.status === 'open' && (
                      <button
                        type="button"
                        onClick={() => void handleAlertStatus(a.id, 'acknowledged')}
                        className="px-2.5 py-1 rounded bg-[#070B14] border border-slate-800 text-slate-300 hover:text-white me-1.5"
                      >
                        {t('alertsAcknowledge')}
                      </button>
                    )}
                    {a.status !== 'resolved' && (
                      <button
                        type="button"
                        onClick={() => void handleAlertStatus(a.id, 'resolved')}
                        className="px-2.5 py-1 rounded bg-emerald-600/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-600/30"
                      >
                        {t('alertsResolve')}
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <form onSubmit={handleCreateRule} className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 space-y-3">
        <h3 className="font-display text-sm font-semibold text-white">{t('alertsCreateRuleTitle')}</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          <input
            type="text"
            required
            aria-label={t('alertsRuleNamePlaceholder')}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t('alertsRuleNamePlaceholder')}
            className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white"
          />
          <select
            aria-label={t('alertsCreateRuleTitle')}
            value={ruleType}
            onChange={(e) => setRuleType(e.target.value)}
            className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200"
          >
            <option value="traffic_spike">{t('alertsCondSpike')}</option>
            <option value="dns_burst">{t('alertsCondDns')}</option>
            <option value="new_public_endpoint">{t('alertsCondNewIp')}</option>
            <option value="sensor_offline">{t('alertsCondOffline')}</option>
            <option value="agent_failure">{t('alertsCondFailure')}</option>
            <option value="ingestion_failure">{t('alertsCondIngestFail')}</option>
            <option value="connection_volume">{t('alertsCondVolume')}</option>
          </select>
          <input
            type="number"
            min={1}
            required
            dir="ltr"
            aria-label="Threshold"
            value={threshold}
            onChange={(e) => setThreshold(Number(e.target.value))}
            className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white font-mono"
          />
          <select
            aria-label={t('alertsColSeverity')}
            value={severity}
            onChange={(e) => setSeverity(e.target.value as any)}
            className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200"
          >
            <option value="info">{t('alertsSevInfo')}</option>
            <option value="warning">{t('alertsSevWarn')}</option>
            <option value="critical">{t('alertsSevCrit')}</option>
          </select>
          <button
            type="submit"
            className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{t('alertsAddRuleBtn')}</span>
          </button>
        </div>

        <div className="pt-3 border-t border-slate-800/80 divide-y divide-slate-800/60">
          {rules.map((r) => (
            <div key={r.id} className="py-2 flex items-center justify-between text-xs gap-2">
              <div>
                <span className="text-slate-200 font-medium">{r.name}</span>
                <span className="text-slate-500 ms-2 font-mono" dir="ltr">
                  {r.ruleType} ≥ {r.threshold} · {severityLabel(r.severity)}
                </span>
              </div>
              <button
                type="button"
                onClick={() => void handleToggleRule(r)}
                className={`px-2.5 py-1 rounded font-mono shrink-0 ${
                  r.enabled ? 'bg-emerald-600/20 text-emerald-400' : 'bg-slate-800 text-slate-400'
                }`}
              >
                {r.enabled ? t('alertsEnabled') : t('alertsDisabled')}
              </button>
            </div>
          ))}
        </div>
      </form>
    </div>
  );
}

export function AnalyticsView({ refreshSignal }: { refreshSignal: number }) {
  const { t } = useI18n();
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    void apiClient.request('/api/analytics').then(setData);
  }, [refreshSignal]);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-xl font-semibold text-white tracking-tight">{t('analyticsTitle')}</h2>
        <p className="text-xs text-slate-400 mt-1">
          {t('analyticsSubtitle')}
        </p>
      </div>

      <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80">
        <h3 className="font-display text-sm font-semibold text-white mb-4">{t('analyticsVolTitle')}</h3>
        <TrafficVolumeChart data={data?.volumeOverTime || []} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <h3 className="font-display text-sm font-semibold text-white mb-3">{t('analyticsBySensor')}</h3>
          <HorizontalDistributionList
            items={(data?.bySensor || []).map((s: any) => ({
              name: s.name,
              count: s.packets,
              secondary: formatBytes(s.bytes),
            }))}
            accent="blue"
          />
        </div>
        <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <h3 className="font-display text-sm font-semibold text-white mb-3">{t('analyticsByProto')}</h3>
          <HorizontalDistributionList
            items={(data?.byProtocol || []).map((p: any) => ({
              name: p.protocol,
              count: p.packets,
              secondary: formatBytes(p.bytes),
            }))}
            accent="blue"
          />
        </div>
        <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <h3 className="font-display text-sm font-semibold text-white mb-3">{t('analyticsByApp')}</h3>
          <HorizontalDistributionList
            items={(data?.byApplication || []).map((a: any) => ({
              name: a.appName,
              count: a.packets,
              secondary: formatBytes(a.bytes),
            }))}
            accent="green"
          />
        </div>
      </div>
    </div>
  );
}

export function ReportsView({ refreshSignal }: { refreshSignal: number }) {
  const { t } = useI18n();
  const [reports, setReports] = useState<any[]>([]);
  const [reportType, setReportType] = useState('daily');
  const [title, setTitle] = useState('');
  const [loading, setLoading] = useState(false);

  const loadReports = useCallback(async () => {
    const res = await apiClient.request('/api/reports');
    setReports(res.items || []);
  }, []);

  useEffect(() => {
    void loadReports();
  }, [loadReports, refreshSignal]);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await apiClient.request('/api/reports/generate', {
        method: 'POST',
        body: JSON.stringify({ reportType, title: title.trim() || undefined }),
      });
      setTitle('');
      await loadReports();
    } finally {
      setLoading(false);
    }
  };

  const exportCsv = (report: any) => {
    const s = report.summary || {};
    const lines = [
      'Section,Key,Value',
      `Overview,Title,"${report.title}"`,
      `Overview,Period,"${report.periodStart} to ${report.periodEnd}"`,
      `Overview,Total Packets,${s.totalPackets ?? 0}`,
      `Overview,Total Bytes,${s.totalBytes ?? 0}`,
      `Overview,Unique Source IPs,${s.uniqueSrcIps ?? 0}`,
      `Overview,Unique Destination IPs,${s.uniqueDstIps ?? 0}`,
      ...(s.topProtocols || []).map((p: any) => `Protocol,"${p.name}",${p.count}`),
      ...(s.topApps || []).map((a: any) => `Application,"${a.name}",${a.count}`),
      ...(s.stunCounts || []).map((st: any) => `STUN/TURN,"${st.category}",${st.count}`),
    ];
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.id}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportPdf = (report: any) => {
    const doc = new jsPDF();
    const s = report.summary || {};
    const asciiTitle = String(report.title || 'PacketScope Report').replace(/[^\x20-\x7E]/g, '') || 'PacketScope Report';
    doc.setFontSize(16);
    doc.text(asciiTitle, 14, 20);
    doc.setFontSize(10);
    doc.text(`Type: ${report.reportType.toUpperCase()} | Generated: ${report.createdAt}`, 14, 28);
    doc.text(`Period: ${report.periodStart} to ${report.periodEnd}`, 14, 34);
    doc.text(`Total Packets: ${s.totalPackets ?? 0} | Total Bytes: ${formatBytes(s.totalBytes ?? 0)}`, 14, 44);
    doc.text(`Unique Source IPs: ${s.uniqueSrcIps ?? 0} | Unique Destination IPs: ${s.uniqueDstIps ?? 0}`, 14, 50);

    let y = 62;
    doc.setFontSize(12);
    doc.text('Top Protocols', 14, y);
    y += 6;
    doc.setFontSize(10);
    for (const p of (s.topProtocols || []).slice(0, 8)) {
      doc.text(`- ${p.name}: ${p.count} packets`, 16, y);
      y += 5;
    }

    y += 6;
    doc.setFontSize(12);
    doc.text('Top Applications', 14, y);
    y += 6;
    doc.setFontSize(10);
    for (const a of (s.topApps || []).slice(0, 8)) {
      doc.text(`- ${a.name}: ${a.count} packets`, 16, y);
      y += 5;
    }

    doc.save(`${report.id}.pdf`);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-xl font-semibold text-white tracking-tight">{t('reportsTitle')}</h2>
        <p className="text-xs text-slate-400 mt-1">
          {t('reportsSubtitle')}
        </p>
      </div>

      <form onSubmit={handleGenerate} className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 grid grid-cols-1 md:grid-cols-4 gap-3">
        <select
          aria-label={t('reportsTitle')}
          value={reportType}
          onChange={(e) => setReportType(e.target.value)}
          className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200"
        >
          <option value="daily">{t('reportsDaily')}</option>
          <option value="weekly">{t('reportsWeekly')}</option>
          <option value="monthly">{t('reportsMonthly')}</option>
          <option value="application">{t('reportsApplication')}</option>
          <option value="protocol">{t('reportsProtocol')}</option>
          <option value="sensor_health">{t('reportsSensorHealth')}</option>
          <option value="stun_turn">{t('reportsStunTurn')}</option>
        </select>
        <input
          type="text"
          aria-label={t('reportsTitlePlaceholder')}
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder={t('reportsTitlePlaceholder')}
          className="md:col-span-2 px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500"
        />
        <button
          type="submit"
          disabled={loading}
          className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white"
        >
          {loading ? t('reportsGeneratingBtn') : t('reportsGenerateBtn')}
        </button>
      </form>

      <div className="space-y-3">
        {reports.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 rounded-xl bg-[#0D1526] border border-slate-800/80">
            {t('reportsEmpty')}
          </div>
        ) : (
          reports.map((r) => (
            <div key={r.id} className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 flex flex-wrap items-center justify-between gap-4">
              <div>
                <h3 className="font-display text-sm font-semibold text-white">{r.title}</h3>
                <p className="text-xs text-slate-400 mt-1 font-mono tabular-nums" dir="ltr">
                  {r.reportType.toUpperCase()} · {r.summary?.totalPackets ?? 0} {t('commonPacketsUnit')} · {formatBytes(r.summary?.totalBytes ?? 0)} · {formatTimestamp(r.createdAt)}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => exportCsv(r)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-[#070B14] border border-slate-800 text-slate-200 hover:text-white"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>CSV</span>
                </button>
                <button
                  type="button"
                  onClick={() => exportPdf(r)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-blue-600 hover:bg-blue-500 text-white"
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>PDF</span>
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export function SettingsView() {
  const { t } = useI18n();
  const [note, setNote] = useState('');
  const [geoipEnabled, setGeoipEnabled] = useState(true);
  const [packetDays, setPacketDays] = useState(30);
  const [flowsDays, setFlowsDays] = useState(90);
  const [stunDays, setStunDays] = useState(60);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);

  useEffect(() => {
    void apiClient.request('/api/settings').then((res) => {
      if (res.settings) {
        setNote(res.settings.monitoring_authorization_note || '');
        setGeoipEnabled(Boolean(res.settings.geoip_enabled));
      }
      if (res.retention) {
        setPacketDays(res.retention.packet_events_days);
        setFlowsDays(res.retention.flows_days);
        setStunDays(res.retention.stun_events_days);
      }
    });
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavedMsg(null);
    await apiClient.request('/api/settings', {
      method: 'PATCH',
      body: JSON.stringify({
        monitoringAuthorizationNote: note,
        geoipEnabled,
        packetEventsDays: Number(packetDays),
        flowsDays: Number(flowsDays),
        stunEventsDays: Number(stunDays),
      }),
    });
    setSavedMsg(t('settingsSavedMsg'));
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h2 className="font-display text-xl font-semibold text-white tracking-tight">{t('settingsTitle')}</h2>
        <p className="text-xs text-slate-400 mt-1">
          {t('settingsSubtitle')}
        </p>
      </div>

      <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-xs font-medium text-slate-200">{t('settingsLangLabel')}</p>
          <p className="text-[11px] text-slate-400 mt-0.5">English (LTR) · کوردی سۆرانی (RTL) · العربية (RTL)</p>
        </div>
        <LanguageSwitcher />
      </div>

      <form onSubmit={handleSave} className="p-6 rounded-xl bg-[#0D1526] border border-slate-800/80 space-y-4">
        {savedMsg && <p className="text-xs text-emerald-400">{savedMsg}</p>}
        <div>
          <label htmlFor="auth-note" className="block text-xs font-medium text-slate-300 mb-1.5">
            {t('settingsAuthNoteLabel')}
          </label>
          <textarea
            id="auth-note"
            dir="auto"
            rows={3}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            className="w-full px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white"
          />
        </div>

        <label className="flex items-center gap-2.5 text-xs text-slate-300 cursor-pointer">
          <input
            type="checkbox"
            checked={geoipEnabled}
            onChange={(e) => setGeoipEnabled(e.target.checked)}
            className="rounded border-slate-700 bg-[#070B14]"
          />
          <span>{t('settingsGeoipLabel')}</span>
        </label>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
          <div>
            <label htmlFor="ret-packets" className="block text-xs text-slate-400 mb-1">{t('settingsRetPackets')}</label>
            <input
              id="ret-packets"
              type="number"
              min={1}
              dir="ltr"
              value={packetDays}
              onChange={(e) => setPacketDays(Number(e.target.value))}
              className="w-full px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white font-mono"
            />
          </div>
          <div>
            <label htmlFor="ret-flows" className="block text-xs text-slate-400 mb-1">{t('settingsRetFlows')}</label>
            <input
              id="ret-flows"
              type="number"
              min={1}
              dir="ltr"
              value={flowsDays}
              onChange={(e) => setFlowsDays(Number(e.target.value))}
              className="w-full px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white font-mono"
            />
          </div>
          <div>
            <label htmlFor="ret-stun" className="block text-xs text-slate-400 mb-1">{t('settingsRetStun')}</label>
            <input
              id="ret-stun"
              type="number"
              min={1}
              dir="ltr"
              value={stunDays}
              onChange={(e) => setStunDays(Number(e.target.value))}
              className="w-full px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white font-mono"
            />
          </div>
        </div>

        <button type="submit" className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white">
          {t('settingsSaveBtn')}
        </button>
      </form>
    </div>
  );
}

export function AdministrationView({ orgId }: { orgId: string }) {
  const { t } = useI18n();
  const [members, setMembers] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'admin' | 'analyst' | 'viewer'>('analyst');
  const [msg, setMsg] = useState<string | null>(null);

  const loadAdmin = useCallback(async () => {
    const mRes = await apiClient.request('/api/members');
    setMembers(mRes.items || []);
    try {
      const aRes = await apiClient.request('/api/audit-logs');
      setAuditLogs(aRes.items || []);
    } catch {
      setAuditLogs([]);
    }
  }, []);

  useEffect(() => {
    void loadAdmin();
  }, [loadAdmin, orgId]);

  const handleAssignMember = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg(null);
    try {
      await apiClient.request('/api/members', {
        method: 'POST',
        body: JSON.stringify({ email: inviteEmail.trim(), role: inviteRole }),
      });
      setInviteEmail('');
      setMsg(t('adminAssignedMsg'));
      await loadAdmin();
    } catch (err: any) {
      setMsg(err.message || 'Failed to assign member');
    }
  };

  const roleLabel = (r: string) => {
    if (r === 'admin') return t('adminRoleAdmin');
    if (r === 'analyst') return t('adminRoleAnalyst');
    return t('adminRoleViewer');
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="font-display text-xl font-semibold text-white tracking-tight">{t('adminTitle')}</h2>
          <p className="text-xs text-slate-400 mt-1">
            {t('adminSubtitle')}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <a
            href="/api/openapi.json"
            target="_blank"
            rel="noreferrer"
            className="px-3.5 py-2 text-xs font-medium rounded-lg bg-[#0D1526] hover:bg-slate-800 border border-slate-800 text-slate-200"
          >
            {t('adminOpenApi')}
          </a>
          <button
            type="button"
            onClick={() => void apiClient.downloadBlob('/api/backup/export', `packetscope-backup-${orgId}.json`)}
            className="px-3.5 py-2 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white"
          >
            {t('adminBackupExport')}
          </button>
        </div>
      </div>

      <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 space-y-4">
        <h3 className="font-display text-sm font-semibold text-white">{t('adminMembersTitle')}</h3>
        {msg && <p className="text-xs text-blue-400">{msg}</p>}
        <form onSubmit={handleAssignMember} className="flex flex-wrap gap-3">
          <input
            type="email"
            dir="ltr"
            required
            aria-label={t('adminColEmail')}
            value={inviteEmail}
            onChange={(e) => setInviteEmail(e.target.value)}
            placeholder={t('adminEmailPlaceholder')}
            className="flex-1 min-w-[220px] px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white"
          />
          <select
            aria-label={t('adminColRole')}
            value={inviteRole}
            onChange={(e) => setInviteRole(e.target.value as any)}
            className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200"
          >
            <option value="admin">{t('adminRoleAdmin')}</option>
            <option value="analyst">{t('adminRoleAnalyst')}</option>
            <option value="viewer">{t('adminRoleViewer')}</option>
          </select>
          <button type="submit" className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white">
            {t('adminAssignBtn')}
          </button>
        </form>

        <table className="w-full text-start text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2 pe-3 font-medium text-start">{t('adminColOperator')}</th>
              <th className="py-2 px-3 font-medium text-start">{t('adminColEmail')}</th>
              <th className="py-2 px-3 font-medium text-start">{t('adminColRole')}</th>
              <th className="py-2 ps-3 font-medium text-start">{t('adminColJoined')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {members.map((m) => (
              <tr key={m.userId}>
                <td className="py-2 pe-3 text-slate-200 font-medium">{m.displayName}</td>
                <td className="py-2 px-3 font-mono text-slate-400" dir="ltr">{m.email}</td>
                <td className="py-2 px-3 font-mono text-emerald-400">{roleLabel(m.role)}</td>
                <td className="py-2 ps-3 font-mono tabular-nums text-slate-400" dir="ltr">{formatTimestamp(m.joinedAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 overflow-x-auto">
        <h3 className="font-display text-sm font-semibold text-white mb-3">{t('adminAuditTitle')}</h3>
        <table className="w-full text-start text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2 pe-3 font-medium text-start">{t('colTimestamp')}</th>
              <th className="py-2 px-3 font-medium text-start">{t('adminColActor')}</th>
              <th className="py-2 px-3 font-medium text-start">{t('adminColAction')}</th>
              <th className="py-2 ps-3 font-medium text-start">{t('adminColResource')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {auditLogs.length === 0 ? (
              <tr><td colSpan={4} className="py-6 text-center text-slate-500">{t('adminNoAudit')}</td></tr>
            ) : (
              auditLogs.map((log) => (
                <tr key={log.id}>
                  <td className="py-2 pe-3 font-mono tabular-nums text-slate-400 whitespace-nowrap" dir="ltr">{formatTimestamp(log.createdAt)}</td>
                  <td className="py-2 px-3 text-slate-300" dir="ltr">{log.actorEmail || t('adminSystemActor')}</td>
                  <td className="py-2 px-3 font-mono text-blue-400" dir="ltr">{log.action}</td>
                  <td className="py-2 ps-3 font-mono text-slate-400" dir="ltr">{log.resourceType} · {log.resourceId || '—'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

import React from 'react';
import { RefreshCw } from 'lucide-react';
import type { NavSection, OverviewResponse, TrafficEventItem } from '../types/packetscope';
import { formatBytes, formatRelativeTime, formatTimestamp, stripCidr } from '../lib/api';
import { HorizontalDistributionList, TrafficVolumeChart } from '../components/Charts';
import { useI18n } from '../i18n/I18nContext';

interface OverviewViewProps {
  data: OverviewResponse | null;
  liveFeed: TrafficEventItem[];
  loading: boolean;
  onRefresh: () => void;
  onNavigate: (section: NavSection) => void;
}

export function OverviewView({ data, liveFeed, loading, onRefresh, onNavigate }: OverviewViewProps) {
  const { t } = useI18n();
  const kpis = data?.kpis;
  const feedRows = liveFeed.length > 0 ? liveFeed : data?.recentFeed || [];

  const statusLabel = (status: string) => {
    switch (status) {
      case 'online':
        return t('statusOnline');
      case 'error':
        return t('statusError');
      case 'warning':
        return t('statusWarning');
      case 'paused':
        return t('statusPaused');
      default:
        return t('statusOffline');
    }
  };

  const severityLabel = (sev: string) => {
    if (sev === 'critical') return t('alertsSevCrit');
    if (sev === 'warning') return t('alertsSevWarn');
    return t('alertsSevInfo');
  };

  const metricCards = [
    {
      label: t('kpiPackets24h'),
      value: (kpis?.packets24h ?? 0).toLocaleString(),
      sub: t('kpiPktPerSec', { rate: kpis?.packetsPerSecond ?? 0 }),
    },
    {
      label: t('kpiActiveSensors'),
      value: `${kpis?.activeSensors ?? 0} / ${kpis?.registeredSensors ?? 0}`,
      sub: t('kpiAuthorizedAgents'),
    },
    {
      label: t('kpiUniqueIps'),
      value: `${kpis?.uniqueSrcIps ?? 0} / ${kpis?.uniqueDstIps ?? 0}`,
      sub: t('kpiNormalizedHosts'),
    },
    {
      label: t('kpiDetectedApps'),
      value: (kpis?.detectedApplications ?? 0).toLocaleString(),
      sub: t('kpiUnclassifiedCount', { count: (kpis?.unclassifiedPackets ?? 0).toLocaleString() }),
    },
    {
      label: t('kpiConfirmedStun'),
      value: (kpis?.confirmedStunPackets ?? 0).toLocaleString(),
      sub: t('kpiDissectorRfc'),
    },
    {
      label: t('kpiConfirmedTurn'),
      value: (kpis?.confirmedTurnPackets ?? 0).toLocaleString(),
      sub: t('kpiSuspectedWebrtcCount', { count: (kpis?.suspectedWebrtcFlows ?? 0).toLocaleString() }),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="font-display text-xl font-semibold text-white tracking-tight">{t('overviewTitle')}</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            {t('overviewLastPacket')}{' '}
            <span className="font-mono text-slate-300" dir="ltr">
              {kpis?.lastPacketAt ? formatTimestamp(kpis.lastPacketAt) : t('commonNever')}
            </span>
            <span className="mx-2" aria-hidden="true">·</span>
            {t('overviewRefreshed')}{' '}
            <span className="font-mono text-slate-300" dir="ltr">
              {data?.updatedAt ? formatTimestamp(data.updatedAt) : t('commonNever')}
            </span>
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onRefresh}
            disabled={loading}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium rounded-lg bg-[#0D1526] hover:bg-slate-800 border border-slate-800 text-slate-200 transition-colors whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>{loading ? t('overviewRefreshing') : t('overviewRefreshBtn')}</span>
          </button>
          <button
            type="button"
            onClick={() => onNavigate('sensors')}
            className="px-3.5 py-2 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors whitespace-nowrap shrink-0"
          >
            {t('overviewManageSensors')}
          </button>
        </div>
      </div>

      {kpis && kpis.registeredSensors === 0 && (
        <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 flex flex-wrap items-center justify-between gap-4">
          <div>
            <h3 className="font-display text-sm font-semibold text-white">{t('overviewEmptyTitle')}</h3>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              {t('overviewEmptyDesc')}
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('sensors')}
            className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors whitespace-nowrap shrink-0"
          >
            {t('overviewRegisterFirst')}
          </button>
        </div>
      )}

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {metricCards.map((card) => (
          <div key={card.label} className="p-4 rounded-xl bg-[#0D1526] border border-slate-800/80">
            <p className="text-xs text-slate-400">{card.label}</p>
            <p className="font-mono tabular-nums text-2xl font-semibold text-white mt-1.5" dir="ltr">{card.value}</p>
            <p className="text-xs text-slate-500 mt-1">{card.sub}</p>
          </div>
        ))}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-6 p-5 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display text-sm font-semibold text-white">{t('chartTrafficVolume')}</h3>
            <span className="text-xs text-slate-500">{t('chartHourlyMeta')}</span>
          </div>
          <TrafficVolumeChart data={data?.volumeTimeline || []} />
        </div>

        <div className="lg:col-span-3 p-5 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display text-sm font-semibold text-white">{t('chartProtoDist')}</h3>
            <button
              type="button"
              onClick={() => onNavigate('protocols')}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              {t('chartViewAll')}
            </button>
          </div>
          <HorizontalDistributionList
            items={(data?.protocolDistribution || []).map((p) => ({
              name: p.name,
              count: p.count,
              secondary: formatBytes(p.bytes),
            }))}
            accent="blue"
          />
        </div>

        <div className="lg:col-span-3 p-5 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display text-sm font-semibold text-white">{t('chartAppClass')}</h3>
            <button
              type="button"
              onClick={() => onNavigate('applications')}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              {t('chartDetails')}
            </button>
          </div>
          <HorizontalDistributionList
            items={(data?.appDistribution || []).map((a) => ({
              name: a.name,
              count: a.count,
            }))}
            accent="green"
          />
        </div>
      </div>

      {/* Live Packet Feed + Sensor Health / Alerts */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <div className="xl:col-span-8 p-5 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display text-sm font-semibold text-white">{t('feedTitle')}</h3>
            <button
              type="button"
              onClick={() => onNavigate('live-traffic')}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              {t('feedOpenExplorer')}
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-start text-[11px] border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2 pe-1.5 font-medium text-start">{t('colTime')}</th>
                  <th className="py-2 px-1.5 font-medium text-start">{t('colSource')}</th>
                  <th className="py-2 px-1.5 font-medium text-start">{t('colDestination')}</th>
                  <th className="py-2 px-1.5 font-medium text-start">{t('colProtocol')}</th>
                  <th className="py-2 px-1.5 font-medium text-start">{t('colApplication')}</th>
                  <th className="py-2 ps-1.5 font-medium text-end">{t('colSize')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {feedRows.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500 text-xs">
                      {t('feedEmpty')}
                    </td>
                  </tr>
                ) : (
                  feedRows.slice(0, 12).map((row) => {
                    const shortTime = new Date(row.observedAt).toLocaleTimeString(undefined, {
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                      hour12: false,
                    });
                    return (
                      <tr key={row.id} className="hover:bg-slate-800/30">
                        <td
                          className="py-2 pe-1.5 font-mono tabular-nums text-slate-400 whitespace-nowrap"
                          title={formatTimestamp(row.observedAt)}
                          dir="ltr"
                        >
                          {shortTime}
                        </td>
                        <td className="py-2 px-1.5 font-mono tabular-nums text-slate-200 whitespace-nowrap" dir="ltr">
                          {stripCidr(row.srcIp)}
                          {row.srcPort ? `:${row.srcPort}` : ''}
                        </td>
                        <td className="py-2 px-1.5 font-mono tabular-nums text-slate-200 whitespace-nowrap" dir="ltr">
                          {stripCidr(row.dstIp)}
                          {row.dstPort ? `:${row.dstPort}` : ''}
                        </td>
                        <td className="py-2 px-1.5 font-mono text-blue-400 whitespace-nowrap" dir="ltr">{row.protocol}</td>
                        <td className="py-2 px-1.5 text-slate-200 whitespace-nowrap max-w-[165px] truncate">
                          {row.appLabel}
                          <span className="text-slate-500 ms-1" dir="ltr">· {row.confidence}</span>
                        </td>
                        <td className="py-2 ps-1.5 font-mono tabular-nums text-slate-400 text-end whitespace-nowrap" dir="ltr">
                          {row.packetLength} B
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="xl:col-span-4 space-y-5">
          <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-display text-sm font-semibold text-white">{t('sensorStatusTitle')}</h3>
              <button type="button" onClick={() => onNavigate('sensors')} className="text-xs text-blue-400 hover:text-blue-300">
                {t('sensorAllLink')}
              </button>
            </div>
            {(data?.sensors || []).length === 0 ? (
              <p className="text-xs text-slate-500 py-4">{t('sensorNone')}</p>
            ) : (
              <div className="space-y-2.5">
                {data!.sensors.slice(0, 5).map((s) => (
                  <div key={s.id} className="flex items-center justify-between py-1.5 border-b border-slate-800/60 last:border-0 text-xs">
                    <div className="min-w-0">
                      <p className="font-medium text-slate-200 truncate">{s.name}</p>
                      <p className="text-slate-500 truncate">
                        {s.activeInterface || t('sensorAwaitingIfc')} ·{' '}
                        <span dir="ltr">{s.lastHeartbeatAt ? formatRelativeTime(s.lastHeartbeatAt) : t('commonNever')}</span>
                      </p>
                    </div>
                    <span
                      className={`font-mono text-xs shrink-0 ms-2 ${
                        s.status === 'online'
                          ? 'text-emerald-400'
                          : s.status === 'error'
                          ? 'text-red-400'
                          : s.status === 'warning'
                          ? 'text-amber-400'
                          : 'text-slate-400'
                      }`}
                    >
                      {statusLabel(s.status)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-display text-sm font-semibold text-white">{t('alertsActiveTitle')}</h3>
              <button type="button" onClick={() => onNavigate('alerts')} className="text-xs text-blue-400 hover:text-blue-300">
                {t('alertsCenterLink')}
              </button>
            </div>
            {(data?.openAlerts || []).length === 0 ? (
              <p className="text-xs text-slate-500 py-4">{t('alertsNoneOpen')}</p>
            ) : (
              <div className="space-y-2.5">
                {data!.openAlerts.slice(0, 4).map((a) => (
                  <div key={a.id} className="p-2.5 rounded-lg bg-[#070B14] border border-slate-800/80 text-xs">
                    <div className="flex items-center justify-between">
                      <span className={a.severity === 'critical' ? 'text-red-400 font-medium' : 'text-amber-400 font-medium'}>
                        {severityLabel(a.severity)}
                      </span>
                      <span className="font-mono text-slate-500" dir="ltr">{formatRelativeTime(a.triggeredAt)}</span>
                    </div>
                    <p className="text-slate-200 font-medium mt-1">{a.title}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Top Endpoints */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <h3 className="font-display text-sm font-semibold text-white mb-3">{t('topSrcIps')}</h3>
          <HorizontalDistributionList
            items={(data?.topSrcIps || []).map((ip) => ({
              name: stripCidr(ip.ip),
              count: ip.packets,
              secondary: formatBytes(ip.bytes),
            }))}
            accent="blue"
          />
        </div>
        <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <h3 className="font-display text-sm font-semibold text-white mb-3">{t('topDstIps')}</h3>
          <HorizontalDistributionList
            items={(data?.topDstIps || []).map((ip) => ({
              name: stripCidr(ip.ip),
              count: ip.packets,
              secondary: formatBytes(ip.bytes),
            }))}
            accent="green"
          />
        </div>
      </div>
    </div>
  );
}

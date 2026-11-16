import React, { useCallback, useEffect, useState } from 'react';
import { Download, Search, ArrowUpDown } from 'lucide-react';
import { apiClient, formatBytes, formatTimestamp, stripCidr } from '../lib/api';
import type { SensorRecord, TrafficEventItem } from '../types/packetscope';
import { useI18n } from '../i18n/I18nContext';

export function LiveTrafficView({ refreshSignal }: { refreshSignal: number }) {
  const { t } = useI18n();
  const [tab, setTab] = useState<'packets' | 'flows'>('packets');
  const [items, setItems] = useState<TrafficEventItem[]>([]);
  const [flows, setFlows] = useState<any[]>([]);
  const [sensors, setSensors] = useState<SensorRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(false);

  const [search, setSearch] = useState('');
  const [protocol, setProtocol] = useState('');
  const [application, setApplication] = useState('');
  const [sensorId, setSensorId] = useState('');
  const [srcIp, setSrcIp] = useState('');
  const [dstIp, setDstIp] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [sortBy, setSortBy] = useState('observedAt');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  const loadSensors = useCallback(async () => {
    try {
      const res = await apiClient.request<{ items: SensorRecord[] }>('/api/sensors');
      setSensors(res.items || []);
    } catch {
      // ignore
    }
  }, []);

  const loadTraffic = useCallback(async () => {
    setLoading(true);
    try {
      if (tab === 'packets') {
        const params = new URLSearchParams({
          page: String(page),
          pageSize: '25',
          sortBy,
          sortDir,
        });
        if (search.trim()) params.set('search', search.trim());
        if (protocol) params.set('protocol', protocol);
        if (application.trim()) params.set('application', application.trim());
        if (sensorId) params.set('sensorId', sensorId);
        if (srcIp.trim()) params.set('srcIp', srcIp.trim());
        if (dstIp.trim()) params.set('dstIp', dstIp.trim());
        if (startDate) params.set('startDate', new Date(startDate).toISOString());
        if (endDate) params.set('endDate', new Date(endDate).toISOString());

        const res = await apiClient.request<any>(`/api/traffic?${params.toString()}`);
        setItems(res.items || []);
        setTotal(res.total || 0);
        setTotalPages(res.totalPages || 1);
      } else {
        const res = await apiClient.request<any>('/api/traffic/flows');
        setFlows(res.items || []);
      }
    } finally {
      setLoading(false);
    }
  }, [tab, page, sortBy, sortDir, search, protocol, application, sensorId, srcIp, dstIp, startDate, endDate]);

  useEffect(() => {
    void loadSensors();
  }, [loadSensors]);

  useEffect(() => {
    void loadTraffic();
  }, [loadTraffic, refreshSignal]);

  const handleSort = (col: string) => {
    if (sortBy === col) {
      setSortDir((d) => (d === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortBy(col);
      setSortDir('desc');
    }
  };

  const handleExportCsv = () => {
    const params = new URLSearchParams();
    if (search.trim()) params.set('search', search.trim());
    if (protocol) params.set('protocol', protocol);
    if (application.trim()) params.set('application', application.trim());
    if (sensorId) params.set('sensorId', sensorId);
    if (srcIp.trim()) params.set('srcIp', srcIp.trim());
    if (dstIp.trim()) params.set('dstIp', dstIp.trim());
    void apiClient.downloadBlob(`/api/traffic/export.csv?${params.toString()}`, 'packetscope-traffic.csv');
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="font-display text-xl font-semibold text-white tracking-tight">{t('trafficTitle')}</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            {t('trafficSubtitle')}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="inline-flex p-1 bg-[#0D1526] border border-slate-800 rounded-lg">
            <button
              type="button"
              onClick={() => setTab('packets')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                tab === 'packets' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              {t('trafficTabPackets')}
            </button>
            <button
              type="button"
              onClick={() => setTab('flows')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                tab === 'flows' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              {t('trafficTabFlows')}
            </button>
          </div>

          <button
            type="button"
            onClick={handleExportCsv}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg bg-[#0D1526] hover:bg-slate-800 border border-slate-800 text-slate-200 whitespace-nowrap shrink-0"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{t('trafficExportCsv')}</span>
          </button>
        </div>
      </div>

      {tab === 'packets' && (
        <div className="p-4 rounded-xl bg-[#0D1526] border border-slate-800/80 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-3">
          <div className="xl:col-span-2 relative">
            <label htmlFor="traffic-search" className="sr-only">{t('trafficSearchPlaceholder')}</label>
            <Search className="w-3.5 h-3.5 text-slate-500 absolute start-3 top-2.5" />
            <input
              id="traffic-search"
              type="text"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              placeholder={t('trafficSearchPlaceholder')}
              className="w-full ps-8 pe-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <label htmlFor="traffic-proto" className="sr-only">{t('colProtocol')}</label>
            <select
              id="traffic-proto"
              value={protocol}
              onChange={(e) => {
                setProtocol(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="">{t('trafficAllProtocols')}</option>
              {['TCP', 'UDP', 'DNS', 'TLS', 'QUIC', 'HTTP', 'STUN', 'TURN', 'DTLS', 'mDNS', 'SSDP', 'DHCP', 'ICMP'].map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="traffic-sensor" className="sr-only">{t('colSensor')}</label>
            <select
              id="traffic-sensor"
              value={sensorId}
              onChange={(e) => {
                setSensorId(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="">{t('commonAllSensors')}</option>
              {sensors.map((s) => (
                <option key={s.id} value={s.id}>{s.name}</option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="traffic-src" className="sr-only">{t('colSource')}</label>
            <input
              id="traffic-src"
              type="text"
              dir="ltr"
              value={srcIp}
              onChange={(e) => {
                setSrcIp(e.target.value);
                setPage(1);
              }}
              placeholder={t('trafficSrcPlaceholder')}
              className="w-full px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <label htmlFor="traffic-dst" className="sr-only">{t('colDestination')}</label>
            <input
              id="traffic-dst"
              type="text"
              dir="ltr"
              value={dstIp}
              onChange={(e) => {
                setDstIp(e.target.value);
                setPage(1);
              }}
              placeholder={t('trafficDstPlaceholder')}
              className="w-full px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <label htmlFor="traffic-app" className="sr-only">{t('colApplication')}</label>
            <input
              id="traffic-app"
              type="text"
              value={application}
              onChange={(e) => {
                setApplication(e.target.value);
                setPage(1);
              }}
              placeholder={t('trafficAppPlaceholder')}
              className="w-full px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="sm:col-span-2 lg:col-span-4 xl:col-span-7 flex flex-wrap items-center gap-3 pt-1">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <label htmlFor="traffic-start">{t('commonFrom')}</label>
              <input
                id="traffic-start"
                type="datetime-local"
                dir="ltr"
                value={startDate}
                onChange={(e) => {
                  setStartDate(e.target.value);
                  setPage(1);
                }}
                className="px-2.5 py-1.5 bg-[#070B14] border border-slate-800 rounded-md text-slate-200 text-xs"
              />
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <label htmlFor="traffic-end">{t('commonTo')}</label>
              <input
                id="traffic-end"
                type="datetime-local"
                dir="ltr"
                value={endDate}
                onChange={(e) => {
                  setEndDate(e.target.value);
                  setPage(1);
                }}
                className="px-2.5 py-1.5 bg-[#070B14] border border-slate-800 rounded-md text-slate-200 text-xs"
              />
            </div>
            {(search || protocol || application || sensorId || srcIp || dstIp || startDate || endDate) && (
              <button
                type="button"
                onClick={() => {
                  setSearch('');
                  setProtocol('');
                  setApplication('');
                  setSensorId('');
                  setSrcIp('');
                  setDstIp('');
                  setStartDate('');
                  setEndDate('');
                  setPage(1);
                }}
                className="text-xs text-blue-400 hover:text-blue-300"
              >
                {t('trafficClearFilters')}
              </button>
            )}
          </div>
        </div>
      )}

      <div className="rounded-xl bg-[#0D1526] border border-slate-800/80 overflow-hidden">
        {tab === 'packets' ? (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-start text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 bg-[#0A101E] text-slate-400">
                    <th className="py-3 px-4 font-medium text-start">
                      <button type="button" onClick={() => handleSort('observedAt')} className="inline-flex items-center gap-1 hover:text-white">
                        {t('colTimestamp')} <ArrowUpDown className="w-3 h-3" />
                      </button>
                    </th>
                    <th className="py-3 px-3 font-medium text-start">{t('colSensor')}</th>
                    <th className="py-3 px-3 font-medium text-start">{t('colSource')}</th>
                    <th className="py-3 px-3 font-medium text-start">{t('colDestination')}</th>
                    <th className="py-3 px-3 font-medium text-start">{t('colTransport')}</th>
                    <th className="py-3 px-3 font-medium text-start">
                      <button type="button" onClick={() => handleSort('protocol')} className="inline-flex items-center gap-1 hover:text-white">
                        {t('colProtocol')} <ArrowUpDown className="w-3 h-3" />
                      </button>
                    </th>
                    <th className="py-3 px-3 font-medium text-start">
                      <button type="button" onClick={() => handleSort('appLabel')} className="inline-flex items-center gap-1 hover:text-white">
                        {t('colApplication')} <ArrowUpDown className="w-3 h-3" />
                      </button>
                    </th>
                    <th className="py-3 px-3 font-medium text-start">{t('colHostnameSni')}</th>
                    <th className="py-3 px-3 font-medium text-end">
                      <button type="button" onClick={() => handleSort('packetLength')} className="inline-flex items-center gap-1 hover:text-white ms-auto">
                        {t('colSize')} <ArrowUpDown className="w-3 h-3" />
                      </button>
                    </th>
                    <th className="py-3 px-4 font-medium text-start">{t('colConfidence')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {loading && items.length === 0 ? (
                    <tr>
                      <td colSpan={10} className="py-10 text-center text-slate-400">{t('trafficLoading')}</td>
                    </tr>
                  ) : items.length === 0 ? (
                    <tr>
                      <td colSpan={10} className="py-10 text-center text-slate-500">
                        {t('trafficNoMatch')}
                      </td>
                    </tr>
                  ) : (
                    items.map((row) => (
                      <tr key={row.id} className="hover:bg-slate-800/30">
                        <td className="py-2.5 px-4 font-mono tabular-nums text-slate-400 whitespace-nowrap" dir="ltr">
                          {formatTimestamp(row.observedAt)}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">{row.sensorName}</td>
                        <td className="py-2.5 px-3 font-mono tabular-nums text-slate-200 whitespace-nowrap" dir="ltr">
                          {stripCidr(row.srcIp)}
                          {row.srcPort ? `:${row.srcPort}` : ''}
                        </td>
                        <td className="py-2.5 px-3 font-mono tabular-nums text-slate-200 whitespace-nowrap" dir="ltr">
                          {stripCidr(row.dstIp)}
                          {row.dstPort ? `:${row.dstPort}` : ''}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-400" dir="ltr">{row.transport}</td>
                        <td className="py-2.5 px-3 font-mono text-blue-400" dir="ltr">{row.protocol}</td>
                        <td className="py-2.5 px-3 text-slate-200 whitespace-nowrap">{row.appLabel}</td>
                        <td className="py-2.5 px-3 font-mono text-slate-400 max-w-[200px] truncate" dir="ltr">{row.hostname || '—'}</td>
                        <td className="py-2.5 px-3 font-mono tabular-nums text-slate-300 text-end whitespace-nowrap" dir="ltr">
                          {row.packetLength} B
                        </td>
                        <td className="py-2.5 px-4 font-mono text-xs whitespace-nowrap" dir="ltr">
                          <span
                            className={
                              row.confidence === 'HIGH'
                                ? 'text-emerald-400'
                                : row.confidence === 'MEDIUM'
                                ? 'text-blue-400'
                                : row.confidence === 'LOW'
                                ? 'text-amber-400'
                                : 'text-slate-500'
                            }
                          >
                            {row.confidence}
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-t border-slate-800/80 text-xs text-slate-400">
              <span className="font-mono tabular-nums">
                {t('trafficPagination', { total: total.toLocaleString(), page, totalPages })}
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="px-3 py-1.5 rounded-md bg-[#070B14] border border-slate-800 text-slate-300 disabled:opacity-40"
                >
                  {t('commonPrevious')}
                </button>
                <button
                  type="button"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  className="px-3 py-1.5 rounded-md bg-[#070B14] border border-slate-800 text-slate-300 disabled:opacity-40"
                >
                  {t('commonNext')}
                </button>
              </div>
            </div>
          </>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-start text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-[#0A101E] text-slate-400">
                  <th className="py-3 px-4 font-medium text-start">{t('trafficLastSeen')}</th>
                  <th className="py-3 px-3 font-medium text-start">{t('colSensor')}</th>
                  <th className="py-3 px-3 font-medium text-start">{t('colSource')}</th>
                  <th className="py-3 px-3 font-medium text-start">{t('colDestination')}</th>
                  <th className="py-3 px-3 font-medium text-start">{t('colProtocol')}</th>
                  <th className="py-3 px-3 font-medium text-start">{t('colApplication')}</th>
                  <th className="py-3 px-3 font-medium text-end">{t('trafficPacketsCol')}</th>
                  <th className="py-3 px-4 font-medium text-end">{t('trafficBytesCol')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {flows.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-10 text-center text-slate-500">{t('trafficNoFlows')}</td>
                  </tr>
                ) : (
                  flows.map((f) => (
                    <tr key={f.id} className="hover:bg-slate-800/30">
                      <td className="py-2.5 px-4 font-mono tabular-nums text-slate-400 whitespace-nowrap" dir="ltr">
                        {formatTimestamp(f.lastSeenAt)}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">{f.sensorName}</td>
                      <td className="py-2.5 px-3 font-mono tabular-nums text-slate-200" dir="ltr">
                        {stripCidr(f.srcIp)}:{f.srcPort ?? 0}
                      </td>
                      <td className="py-2.5 px-3 font-mono tabular-nums text-slate-200" dir="ltr">
                        {stripCidr(f.dstIp)}:{f.dstPort ?? 0}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-blue-400" dir="ltr">{f.protocol}</td>
                      <td className="py-2.5 px-3 text-slate-200">
                        {f.appLabel} <span className="text-slate-500" dir="ltr">· {f.confidence}</span>
                      </td>
                      <td className="py-2.5 px-3 font-mono tabular-nums text-end text-slate-300" dir="ltr">{f.packetCount}</td>
                      <td className="py-2.5 px-4 font-mono tabular-nums text-end text-slate-300" dir="ltr">{formatBytes(f.byteCount)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

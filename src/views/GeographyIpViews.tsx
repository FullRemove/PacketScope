import React, { useCallback, useEffect, useState } from 'react';
import { RefreshCw, Search } from 'lucide-react';
import { apiClient, formatTimestamp, stripCidr } from '../lib/api';
import { WorldMap } from '../components/WorldMap';
import type { GeoMarkerItem, SensorRecord } from '../types/packetscope';
import { useI18n } from '../i18n/I18nContext';

export function NetworkGeographyView({ refreshSignal }: { refreshSignal: number }) {
  const { t } = useI18n();
  const [markers, setMarkers] = useState<GeoMarkerItem[]>([]);
  const [sensors, setSensors] = useState<SensorRecord[]>([]);
  const [sensorId, setSensorId] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [stats, setStats] = useState<{ totalPublicEndpoints: number; locatedEndpoints: number; rateLimit?: any }>({
    totalPublicEndpoints: 0,
    locatedEndpoints: 0,
  });
  const [loading, setLoading] = useState(false);

  const loadGeo = useCallback(
    async (forceRefresh = false) => {
      setLoading(true);
      try {
        const params = new URLSearchParams();
        if (forceRefresh) params.set('refresh', '1');
        if (sensorId) params.set('sensorId', sensorId);
        if (startDate) params.set('startDate', new Date(startDate).toISOString());
        if (endDate) params.set('endDate', new Date(endDate).toISOString());

        const [geoRes, sensorRes] = await Promise.all([
          apiClient.request(`/api/geography?${params.toString()}`),
          apiClient.request('/api/sensors'),
        ]);
        setMarkers(geoRes.markers || []);
        setStats({
          totalPublicEndpoints: geoRes.totalPublicEndpoints || 0,
          locatedEndpoints: geoRes.locatedEndpoints || 0,
          rateLimit: geoRes.rateLimit,
        });
        setSensors(sensorRes.items || []);
      } finally {
        setLoading(false);
      }
    },
    [sensorId, startDate, endDate]
  );

  useEffect(() => {
    void loadGeo(false);
  }, [loadGeo, refreshSignal]);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="font-display text-xl font-semibold text-white tracking-tight">{t('geoTitle')}</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            {t('geoStatsLine', { located: stats.locatedEndpoints, total: stats.totalPublicEndpoints })}
          </p>
        </div>

        <button
          type="button"
          onClick={() => void loadGeo(true)}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium rounded-lg bg-[#0D1526] hover:bg-slate-800 border border-slate-800 text-slate-200 whitespace-nowrap shrink-0"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>{loading ? t('geoRefreshingBtn') : t('geoRefreshBtn')}</span>
        </button>
      </div>

      <div className="p-4 rounded-xl bg-[#0D1526] border border-slate-800/80 flex flex-wrap items-center gap-3 text-xs">
        <select
          aria-label={t('colSensor')}
          value={sensorId}
          onChange={(e) => setSensorId(e.target.value)}
          className="px-3 py-1.5 bg-[#070B14] border border-slate-800 rounded-lg text-slate-200"
        >
          <option value="">{t('commonAllSensors')}</option>
          {sensors.map((s) => (
            <option key={s.id} value={s.id}>{s.name}</option>
          ))}
        </select>

        <div className="flex items-center gap-2 text-slate-400">
          <label htmlFor="geo-start">{t('commonFrom')}</label>
          <input
            id="geo-start"
            type="datetime-local"
            dir="ltr"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
            className="px-2.5 py-1.5 bg-[#070B14] border border-slate-800 rounded-lg text-slate-200"
          />
        </div>
        <div className="flex items-center gap-2 text-slate-400">
          <label htmlFor="geo-end">{t('commonTo')}</label>
          <input
            id="geo-end"
            type="datetime-local"
            dir="ltr"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
            className="px-2.5 py-1.5 bg-[#070B14] border border-slate-800 rounded-lg text-slate-200"
          />
        </div>

        {stats.rateLimit && (
          <span className="ms-auto font-mono text-slate-400">
            {t('geoQuotaLine', {
              remaining: stats.rateLimit.remaining,
              limit: stats.rateLimit.limitPerMinute,
            })}
          </span>
        )}
      </div>

      <WorldMap markers={markers} />
    </div>
  );
}

export function IpIntelligenceView({ refreshSignal }: { refreshSignal: number }) {
  const { t } = useI18n();
  const [items, setItems] = useState<any[]>([]);
  const [lookupIp, setLookupIp] = useState('');
  const [lookupResult, setLookupResult] = useState<any>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const loadList = useCallback(async () => {
    const res = await apiClient.request('/api/ip-intelligence');
    setItems(res.items || []);
  }, []);

  useEffect(() => {
    void loadList();
  }, [loadList, refreshSignal]);

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    setLookupError(null);
    setLoading(true);
    try {
      const res = await apiClient.request('/api/ip-intelligence/lookup', {
        method: 'POST',
        body: JSON.stringify({ ip: lookupIp }),
      });
      setLookupResult(res.intel);
      await loadList();
    } catch (err: any) {
      setLookupError(err.message || 'Lookup failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-xl font-semibold text-white tracking-tight">{t('ipIntelTitle')}</h2>
        <p className="text-xs text-slate-400 mt-1">
          {t('ipIntelSubtitle')}
        </p>
      </div>

      <form onSubmit={handleLookup} className="p-4 rounded-xl bg-[#0D1526] border border-slate-800/80 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <label htmlFor="ip-lookup-input" className="sr-only">{t('ipIntelIpCol')}</label>
          <Search className="w-3.5 h-3.5 text-slate-500 absolute start-3 top-2.5" />
          <input
            id="ip-lookup-input"
            type="text"
            dir="ltr"
            required
            value={lookupIp}
            onChange={(e) => setLookupIp(e.target.value)}
            placeholder={t('ipIntelPlaceholder')}
            className="w-full ps-8 pe-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white whitespace-nowrap shrink-0"
        >
          {loading ? t('ipIntelResolvingBtn') : t('ipIntelResolveBtn')}
        </button>
        {lookupError && <p className="w-full text-xs text-red-400">{lookupError}</p>}
      </form>

      {lookupResult && (
        <div className="p-4 rounded-xl bg-[#0D1526] border border-slate-800/80 text-xs grid grid-cols-2 md:grid-cols-5 gap-4">
          <div>
            <p className="text-slate-400">{t('ipIntelIpCol')}</p>
            <p className="font-mono font-semibold text-white mt-0.5" dir="ltr">{stripCidr(lookupResult.ip)}</p>
          </div>
          <div>
            <p className="text-slate-400">{t('ipIntelScopeCol')}</p>
            <p className="text-slate-200 mt-0.5">{lookupResult.isPublic ? t('ipIntelPublicScope') : t('ipIntelPrivateScope')}</p>
          </div>
          <div>
            <p className="text-slate-400">ASN / ISP</p>
            <p className="font-mono text-slate-200 mt-0.5" dir="ltr">{lookupResult.asn || '—'} · {lookupResult.isp || '—'}</p>
          </div>
          <div>
            <p className="text-slate-400">{t('ipIntelApproxRegion')}</p>
            <p className="text-slate-200 mt-0.5">{[lookupResult.city, lookupResult.countryName].filter(Boolean).join(', ') || t('commonUnknown')}</p>
          </div>
          <div>
            <p className="text-slate-400">{t('ipIntelSource')}</p>
            <p className="font-mono text-emerald-400 mt-0.5" dir="ltr">{lookupResult.providerSource}</p>
          </div>
        </div>
      )}

      <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 overflow-x-auto">
        <h3 className="font-display text-sm font-semibold text-white mb-3">{t('ipIntelObservedTitle')}</h3>
        <table className="w-full text-start text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2.5 pe-3 font-medium text-start">{t('ipIntelIpCol')}</th>
              <th className="py-2.5 px-3 font-medium text-start">{t('ipIntelScopeCol')}</th>
              <th className="py-2.5 px-3 font-medium text-start">ASN</th>
              <th className="py-2.5 px-3 font-medium text-start">{t('ipIntelIspOrgCol')}</th>
              <th className="py-2.5 px-3 font-medium text-start">{t('ipIntelApproxLocCol')}</th>
              <th className="py-2.5 px-3 font-medium text-end">{t('ipIntelActivityCol')}</th>
              <th className="py-2.5 ps-3 font-medium text-start">{t('stunLastObservedCol')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {items.length === 0 ? (
              <tr><td colSpan={7} className="py-8 text-center text-slate-500">{t('ipIntelNoEndpoints')}</td></tr>
            ) : (
              items.map((item) => (
                <tr key={item.ip}>
                  <td className="py-2.5 pe-3 font-mono text-white" dir="ltr">{stripCidr(item.ip)}</td>
                  <td className="py-2.5 px-3 font-mono">
                    <span className={item.isPublic ? 'text-emerald-400' : 'text-slate-400'}>
                      {item.isPublic ? t('ipIntelPublicShort') : t('ipIntelPrivateShort')}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-300" dir="ltr">{item.asn || '—'}</td>
                  <td className="py-2.5 px-3 text-slate-300">{item.orgName || item.isp || '—'}</td>
                  <td className="py-2.5 px-3 text-slate-300">
                    {item.isPublic ? [item.city, item.countryName].filter(Boolean).join(', ') || t('ipIntelPending') : t('ipIntelExcludedPrivate')}
                  </td>
                  <td className="py-2.5 px-3 font-mono tabular-nums text-end text-slate-200" dir="ltr">{item.activityCount}</td>
                  <td className="py-2.5 ps-3 font-mono tabular-nums text-slate-400" dir="ltr">{formatTimestamp(item.lastObservedAt)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

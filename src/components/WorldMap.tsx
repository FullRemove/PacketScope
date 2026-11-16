import React, { useMemo, useState } from 'react';
import { geoNaturalEarth1, geoPath } from 'd3-geo';
import { feature } from 'topojson-client';
import worldAtlas from 'world-atlas/countries-110m.json';
import type { GeoMarkerItem } from '../types/packetscope';
import { formatTimestamp, stripCidr } from '../lib/api';
import { useI18n } from '../i18n/I18nContext';

interface EndpointCluster {
  key: string;
  latitude: number;
  longitude: number;
  countryName: string | null;
  city: string | null;
  totalActivity: number;
  endpoints: GeoMarkerItem[];
}

export function WorldMap({ markers }: { markers: GeoMarkerItem[] }) {
  const { t } = useI18n();
  const [selectedCluster, setSelectedCluster] = useState<EndpointCluster | null>(null);
  const [zoom, setZoom] = useState(1);

  const countries = useMemo(() => {
    const topo = worldAtlas as any;
    const fc = feature(topo, topo.objects.countries) as any;
    return fc.features as any[];
  }, []);

  const width = 920;
  const height = 440;

  const projection = useMemo(() => {
    return geoNaturalEarth1().scale(168 * zoom).translate([width / 2, height / 2 + 18]);
  }, [zoom]);

  const pathGen = useMemo(() => geoPath(projection), [projection]);

  // Group overlapping endpoint coordinates (rounded to 1 decimal place ~11km)
  const clusters = useMemo<EndpointCluster[]>(() => {
    const map = new Map<string, EndpointCluster>();
    for (const m of markers) {
      if (typeof m.latitude !== 'number' || typeof m.longitude !== 'number') continue;
      const latKey = m.latitude.toFixed(1);
      const lonKey = m.longitude.toFixed(1);
      const key = `${latKey},${lonKey}`;
      const existing = map.get(key);
      if (existing) {
        existing.totalActivity += m.activityCount;
        existing.endpoints.push(m);
      } else {
        map.set(key, {
          key,
          latitude: m.latitude,
          longitude: m.longitude,
          countryName: m.countryName,
          city: m.city,
          totalActivity: m.activityCount,
          endpoints: [m],
        });
      }
    }
    return Array.from(map.values());
  }, [markers]);

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
      <div className="xl:col-span-8 bg-[#0D1526] border border-slate-800/80 rounded-xl p-4 flex flex-col">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
          <div>
            <h3 className="font-display text-sm font-semibold text-white">{t('mapTitle')}</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              {t('mapDisclaimer')}
            </p>
          </div>
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setZoom((z) => Math.max(1, Number((z - 0.3).toFixed(2))))}
              className="px-2.5 py-1 text-xs bg-[#070B14] border border-slate-800 rounded-md text-slate-300 hover:text-white whitespace-nowrap shrink-0"
            >
              {t('mapZoomOut')}
            </button>
            <button
              type="button"
              onClick={() => setZoom((z) => Math.min(2.5, Number((z + 0.3).toFixed(2))))}
              className="px-2.5 py-1 text-xs bg-[#070B14] border border-slate-800 rounded-md text-slate-300 hover:text-white whitespace-nowrap shrink-0"
            >
              {t('mapZoomIn')}
            </button>
            {zoom !== 1 && (
              <button
                type="button"
                onClick={() => setZoom(1)}
                className="px-2.5 py-1 text-xs bg-[#070B14] border border-slate-800 rounded-md text-slate-300 hover:text-white whitespace-nowrap shrink-0"
              >
                {t('mapReset')}
              </button>
            )}
          </div>
        </div>

        <div className="relative bg-[#070B14] border border-slate-800/80 rounded-lg overflow-hidden" dir="ltr">
          <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-auto block" role="img" aria-label={t('mapTitle')}>
            <rect width={width} height={height} fill="#070B14" />
            <g>
              {countries.map((c, i) => (
                <path
                  key={c.id || i}
                  d={pathGen(c) || ''}
                  fill="#131E36"
                  stroke="#1E293B"
                  strokeWidth={0.6}
                />
              ))}
            </g>
            <g>
              {clusters.map((cluster) => {
                const coords = projection([cluster.longitude, cluster.latitude]);
                if (!coords) return null;
                const [cx, cy] = coords;
                const isSelected = selectedCluster?.key === cluster.key;
                const radius = cluster.endpoints.length > 1 ? Math.min(13, 6 + cluster.endpoints.length) : 5.5;
                return (
                  <g
                    key={cluster.key}
                    onClick={() => setSelectedCluster(cluster)}
                    className="cursor-pointer"
                    role="button"
                    tabIndex={0}
                    aria-label={`Inspect ${cluster.city || cluster.countryName || 'endpoint'} (${cluster.endpoints.length} endpoints)`}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') setSelectedCluster(cluster);
                    }}
                  >
                    <circle
                      cx={cx}
                      cy={cy}
                      r={radius + 4}
                      fill={isSelected ? 'rgba(59, 130, 246, 0.25)' : 'rgba(34, 197, 94, 0.18)'}
                    />
                    <circle
                      cx={cx}
                      cy={cy}
                      r={radius}
                      fill="#22C55E"
                      stroke={isSelected ? '#3B82F6' : '#070B14'}
                      strokeWidth={isSelected ? 2 : 1.5}
                    />
                    {cluster.endpoints.length > 1 && (
                      <text
                        x={cx}
                        y={cy + 3}
                        textAnchor="middle"
                        className="fill-[#070B14] text-[9px] font-mono font-semibold pointer-events-none"
                      >
                        {cluster.endpoints.length}
                      </text>
                    )}
                  </g>
                );
              })}
            </g>
          </svg>

          {clusters.length === 0 && (
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none px-4">
              <div className="px-4 py-2.5 rounded-lg bg-[#0D1526]/95 border border-slate-800 text-xs text-slate-300 text-center">
                {t('mapEmptyOverlay')}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="xl:col-span-4 bg-[#0D1526] border border-slate-800/80 rounded-xl p-4 flex flex-col">
        <h3 className="font-display text-sm font-semibold text-white mb-1">{t('mapInspectorTitle')}</h3>
        <p className="text-xs text-slate-400 mb-4">
          {t('mapInspectorDesc')}
        </p>

        {!selectedCluster ? (
          <div className="flex-1 flex items-center justify-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg p-6 text-center">
            {clusters.length > 0
              ? t('mapClustersReady', { count: clusters.length })
              : t('mapWaiting')}
          </div>
        ) : (
          <div className="space-y-3 overflow-y-auto max-h-[380px] pe-1">
            <div className="pb-2 border-b border-slate-800/80 flex items-center justify-between text-xs">
              <span className="font-medium text-emerald-400">
                {[selectedCluster.city, selectedCluster.countryName].filter(Boolean).join(', ') || t('mapPublicInfra')}
              </span>
              <span className="font-mono tabular-nums text-slate-400">
                {t('mapHitsSuffix', { ips: selectedCluster.endpoints.length, hits: selectedCluster.totalActivity })}
              </span>
            </div>

            {selectedCluster.endpoints.map((ep) => (
              <div key={ep.ip} className="p-3 rounded-lg bg-[#070B14] border border-slate-800/80 space-y-1.5 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-mono font-semibold text-white" dir="ltr">{stripCidr(ep.ip)}</span>
                  <span className="font-mono tabular-nums text-emerald-400">{t('mapEventsSuffix', { count: ep.activityCount })}</span>
                </div>
                <div className="text-slate-400 space-y-0.5">
                  <div>ASN: <span className="text-slate-200 font-mono" dir="ltr">{ep.asn || t('commonUnknown')}</span></div>
                  <div>ISP: <span className="text-slate-200">{ep.isp || t('commonUnknown')}</span></div>
                  <div>{t('adminColResource')}: <span className="text-slate-200">{ep.orgName || t('commonUnknown')}</span></div>
                  <div>{t('stunLastObservedCol')}: <span className="text-slate-300 font-mono tabular-nums" dir="ltr">{formatTimestamp(ep.lastObservedAt)}</span></div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

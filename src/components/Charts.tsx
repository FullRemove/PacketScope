import React from 'react';
import { useI18n } from '../i18n/I18nContext';

interface TimelinePoint {
  bucket: string;
  packets: number;
  bytes: number;
}

export function TrafficVolumeChart({ data }: { data: TimelinePoint[] }) {
  const { t } = useI18n();

  if (!data || data.length === 0) {
    return (
      <div className="h-52 flex items-center justify-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg px-4 text-center">
        {t('chartNoVolume')}
      </div>
    );
  }

  const maxPackets = Math.max(1, ...data.map((d) => d.packets));
  const width = 640;
  const height = 200;
  const padLeft = 44;
  const padRight = 14;
  const padTop = 16;
  const padBottom = 28;
  const innerW = width - padLeft - padRight;
  const innerH = height - padTop - padBottom;

  const points = data.map((d, idx) => {
    const x = padLeft + (data.length === 1 ? innerW / 2 : (idx / (data.length - 1)) * innerW);
    const y = padTop + innerH - (d.packets / maxPackets) * innerH;
    return { x, y, ...d };
  });

  const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ');
  const areaPath = `${linePath} L ${points[points.length - 1].x.toFixed(1)} ${(padTop + innerH).toFixed(1)} L ${points[0].x.toFixed(1)} ${(padTop + innerH).toFixed(1)} Z`;

  return (
    <div className="w-full overflow-hidden" dir="ltr">
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-52" role="img" aria-label={t('chartTrafficVolume')}>
        <defs>
          <linearGradient id="psAreaGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.32" />
            <stop offset="100%" stopColor="#3B82F6" stopOpacity="0.01" />
          </linearGradient>
        </defs>
        {[0, 0.5, 1].map((frac) => {
          const y = padTop + innerH * (1 - frac);
          const val = Math.round(maxPackets * frac);
          return (
            <g key={frac}>
              <line x1={padLeft} y1={y} x2={width - padRight} y2={y} stroke="#1E293B" strokeDasharray="3 3" />
              <text x={padLeft - 6} y={y + 3} textAnchor="end" className="fill-slate-500 text-[10px] font-mono tabular-nums">
                {val}
              </text>
            </g>
          );
        })}
        <path d={areaPath} fill="url(#psAreaGrad)" />
        <path d={linePath} fill="none" stroke="#3B82F6" strokeWidth="2" strokeLinejoin="round" />
        {points.map((p) => (
          <g key={p.bucket}>
            <circle cx={p.x} cy={p.y} r="3.5" fill="#22C55E" stroke="#070B14" strokeWidth="1.5">
              <title>{`${p.bucket.slice(11, 16)} UTC · ${p.packets} ${t('commonPacketsUnit')}`}</title>
            </circle>
          </g>
        ))}
        {points
          .filter((_, idx) => idx === 0 || idx === points.length - 1 || idx === Math.floor(points.length / 2))
          .map((p) => (
            <text
              key={`lbl-${p.bucket}`}
              x={p.x}
              y={height - 8}
              textAnchor="middle"
              className="fill-slate-500 text-[10px] font-mono tabular-nums"
            >
              {p.bucket.slice(11, 16)}
            </text>
          ))}
      </svg>
    </div>
  );
}

export function HorizontalDistributionList({
  items,
  accent = 'blue',
  emptyText,
}: {
  items: Array<{ name: string; count: number; secondary?: string }>;
  accent?: 'blue' | 'green';
  emptyText?: string;
}) {
  const { t } = useI18n();

  if (!items || items.length === 0) {
    return (
      <div className="py-10 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
        {emptyText || t('commonNoData')}
      </div>
    );
  }

  const total = Math.max(1, items.reduce((sum, i) => sum + i.count, 0));
  const maxVal = Math.max(1, ...items.map((i) => i.count));
  const barColor = accent === 'green' ? 'bg-emerald-500/80' : 'bg-blue-500/85';

  return (
    <div className="space-y-2.5">
      {items.map((item) => {
        const pct = ((item.count / total) * 100).toFixed(1);
        const widthPct = Math.max(3, (item.count / maxVal) * 100);
        return (
          <div key={item.name} className="space-y-1">
            <div className="flex items-center justify-between text-xs gap-2">
              <span className="text-slate-200 font-medium truncate max-w-[60%]" dir="ltr">
                {item.name}
                {item.secondary && <span className="text-slate-500 font-normal ms-1.5">· {item.secondary}</span>}
              </span>
              <span className="font-mono tabular-nums text-slate-400 shrink-0" dir="ltr">
                {item.count.toLocaleString()} <span className="text-slate-500">({pct}%)</span>
              </span>
            </div>
            <div className="h-1.5 w-full bg-[#070B14] rounded-full overflow-hidden">
              <div className={`h-full rounded-full ${barColor}`} style={{ width: `${widthPct}%` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

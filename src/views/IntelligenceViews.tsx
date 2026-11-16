import React, { useCallback, useEffect, useState } from 'react';
import { apiClient, formatBytes, formatTimestamp, stripCidr } from '../lib/api';
import type { SensorRecord, StunTurnEventRecord } from '../types/packetscope';
import { useI18n } from '../i18n/I18nContext';

export function ApplicationIntelligenceView({ refreshSignal }: { refreshSignal: number }) {
  const { t } = useI18n();
  const [summary, setSummary] = useState<any[]>([]);
  const [detections, setDetections] = useState<any[]>([]);

  useEffect(() => {
    void apiClient.request('/api/applications').then((res) => {
      setSummary(res.summary || []);
      setDetections(res.detections || []);
    });
  }, [refreshSignal]);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-xl font-semibold text-white tracking-tight">{t('appsTitle')}</h2>
        <p className="text-xs text-slate-400 mt-1">
          {t('appsSubtitle')}
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
        <div className="p-4 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <p className="font-medium text-emerald-400">{t('confHighTitle')}</p>
          <p className="text-slate-400 mt-1">{t('confHighDesc')}</p>
        </div>
        <div className="p-4 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <p className="font-medium text-blue-400">{t('confMediumTitle')}</p>
          <p className="text-slate-400 mt-1">{t('confMediumDesc')}</p>
        </div>
        <div className="p-4 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <p className="font-medium text-amber-400">{t('confLowTitle')}</p>
          <p className="text-slate-400 mt-1">{t('confLowDesc')}</p>
        </div>
        <div className="p-4 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <p className="font-medium text-slate-300">{t('confUnclassTitle')}</p>
          <p className="text-slate-400 mt-1">{t('confUnclassDesc')}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <div className="xl:col-span-5 p-5 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <h3 className="font-display text-sm font-semibold text-white mb-4">{t('appsBreakdownTitle')}</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-start text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2 pe-3 font-medium text-start">{t('colApplication')}</th>
                  <th className="py-2 px-3 font-medium text-start">{t('colConfidence')}</th>
                  <th className="py-2 px-3 font-medium text-start">{t('appsModeCol')}</th>
                  <th className="py-2 ps-3 font-medium text-end">{t('trafficPacketsCol')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {summary.length === 0 ? (
                  <tr><td colSpan={4} className="py-8 text-center text-slate-500">{t('appsNoTelemetry')}</td></tr>
                ) : (
                  summary.map((row, idx) => (
                    <tr key={`${row.appName}-${row.confidence}-${idx}`}>
                      <td className="py-2 pe-3 text-slate-200 font-medium">{row.appName}</td>
                      <td className="py-2 px-3 font-mono text-slate-300" dir="ltr">{row.confidence}</td>
                      <td className="py-2 px-3 text-slate-400">{row.classificationMode}</td>
                      <td className="py-2 ps-3 font-mono tabular-nums text-end text-slate-300" dir="ltr">
                        {row.packetCount} ({formatBytes(row.byteCount)})
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="xl:col-span-7 p-5 rounded-xl bg-[#0D1526] border border-slate-800/80">
          <h3 className="font-display text-sm font-semibold text-white mb-4">{t('appsEvidenceLogTitle')}</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-start text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2 pe-3 font-medium text-start">{t('colTimestamp')}</th>
                  <th className="py-2 px-3 font-medium text-start">{t('colApplication')}</th>
                  <th className="py-2 px-3 font-medium text-start">{t('appsEvidenceSourceCol')}</th>
                  <th className="py-2 px-3 font-medium text-start">{t('colSensor')}</th>
                  <th className="py-2 ps-3 font-medium text-start">{t('appsModeConfidenceCol')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {detections.length === 0 ? (
                  <tr><td colSpan={5} className="py-8 text-center text-slate-500">{t('appsNoRecords')}</td></tr>
                ) : (
                  detections.map((d) => (
                    <tr key={d.id}>
                      <td className="py-2 pe-3 font-mono tabular-nums text-slate-400 whitespace-nowrap" dir="ltr">{formatTimestamp(d.observedAt)}</td>
                      <td className="py-2 px-3 text-slate-200 font-medium whitespace-nowrap">{d.appName}</td>
                      <td className="py-2 px-3 text-slate-300 max-w-[260px] truncate" dir="ltr">{d.evidenceSource}</td>
                      <td className="py-2 px-3 text-slate-400 whitespace-nowrap">{d.sensorName}</td>
                      <td className="py-2 ps-3 font-mono text-slate-300 whitespace-nowrap" dir="ltr">
                        {d.classificationMode} · {d.confidence}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

export function ProtocolAnalysisView({ refreshSignal }: { refreshSignal: number }) {
  const { t } = useI18n();
  const [summary, setSummary] = useState<any[]>([]);
  const [recent, setRecent] = useState<any[]>([]);

  useEffect(() => {
    void apiClient.request('/api/protocols').then((res) => {
      setSummary(res.summary || []);
      setRecent(res.recent || []);
    });
  }, [refreshSignal]);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-xl font-semibold text-white tracking-tight">{t('protoTitle')}</h2>
        <p className="text-xs text-slate-400 mt-1">
          {t('protoSubtitle')}
        </p>
      </div>

      <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 overflow-x-auto">
        <h3 className="font-display text-sm font-semibold text-white mb-3">{t('protoSummaryTitle')}</h3>
        <table className="w-full text-start text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2.5 pe-4 font-medium text-start">{t('colProtocol')}</th>
              <th className="py-2.5 px-4 font-medium text-end">{t('protoTotalObsCol')}</th>
              <th className="py-2.5 px-4 font-medium text-end">{t('protoConfirmedCol')}</th>
              <th className="py-2.5 px-4 font-medium text-end">{t('protoHeuristicCol')}</th>
              <th className="py-2.5 ps-4 font-medium text-start">{t('trafficLastSeen')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {summary.length === 0 ? (
              <tr><td colSpan={5} className="py-8 text-center text-slate-500">{t('protoNoDetections')}</td></tr>
            ) : (
              summary.map((s) => (
                <tr key={s.protocol}>
                  <td className="py-2.5 pe-4 font-mono font-semibold text-blue-400" dir="ltr">{s.protocol}</td>
                  <td className="py-2.5 px-4 font-mono tabular-nums text-end text-slate-200" dir="ltr">{s.totalObservations}</td>
                  <td className="py-2.5 px-4 font-mono tabular-nums text-end text-emerald-400" dir="ltr">{s.confirmedCount}</td>
                  <td className="py-2.5 px-4 font-mono tabular-nums text-end text-slate-400" dir="ltr">{s.heuristicCount}</td>
                  <td className="py-2.5 ps-4 font-mono tabular-nums text-slate-400" dir="ltr">{formatTimestamp(s.lastSeenAt)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 overflow-x-auto">
        <h3 className="font-display text-sm font-semibold text-white mb-3">{t('protoRecentTitle')}</h3>
        <table className="w-full text-start text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2 pe-3 font-medium text-start">{t('colTimestamp')}</th>
              <th className="py-2 px-3 font-medium text-start">{t('colProtocol')}</th>
              <th className="py-2 px-3 font-medium text-start">{t('protoEndpointsCol')}</th>
              <th className="py-2 px-3 font-medium text-start">{t('protoVerificationCol')}</th>
              <th className="py-2 ps-3 font-medium text-start">{t('protoEvidenceCol')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {recent.length === 0 ? (
              <tr><td colSpan={5} className="py-8 text-center text-slate-500">{t('protoWaiting')}</td></tr>
            ) : (
              recent.slice(0, 40).map((r) => (
                <tr key={r.id}>
                  <td className="py-2 pe-3 font-mono tabular-nums text-slate-400 whitespace-nowrap" dir="ltr">{formatTimestamp(r.observedAt)}</td>
                  <td className="py-2 px-3 font-mono text-blue-400" dir="ltr">{r.protocol}</td>
                  <td className="py-2 px-3 font-mono tabular-nums text-slate-300 whitespace-nowrap" dir="ltr">
                    {stripCidr(r.srcIp)}:{r.srcPort ?? 0} → {stripCidr(r.dstIp)}:{r.dstPort ?? 0}
                  </td>
                  <td className="py-2 px-3 whitespace-nowrap">
                    <span className={r.dissectorConfirmed ? 'text-emerald-400 font-mono' : 'text-amber-400 font-mono'}>
                      {r.dissectorConfirmed ? t('protoStatusConfirmed') : t('protoStatusHeuristic')}
                    </span>
                  </td>
                  <td className="py-2 ps-3 text-slate-300">{r.evidence}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function StunTurnView({ refreshSignal }: { refreshSignal: number }) {
  const { t, lang } = useI18n();
  const [counters, setCounters] = useState<any>({});
  const [events, setEvents] = useState<StunTurnEventRecord[]>([]);
  const [udpFlows, setUdpFlows] = useState<any[]>([]);
  const [sensors, setSensors] = useState<SensorRecord[]>([]);
  const [privacyNotice, setPrivacyNotice] = useState('');

  const [sensorId, setSensorId] = useState('');
  const [category, setCategory] = useState('');
  const [confidence, setConfidence] = useState('');
  const [messageType, setMessageType] = useState('');
  const [srcIp, setSrcIp] = useState('');
  const [dstIp, setDstIp] = useState('');

  const loadData = useCallback(async () => {
    const params = new URLSearchParams();
    if (sensorId) params.set('sensorId', sensorId);
    if (category) params.set('category', category);
    if (confidence) params.set('confidence', confidence);
    if (messageType.trim()) params.set('messageType', messageType.trim());
    if (srcIp.trim()) params.set('srcIp', srcIp.trim());
    if (dstIp.trim()) params.set('dstIp', dstIp.trim());

    const [stunRes, sensorRes] = await Promise.all([
      apiClient.request(`/api/stun-turn?${params.toString()}`),
      apiClient.request('/api/sensors'),
    ]);
    setCounters(stunRes.counters || {});
    setEvents(stunRes.events || []);
    setUdpFlows(stunRes.udpFlows || []);
    setPrivacyNotice(stunRes.privacyNotice || '');
    setSensors(sensorRes.items || []);
  }, [sensorId, category, confidence, messageType, srcIp, dstIp]);

  useEffect(() => {
    void loadData();
  }, [loadData, refreshSignal]);

  const categoryLabel = (cat: string) => {
    switch (cat) {
      case 'confirmed_stun':
        return t('stunConfirmedStun');
      case 'confirmed_turn':
        return t('stunConfirmedTurn');
      case 'suspected_webrtc':
        return t('stunSuspectedWebrtc');
      case 'unclassified_udp':
        return t('stunUnclassifiedUdp');
      default:
        return cat;
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-xl font-semibold text-white tracking-tight">{t('stunTitle')}</h2>
        <p className="text-xs text-slate-400 mt-1">
          {lang === 'en' && privacyNotice ? privacyNotice : t('stunSubtitleFallback')}
        </p>
      </div>

      {/* Category & Message Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        {[
          [t('stunConfirmedStun'), counters.confirmedStunPackets ?? 0, 'text-emerald-400'],
          [t('stunConfirmedTurn'), counters.confirmedTurnPackets ?? 0, 'text-blue-400'],
          [t('stunSuspectedWebrtc'), counters.suspectedWebrtcFlows ?? 0, 'text-amber-400'],
          [t('stunUnclassifiedUdp'), counters.unclassifiedUdpFlows ?? 0, 'text-slate-300'],
          [t('stunBindingReq'), counters.bindingRequests ?? 0, 'text-white'],
          [t('stunBindingResp'), counters.bindingResponses ?? 0, 'text-white'],
          [t('stunTurnAlloc'), counters.turnAllocations ?? 0, 'text-white'],
        ].map(([label, val, color]) => (
          <div key={String(label)} className="p-3.5 rounded-xl bg-[#0D1526] border border-slate-800/80">
            <p className="text-xs text-slate-400">{label}</p>
            <p className={`font-mono tabular-nums text-xl font-semibold mt-1 ${color}`} dir="ltr">{val}</p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="p-4 rounded-xl bg-[#0D1526] border border-slate-800/80 grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <select
          aria-label={t('colSensor')}
          value={sensorId}
          onChange={(e) => setSensorId(e.target.value)}
          className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200"
        >
          <option value="">{t('commonAllSensors')}</option>
          {sensors.map((s) => (
            <option key={s.id} value={s.id}>{s.name}</option>
          ))}
        </select>

        <select
          aria-label={t('stunCategoryCol')}
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200"
        >
          <option value="">{t('stunAllCategories')}</option>
          <option value="confirmed_stun">{t('stunConfirmedStun')}</option>
          <option value="confirmed_turn">{t('stunConfirmedTurn')}</option>
          <option value="suspected_webrtc">{t('stunSuspectedWebrtc')}</option>
          <option value="unclassified_udp">{t('stunUnclassifiedUdp')}</option>
        </select>

        <select
          aria-label={t('colConfidence')}
          value={confidence}
          onChange={(e) => setConfidence(e.target.value)}
          className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200"
        >
          <option value="">{t('stunAllConfidence')}</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="UNCLASSIFIED">UNCLASSIFIED</option>
        </select>

        <input
          type="text"
          aria-label={t('stunMsgTypeCol')}
          value={messageType}
          onChange={(e) => setMessageType(e.target.value)}
          placeholder={t('stunMsgPlaceholder')}
          className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500"
        />

        <input
          type="text"
          dir="ltr"
          aria-label={t('stunSrcEndpointCol')}
          value={srcIp}
          onChange={(e) => setSrcIp(e.target.value)}
          placeholder={t('stunSrcPlaceholder')}
          className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500"
        />

        <input
          type="text"
          dir="ltr"
          aria-label={t('stunDstEndpointCol')}
          value={dstIp}
          onChange={(e) => setDstIp(e.target.value)}
          placeholder={t('stunDstPlaceholder')}
          className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500"
        />
      </div>

      {/* STUN/TURN Timeline Table */}
      <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 overflow-x-auto">
        <h3 className="font-display text-sm font-semibold text-white mb-3">{t('stunTimelineTitle')}</h3>
        <table className="w-full text-start text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2.5 pe-2 font-medium text-start">{t('colTimestamp')}</th>
              <th className="py-2.5 px-2 font-medium text-start">{t('colSensor')}</th>
              <th className="py-2.5 px-2 font-medium text-start">{t('stunCategoryCol')}</th>
              <th className="py-2.5 px-2 font-medium text-start">{t('stunMsgTypeCol')}</th>
              <th className="py-2.5 px-2 font-medium text-start">{t('protoEndpointsCol')}</th>
              <th className="py-2.5 px-2 font-medium text-start">{t('stunAttributesCol')}</th>
              <th className="py-2.5 px-2 font-medium text-start">{t('protoEvidenceCol')}</th>
              <th className="py-2.5 ps-2 font-medium text-start">{t('colConfidence')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {events.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-10 text-center text-slate-500">
                  {t('stunEmpty')}
                </td>
              </tr>
            ) : (
              events.map((ev) => (
                <tr key={ev.id} className="hover:bg-slate-800/30">
                  <td className="py-2.5 pe-2 font-mono tabular-nums text-slate-400 whitespace-nowrap" dir="ltr">
                    {formatTimestamp(ev.observedAt)}
                  </td>
                  <td className="py-2.5 px-2 text-slate-300 whitespace-nowrap">{ev.sensorName}</td>
                  <td className="py-2.5 px-2 font-mono whitespace-nowrap">
                    <span
                      className={
                        ev.category === 'confirmed_stun'
                          ? 'text-emerald-400'
                          : ev.category === 'confirmed_turn'
                          ? 'text-blue-400'
                          : ev.category === 'suspected_webrtc'
                          ? 'text-amber-400'
                          : 'text-slate-400'
                      }
                    >
                      {categoryLabel(ev.category)}
                    </span>
                  </td>
                  <td className="py-2.5 px-2 text-slate-200 font-medium whitespace-nowrap">{ev.messageType}</td>
                  <td className="py-2.5 px-2 font-mono tabular-nums text-slate-200 whitespace-nowrap" dir="ltr">
                    {stripCidr(ev.srcIp)}:{ev.srcPort ?? 0} → {stripCidr(ev.dstIp)}:{ev.dstPort ?? 0}
                  </td>
                  <td className="py-2.5 px-2 font-mono text-slate-400 max-w-[150px] truncate" dir="ltr">
                    {ev.attributesMeta || '—'}
                  </td>
                  <td className="py-2.5 px-2 text-slate-300 max-w-[180px] truncate">{ev.evidence}</td>
                  <td className="py-2.5 ps-2 font-mono text-slate-300 whitespace-nowrap" dir="ltr">{ev.confidence}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* UDP Flow Summaries */}
      <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 overflow-x-auto">
        <h3 className="font-display text-sm font-semibold text-white mb-3">{t('stunUdpSummaryTitle')}</h3>
        <table className="w-full text-start text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2 pe-3 font-medium text-start">{t('colSensor')}</th>
              <th className="py-2 px-3 font-medium text-start">{t('stunSrcEndpointCol')}</th>
              <th className="py-2 px-3 font-medium text-start">{t('stunDstEndpointCol')}</th>
              <th className="py-2 px-3 font-medium text-start">{t('colProtocol')}</th>
              <th className="py-2 px-3 font-medium text-end">{t('trafficPacketsCol')}</th>
              <th className="py-2 ps-3 font-medium text-start">{t('stunLastObservedCol')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {udpFlows.length === 0 ? (
              <tr><td colSpan={6} className="py-6 text-center text-slate-500">{t('stunNoUdpFlows')}</td></tr>
            ) : (
              udpFlows.map((f, idx) => (
                <tr key={idx}>
                  <td className="py-2 pe-3 text-slate-300">{f.sensorName}</td>
                  <td className="py-2 px-3 font-mono tabular-nums text-slate-200" dir="ltr">{stripCidr(f.srcIp)}:{f.srcPort ?? 0}</td>
                  <td className="py-2 px-3 font-mono tabular-nums text-slate-200" dir="ltr">{stripCidr(f.dstIp)}:{f.dstPort ?? 0}</td>
                  <td className="py-2 px-3 font-mono text-blue-400" dir="ltr">{f.protocol}</td>
                  <td className="py-2 px-3 font-mono tabular-nums text-end text-slate-300" dir="ltr">{f.packetCount}</td>
                  <td className="py-2 ps-3 font-mono tabular-nums text-slate-400" dir="ltr">{formatTimestamp(f.lastSeenAt)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

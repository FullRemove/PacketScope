import React, { useCallback, useEffect, useState } from 'react';
import { Download, Pause, Play, Plus, RefreshCw, ShieldAlert, Trash2, Copy, Check, Upload } from 'lucide-react';
import { apiClient, formatRelativeTime, formatTimestamp, stripCidr } from '../lib/api';
import type { SensorRecord } from '../types/packetscope';
import { useI18n } from '../i18n/I18nContext';

export function SensorsView({ refreshSignal }: { refreshSignal: number }) {
  const { t } = useI18n();
  const [sensors, setSensors] = useState<SensorRecord[]>([]);
  const [networks, setNetworks] = useState<any[]>([]);
  const [name, setName] = useState('');
  const [networkId, setNetworkId] = useState('');
  const [issuedToken, setIssuedToken] = useState<{ sensorName: string; rawToken: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [renameId, setRenameId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [importSensorId, setImportSensorId] = useState('');
  const [importing, setImporting] = useState(false);
  const [importStatus, setImportStatus] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    const [sRes, invRes] = await Promise.all([
      apiClient.request('/api/sensors'),
      apiClient.request('/api/inventory'),
    ]);
    const list = sRes.items || [];
    setSensors(list);
    setNetworks(invRes.networks || []);
    setImportSensorId((prev) => prev || list.find((s: SensorRecord) => !s.revokedAt)?.id || '');
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData, refreshSignal]);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await apiClient.request('/api/sensors', {
        method: 'POST',
        body: JSON.stringify({ name: name.trim(), networkId: networkId || null }),
      });
      setIssuedToken({ sensorName: res.sensor.name, rawToken: res.rawToken });
      setName('');
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to register sensor');
    } finally {
      setLoading(false);
    }
  };

  const handleAction = async (sensor: SensorRecord, action: 'pause' | 'resume' | 'revoke') => {
    await apiClient.request(`/api/sensors/${sensor.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ action }),
    });
    await loadData();
  };

  const handleRotate = async (sensor: SensorRecord) => {
    const res = await apiClient.request(`/api/sensors/${sensor.id}/rotate-token`, { method: 'POST' });
    setIssuedToken({ sensorName: sensor.name, rawToken: res.rawToken });
    await loadData();
  };

  const handleDelete = async (sensor: SensorRecord) => {
    await apiClient.request(`/api/sensors/${sensor.id}`, { method: 'DELETE' });
    await loadData();
  };

  const handleSaveRename = async (sensorId: string) => {
    if (!renameValue.trim()) return;
    await apiClient.request(`/api/sensors/${sensorId}`, {
      method: 'PATCH',
      body: JSON.stringify({ name: renameValue.trim() }),
    });
    setRenameId(null);
    await loadData();
  };

  const copyText = async (txt: string, kind: 'token' | 'cmd' = 'token') => {
    await navigator.clipboard.writeText(txt);
    if (kind === 'cmd') {
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 1800);
    } else {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    }
  };

  const serverOrigin = typeof window !== 'undefined' ? window.location.origin : 'https://your-packetscope-host';
  const isPreviewProxy = typeof window !== 'undefined' && window.location.hostname.startsWith('ais-dev-');
  const buildOneLineCommand = (token: string) =>
    `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $f = "$env:TEMP\\Install-PacketScopeAgent.ps1"; Invoke-WebRequest -UseBasicParsing -Uri "${serverOrigin}/api/agent/download/installer" -OutFile $f; powershell -ExecutionPolicy Bypass -File $f -ServerUrl "${serverOrigin}" -SensorToken "${token}" -StartNow`;

  const handleDownload = async (path: string, filename: string) => {
    setError(null);
    try {
      await apiClient.downloadBlob(path, filename);
    } catch (err: any) {
      setError(err.message || `Failed to download ${filename}`);
    }
  };

  const handleImportQueue = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    if (!importSensorId) {
      setError(t('sensorsQueueSelectSensor'));
      return;
    }

    setError(null);
    setImportStatus(null);
    setImporting(true);
    try {
      const text = (await file.text()).replace(/^\uFEFF/, '');
      const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      const events: any[] = [];
      for (const line of lines) {
        const clean = line.replace(/^\uFEFF/, '');
        try {
          const obj = JSON.parse(clean);
          if (obj && obj.srcIp && obj.dstIp && obj.observedAt) {
            events.push(obj);
          }
        } catch {
          // skip malformed line
        }
      }
      if (events.length === 0) {
        throw new Error('No valid packet metadata records found in selected queue.jsonl file.');
      }

      let totalAccepted = 0;
      let totalDuplicates = 0;
      let totalRejected = 0;
      for (let i = 0; i < events.length; i += 500) {
        const chunk = events.slice(i, i + 500);
        const res = await apiClient.request(`/api/sensors/${importSensorId}/import-queue`, {
          method: 'POST',
          body: JSON.stringify({ events: chunk }),
        });
        totalAccepted += res.accepted || 0;
        totalDuplicates += res.duplicates || 0;
        totalRejected += res.rejected || 0;
      }

      setImportStatus(
        `${file.name}: ${totalAccepted.toLocaleString()} / ${totalDuplicates.toLocaleString()} / ${totalRejected.toLocaleString()}`
      );
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to import agent queue file');
    } finally {
      setImporting(false);
    }
  };

  const sensorStatusText = (s: SensorRecord) => {
    if (s.revokedAt) return t('statusRevoked');
    switch (s.status) {
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

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="font-display text-xl font-semibold text-white tracking-tight">{t('sensorsTitle')}</h2>
          <p className="text-xs text-slate-400 mt-1">
            {t('sensorsSubtitle')}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void handleDownload('/api/agent/download/script', 'PacketScope-Agent.ps1')}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg bg-[#0D1526] hover:bg-slate-800 border border-slate-800 text-slate-200 whitespace-nowrap shrink-0"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{t('sensorsDownloadAgent')}</span>
            <span dir="ltr" className="font-mono text-[11px] opacity-75">(.ps1)</span>
          </button>
          <button
            type="button"
            onClick={() => void handleDownload('/api/agent/download/installer', 'Install-PacketScopeAgent.ps1')}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white whitespace-nowrap shrink-0"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{t('sensorsDownloadInstaller')}</span>
          </button>
        </div>
      </div>

      {isPreviewProxy && (
        <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-500/40 text-xs text-amber-100 space-y-1.5">
          <p className="font-semibold text-amber-300">
            {t('sensorsPreviewNoticeTitle')}
          </p>
          <p className="text-amber-100/90 leading-relaxed">
            {t('sensorsPreviewNoticeBody')}
          </p>
        </div>
      )}

      {/* Register Sensor Form */}
      <form onSubmit={handleRegister} className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 space-y-3">
        <h3 className="font-display text-sm font-semibold text-white">{t('sensorsRegTitle')}</h3>
        {error && <p className="text-xs text-red-400">{error}</p>}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
          <div className="md:col-span-5">
            <label htmlFor="sensor-name-input" className="block text-xs text-slate-400 mb-1">{t('sensorsNameLabel')}</label>
            <input
              id="sensor-name-input"
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('sensorsNamePlaceholder')}
              className="w-full px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div className="md:col-span-4">
            <label htmlFor="sensor-network-select" className="block text-xs text-slate-400 mb-1">{t('sensorsNetworkLabel')}</label>
            <select
              id="sensor-network-select"
              value={networkId}
              onChange={(e) => setNetworkId(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="">{t('sensorsDefaultNetwork')}</option>
              {networks.map((n) => (
                <option key={n.id} value={n.id}>{n.name} ({n.deploymentMode})</option>
              ))}
            </select>
          </div>
          <div className="md:col-span-3 flex items-end">
            <button
              type="submit"
              disabled={loading}
              className="w-full inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white whitespace-nowrap shrink-0"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>{loading ? t('sensorsRegisteringBtn') : t('sensorsRegisterBtn')}</span>
            </button>
          </div>
        </div>
      </form>

      {/* One-time Token Issuance Panel */}
      {issuedToken && (
        <div className="p-5 rounded-xl bg-[#0A1628] border border-blue-500/40 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h3 className="font-display text-sm font-semibold text-white">
                {t('sensorsTokenIssuedTitle', { name: issuedToken.sensorName })}
              </h3>
              <p className="text-xs text-slate-300 mt-0.5">
                {t('sensorsTokenIssuedDesc')}
              </p>
            </div>
            <button
              type="button"
              onClick={() => setIssuedToken(null)}
              className="text-xs text-slate-400 hover:text-white"
            >
              {t('commonDismiss')}
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-2 p-3 rounded-lg bg-[#070B14] border border-slate-800">
            <code className="font-mono text-xs text-emerald-400 break-all flex-1" dir="ltr">{issuedToken.rawToken}</code>
            <button
              type="button"
              onClick={() => void copyText(issuedToken.rawToken)}
              className="inline-flex items-center gap-1 px-3 py-1.5 text-xs rounded-md bg-slate-800 hover:bg-slate-700 text-white whitespace-nowrap shrink-0"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? t('sensorsCopied') : t('sensorsCopyToken')}</span>
            </button>
          </div>

          <div className="text-xs text-slate-300 space-y-2">
            {isPreviewProxy ? (
              <>
                <p className="font-medium text-slate-200">
                  {t('sensorsPreviewCmdLabel')}
                </p>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[11px] text-slate-400">{t('sensorsPreviewCmdHint')}</span>
                  <button
                    type="button"
                    onClick={() =>
                      void copyText(
                        `powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\\Downloads\\Install-PacketScopeAgent.ps1" -ServerUrl "https://YOUR-DEPLOYED-PACKETSCOPE-URL" -SensorToken "${issuedToken.rawToken}" -StartNow`,
                        'cmd'
                      )
                    }
                    className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] rounded-md bg-slate-800 hover:bg-slate-700 text-white whitespace-nowrap shrink-0"
                  >
                    {copiedCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedCmd ? t('sensorsCopiedCmd') : t('sensorsCopyCmd')}</span>
                  </button>
                </div>
                <pre dir="ltr" className="p-3 rounded-lg bg-[#070B14] border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto select-all text-left">
                  {`powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\\Downloads\\Install-PacketScopeAgent.ps1" -ServerUrl "https://YOUR-DEPLOYED-PACKETSCOPE-URL" -SensorToken "${issuedToken.rawToken}" -StartNow`}
                </pre>
              </>
            ) : (
              <>
                <div className="flex items-center justify-between gap-2">
                  <p className="font-medium text-slate-200">{t('sensorsDirectCmdLabel')}</p>
                  <button
                    type="button"
                    onClick={() => void copyText(buildOneLineCommand(issuedToken.rawToken), 'cmd')}
                    className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] rounded-md bg-slate-800 hover:bg-slate-700 text-white whitespace-nowrap shrink-0"
                  >
                    {copiedCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedCmd ? t('sensorsCopiedCmd') : t('sensorsCopyCmd')}</span>
                  </button>
                </div>
                <pre dir="ltr" className="p-3 rounded-lg bg-[#070B14] border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto select-all text-left">
                  {buildOneLineCommand(issuedToken.rawToken)}
                </pre>
                <p className="text-[11px] text-slate-400">
                  {t('sensorsDirectCmdOr')}{' '}
                  <code className="font-mono text-slate-300" dir="ltr">
                    {`powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\\Downloads\\Install-PacketScopeAgent.ps1" -ServerUrl "${serverOrigin}" -SensorToken "${issuedToken.rawToken}" -StartNow`}
                  </code>
                </p>
              </>
            )}
          </div>
        </div>
      )}

      {/* Registered Sensors Table */}
      <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 overflow-x-auto">
        <h3 className="font-display text-sm font-semibold text-white mb-3">
          {t('sensorsTableTitle', { count: sensors.length })}
        </h3>
        <table className="w-full text-start text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2.5 pe-3 font-medium text-start">{t('sensorsColSensor')}</th>
              <th className="py-2.5 px-3 font-medium text-start">{t('sensorsColStatus')}</th>
              <th className="py-2.5 px-3 font-medium text-start">{t('sensorsColIfcHost')}</th>
              <th className="py-2.5 px-3 font-medium text-start">{t('sensorsColTokenPrefix')}</th>
              <th className="py-2.5 px-3 font-medium text-end">{t('sensorsColObservedAccepted')}</th>
              <th className="py-2.5 px-3 font-medium text-start">{t('sensorsColLastHeartbeat')}</th>
              <th className="py-2.5 px-3 font-medium text-start">{t('sensorsColLastError')}</th>
              <th className="py-2.5 ps-3 font-medium text-end">{t('sensorsColActions')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {sensors.length === 0 ? (
              <tr><td colSpan={8} className="py-8 text-center text-slate-500">{t('sensorsNoneTable')}</td></tr>
            ) : (
              sensors.map((s) => (
                <tr key={s.id} className="hover:bg-slate-800/30">
                  <td className="py-2.5 pe-3">
                    {renameId === s.id ? (
                      <div className="flex items-center gap-1.5">
                        <input
                          type="text"
                          value={renameValue}
                          onChange={(e) => setRenameValue(e.target.value)}
                          className="px-2 py-1 text-xs bg-[#070B14] border border-slate-700 rounded text-white"
                        />
                        <button type="button" onClick={() => void handleSaveRename(s.id)} className="text-emerald-400">{t('commonSave')}</button>
                        <button type="button" onClick={() => setRenameId(null)} className="text-slate-400">{t('commonCancel')}</button>
                      </div>
                    ) : (
                      <div>
                        <button
                          type="button"
                          onClick={() => {
                            setRenameId(s.id);
                            setRenameValue(s.name);
                          }}
                          className="font-medium text-white hover:text-blue-400 text-start"
                        >
                          {s.name}
                        </button>
                        <p className="text-[11px] text-slate-500">{s.networkName || t('sensorsDefaultNetwork')}</p>
                      </div>
                    )}
                  </td>
                  <td className="py-2.5 px-3 font-mono whitespace-nowrap">
                    <span
                      className={
                        s.revokedAt
                          ? 'text-red-400'
                          : s.status === 'online'
                          ? 'text-emerald-400'
                          : s.status === 'error'
                          ? 'text-red-400'
                          : s.status === 'warning'
                          ? 'text-amber-400'
                          : 'text-slate-400'
                      }
                    >
                      {sensorStatusText(s)}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">
                    <div className="truncate max-w-[180px]">{s.activeInterface || t('sensorsNotReporting')}</div>
                    <div className="text-[11px] text-slate-500 font-mono" dir="ltr">{s.hostname || '—'}</div>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-400" dir="ltr">{s.tokenPrefix}...</td>
                  <td className="py-2.5 px-3 font-mono tabular-nums text-end text-slate-200" dir="ltr">
                    {s.packetsObserved.toLocaleString()} / {s.recordsAccepted.toLocaleString()}
                  </td>
                  <td className="py-2.5 px-3 font-mono tabular-nums text-slate-400 whitespace-nowrap" dir="ltr">
                    {s.lastHeartbeatAt ? formatRelativeTime(s.lastHeartbeatAt) : t('commonNever')}
                  </td>
                  <td className="py-2.5 px-3 text-red-400 max-w-[180px] truncate">{s.lastError || '—'}</td>
                  <td className="py-2.5 ps-3 text-end">
                    <div className="inline-flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => void handleAction(s, s.status === 'paused' ? 'resume' : 'pause')}
                        aria-label={`${s.status === 'paused' ? t('sensorsActionResume') : t('sensorsActionPause')} ${s.name}`}
                        title={s.status === 'paused' ? t('sensorsActionResume') : t('sensorsActionPause')}
                        className="p-1.5 rounded bg-[#070B14] border border-slate-800 text-slate-300 hover:text-white"
                      >
                        {s.status === 'paused' ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleRotate(s)}
                        aria-label={`${t('sensorsActionRotate')} ${s.name}`}
                        title={t('sensorsActionRotate')}
                        className="p-1.5 rounded bg-[#070B14] border border-slate-800 text-slate-300 hover:text-blue-400"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleAction(s, 'revoke')}
                        aria-label={`${t('sensorsActionRevoke')} ${s.name}`}
                        title={t('sensorsActionRevoke')}
                        className="p-1.5 rounded bg-[#070B14] border border-slate-800 text-slate-300 hover:text-amber-400"
                      >
                        <ShieldAlert className="w-3.5 h-3.5" />
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleDelete(s)}
                        aria-label={`${t('sensorsActionDelete')} ${s.name}`}
                        title={t('sensorsActionDelete')}
                        className="p-1.5 rounded bg-[#070B14] border border-slate-800 text-slate-300 hover:text-red-400"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Offline Queue File Import (supports C:\ProgramData\PacketScope\queue.jsonl) */}
      <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="font-display text-sm font-semibold text-white">{t('sensorsQueueTitle')}</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              {t('sensorsQueueDesc')}
            </p>
            <p className="text-[11px] text-slate-500 mt-1">
              {t('sensorsQueueHiddenNote')}
            </p>
            <div
              dir="ltr"
              className="mt-1.5 px-2.5 py-1.5 rounded-md bg-[#070B14] border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto select-all"
            >
              Copy-Item &quot;$env:ProgramData\PacketScope\queue.jsonl&quot; &quot;$env:USERPROFILE\Desktop\queue.jsonl&quot;
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label={t('sensorsQueueSelectSensor')}
              value={importSensorId}
              onChange={(e) => setImportSensorId(e.target.value)}
              className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="">{t('sensorsQueueSelectSensor')}</option>
              {sensors
                .filter((s) => !s.revokedAt && s.status !== 'paused')
                .map((s) => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
            </select>
            <label
              className={`inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                importing || !importSensorId
                  ? 'bg-slate-800 border-slate-700 text-slate-400 cursor-not-allowed'
                  : 'bg-emerald-600 hover:bg-emerald-500 border-emerald-500 text-white'
              }`}
            >
              <Upload className="w-3.5 h-3.5" />
              <span>{importing ? t('sensorsQueueImporting') : t('sensorsQueueBtn')}</span>
              <input
                type="file"
                accept=".jsonl,.json,.txt"
                disabled={importing || !importSensorId}
                onChange={(e) => void handleImportQueue(e)}
                className="hidden"
              />
            </label>
          </div>
        </div>
        {importStatus && <p className="text-xs text-emerald-400 font-mono" dir="ltr">{importStatus}</p>}
      </div>

      {/* Deployment & Visibility Architecture Guide */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 text-xs">
        <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 space-y-2.5">
          <h3 className="font-display text-sm font-semibold text-white">{t('sensorsReqTitle')}</h3>
          <ol className="list-decimal list-inside space-y-1.5 text-slate-300">
            <li>{t('sensorsReq1')}</li>
            <li>{t('sensorsReq2')}</li>
            <li>{t('sensorsReq3')}</li>
            <li>{t('sensorsReq4')}</li>
          </ol>
        </div>

        <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 space-y-2.5">
          <h3 className="font-display text-sm font-semibold text-white">{t('sensorsScopeTitle')}</h3>
          <p className="text-slate-300 leading-relaxed">
            {t('sensorsScopeDesc')}
          </p>
          <ul className="list-disc list-inside space-y-1 text-slate-400">
            <li>{t('sensorsScopeSpan')}</li>
            <li>{t('sensorsScopeGw')}</li>
            <li>{t('sensorsScopeAp')}</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export function NetworkInventoryView({ refreshSignal }: { refreshSignal: number }) {
  const { t } = useI18n();
  const [networks, setNetworks] = useState<any[]>([]);
  const [interfaces, setInterfaces] = useState<any[]>([]);
  const [hosts, setHosts] = useState<any[]>([]);
  const [netName, setNetName] = useState('');
  const [netCidr, setNetCidr] = useState('');
  const [mode, setMode] = useState<'host-interface' | 'mirror-port' | 'gateway' | 'access-point'>('host-interface');

  const loadData = useCallback(async () => {
    const res = await apiClient.request('/api/inventory');
    setNetworks(res.networks || []);
    setInterfaces(res.interfaces || []);
    setHosts(res.hosts || []);
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData, refreshSignal]);

  const handleCreateNetwork = async (e: React.FormEvent) => {
    e.preventDefault();
    await apiClient.request('/api/networks', {
      method: 'POST',
      body: JSON.stringify({ name: netName.trim(), cidr: netCidr.trim() || null, deploymentMode: mode }),
    });
    setNetName('');
    setNetCidr('');
    await loadData();
  };

  const modeLabel = (m: string) => {
    switch (m) {
      case 'mirror-port':
        return t('invModeMirror');
      case 'gateway':
        return t('invModeGateway');
      case 'access-point':
        return t('invModeAp');
      default:
        return t('invModeHost');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-xl font-semibold text-white tracking-tight">{t('invTitle')}</h2>
        <p className="text-xs text-slate-400 mt-1">
          {t('invSubtitle')}
        </p>
      </div>

      <form onSubmit={handleCreateNetwork} className="p-4 rounded-xl bg-[#0D1526] border border-slate-800/80 grid grid-cols-1 md:grid-cols-4 gap-3">
        <input
          type="text"
          required
          aria-label={t('invColName')}
          value={netName}
          onChange={(e) => setNetName(e.target.value)}
          placeholder={t('invNamePlaceholder')}
          className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500"
        />
        <input
          type="text"
          dir="ltr"
          aria-label="CIDR"
          value={netCidr}
          onChange={(e) => setNetCidr(e.target.value)}
          placeholder={t('invCidrPlaceholder')}
          className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500"
        />
        <select
          aria-label={t('invColTopology')}
          value={mode}
          onChange={(e) => setMode(e.target.value as any)}
          className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200"
        >
          <option value="host-interface">{t('invModeHost')}</option>
          <option value="mirror-port">{t('invModeMirror')}</option>
          <option value="gateway">{t('invModeGateway')}</option>
          <option value="access-point">{t('invModeAp')}</option>
        </select>
        <button type="submit" className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white">
          {t('invAddBtn')}
        </button>
      </form>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 overflow-x-auto">
          <h3 className="font-display text-sm font-semibold text-white mb-3">{t('invNetworksTitle')}</h3>
          <table className="w-full text-start text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2 pe-3 font-medium text-start">{t('invColName')}</th>
                <th className="py-2 px-3 font-medium text-start">CIDR</th>
                <th className="py-2 ps-3 font-medium text-start">{t('invColTopology')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {networks.map((n) => (
                <tr key={n.id}>
                  <td className="py-2 pe-3 text-slate-200 font-medium">{n.name}</td>
                  <td className="py-2 px-3 font-mono text-slate-400" dir="ltr">{n.cidr || t('invUnscoped')}</td>
                  <td className="py-2 ps-3 font-mono text-blue-400">{modeLabel(n.deploymentMode)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 overflow-x-auto">
          <h3 className="font-display text-sm font-semibold text-white mb-3">{t('invInterfacesTitle')}</h3>
          <table className="w-full text-start text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2 pe-3 font-medium text-start">{t('colSensor')}</th>
                <th className="py-2 px-3 font-medium text-start">{t('invColInterface')}</th>
                <th className="py-2 px-3 font-medium text-start">IP</th>
                <th className="py-2 ps-3 font-medium text-start">{t('invColState')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {interfaces.length === 0 ? (
                <tr><td colSpan={4} className="py-6 text-center text-slate-500">{t('invNoInterfaces')}</td></tr>
              ) : (
                interfaces.map((ifc) => (
                  <tr key={ifc.id}>
                    <td className="py-2 pe-3 text-slate-200">{ifc.sensorName}</td>
                    <td className="py-2 px-3 text-slate-300 truncate max-w-[180px]">{ifc.interfaceName}</td>
                    <td className="py-2 px-3 font-mono text-slate-400" dir="ltr">{stripCidr(ifc.ipAddress) || '—'}</td>
                    <td className="py-2 ps-3 font-mono text-emerald-400">
                      {ifc.isActive ? t('invStateActive') : t('invStateAvailable')}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="p-5 rounded-xl bg-[#0D1526] border border-slate-800/80 overflow-x-auto">
        <h3 className="font-display text-sm font-semibold text-white mb-3">{t('invHostsTitle')}</h3>
        <table className="w-full text-start text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2 pe-3 font-medium text-start">{t('invColHostIp')}</th>
              <th className="py-2 px-3 font-medium text-end">{t('invColObservedPkts')}</th>
              <th className="py-2 px-3 font-medium text-end">{t('invColUniquePeers')}</th>
              <th className="py-2 ps-3 font-medium text-start">{t('trafficLastSeen')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {hosts.length === 0 ? (
              <tr><td colSpan={4} className="py-6 text-center text-slate-500">{t('invNoHosts')}</td></tr>
            ) : (
              hosts.map((h) => (
                <tr key={h.ip}>
                  <td className="py-2 pe-3 font-mono text-white" dir="ltr">{stripCidr(h.ip)}</td>
                  <td className="py-2 px-3 font-mono tabular-nums text-end text-slate-300" dir="ltr">{h.packetCount}</td>
                  <td className="py-2 px-3 font-mono tabular-nums text-end text-slate-300" dir="ltr">{h.peersContacted}</td>
                  <td className="py-2 ps-3 font-mono tabular-nums text-slate-400" dir="ltr">{formatTimestamp(h.lastSeenAt)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

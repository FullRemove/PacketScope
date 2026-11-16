import React, { useState } from 'react';
import { signInWithPopup } from 'firebase/auth';
import { ShieldCheck, Lock, ArrowRight } from 'lucide-react';
import { auth, googleAuthProvider } from '../lib/firebase';
import { apiClient } from '../lib/api';
import { LanguageSwitcher, useI18n } from '../i18n/I18nContext';
import type { AuthUser, OrganizationSummary } from '../types/packetscope';

interface AuthGateProps {
  onAuthenticated: (token: string, user: AuthUser, orgs: OrganizationSummary[]) => void;
}

export function AuthGate({ onAuthenticated }: AuthGateProps) {
  const { t, isRtl } = useI18n();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [organizationName, setOrganizationName] = useState('');
  const [authorizedConfirm, setAuthorizedConfirm] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!authorizedConfirm) {
      setError(t('authComplianceError'));
      return;
    }

    setLoading(true);
    try {
      const endpoint = mode === 'login' ? '/api/auth/login' : '/api/auth/register';
      const body =
        mode === 'login'
          ? { email, password }
          : { email, password, displayName, organizationName };

      const res = await apiClient.request<{
        token: string;
        user: AuthUser;
        organizations: OrganizationSummary[];
      }>(endpoint, {
        method: 'POST',
        body: JSON.stringify(body),
      });

      onAuthenticated(res.token, res.user, res.organizations);
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setError(null);
    if (!authorizedConfirm) {
      setError(t('authComplianceError'));
      return;
    }
    setLoading(true);
    try {
      const cred = await signInWithPopup(auth, googleAuthProvider);
      const idToken = await cred.user.getIdToken();
      apiClient.setCredentials(idToken, null);
      const synced = await apiClient.request<{
        user: AuthUser;
        organizations: OrganizationSummary[];
      }>('/api/auth/firebase-sync', {
        method: 'POST',
        body: JSON.stringify({ organizationName: organizationName.trim() || undefined }),
      });
      onAuthenticated(idToken, synced.user, synced.organizations);
    } catch (err: any) {
      setError(err.message || 'Google sign-in failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070B14] text-slate-100 flex items-center justify-center p-6">
      <div className="w-full max-w-4xl grid grid-cols-1 lg:grid-cols-12 border border-slate-800/80 bg-[#0D1526] rounded-xl overflow-hidden">
        <div className="lg:col-span-5 p-8 border-b lg:border-b-0 lg:border-e border-slate-800/80 flex flex-col justify-between bg-[#0A101E]">
          <div>
            <div className="flex items-center gap-2.5 mb-8">
              <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <span className="font-display text-lg font-semibold tracking-tight text-white">PacketScope</span>
            </div>

            <h1 className="font-display text-2xl font-semibold text-white tracking-tight leading-snug mb-3">
              {t('authHeroTitle')}
            </h1>
            <p className="text-sm text-slate-400 leading-relaxed mb-6">
              {t('authHeroDesc')}
            </p>

            <div className="space-y-3 text-xs text-slate-300 border-t border-slate-800/80 pt-5">
              <div>
                <p className="font-medium text-slate-200">{t('authZeroPayloadTitle')}</p>
                <p className="text-slate-400 mt-0.5">{t('authZeroPayloadDesc')}</p>
              </div>
              <div>
                <p className="font-medium text-slate-200">{t('authTenantTitle')}</p>
                <p className="text-slate-400 mt-0.5">{t('authTenantDesc')}</p>
              </div>
            </div>
          </div>

          <p className="text-xs text-slate-500 mt-8">{t('authFooterNote')}</p>
        </div>

        <div className="lg:col-span-7 p-8">
          <div className="flex items-center justify-end mb-4">
            <LanguageSwitcher compact />
          </div>
          <div className="mb-6">
            <div className="inline-flex p-1 bg-[#070B14] border border-slate-800 rounded-lg">
              <button
                type="button"
                onClick={() => {
                  setMode('login');
                  setError(null);
                }}
                className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  mode === 'login' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {t('authSignInTab')}
              </button>
              <button
                type="button"
                onClick={() => {
                  setMode('register');
                  setError(null);
                }}
                className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  mode === 'register' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {t('authRegisterTab')}
              </button>
            </div>
          </div>

          {error && (
            <div role="alert" className="mb-4 p-3 rounded-lg bg-red-950/50 border border-red-800/60 text-xs text-red-200">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === 'register' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="auth-display-name" className="block text-xs font-medium text-slate-300 mb-1.5">
                    {t('authDisplayName')}
                  </label>
                  <input
                    id="auth-display-name"
                    type="text"
                    required
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    placeholder="Alex Rivera"
                    className="w-full px-3 py-2 text-sm bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label htmlFor="auth-org-name" className="block text-xs font-medium text-slate-300 mb-1.5">
                    {t('authOrgName')}
                  </label>
                  <input
                    id="auth-org-name"
                    type="text"
                    required
                    value={organizationName}
                    onChange={(e) => setOrganizationName(e.target.value)}
                    placeholder="Northstar NetOps"
                    className="w-full px-3 py-2 text-sm bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>
            )}

            <div>
              <label htmlFor="auth-email" className="block text-xs font-medium text-slate-300 mb-1.5">
                {t('authEmail')}
              </label>
              <input
                id="auth-email"
                type="email"
                dir="ltr"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="operator@company.com"
                className="w-full px-3 py-2 text-sm bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label htmlFor="auth-password" className="block text-xs font-medium text-slate-300 mb-1.5">
                {t('authPassword')}
              </label>
              <input
                id="auth-password"
                type="password"
                dir={password || !isRtl ? 'ltr' : 'rtl'}
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={t('authPasswordPlaceholder')}
                className="w-full px-3 py-2 text-sm bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <label className="flex items-start gap-2.5 text-xs text-slate-400 cursor-pointer pt-1">
              <input
                type="checkbox"
                checked={authorizedConfirm}
                onChange={(e) => setAuthorizedConfirm(e.target.checked)}
                className="mt-0.5 rounded border-slate-700 bg-[#070B14] text-blue-600 focus:ring-blue-500"
              />
              <span>{t('authConfirmCompliance')}</span>
            </label>

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white transition-colors"
            >
              <Lock className="w-4 h-4" />
              <span>{loading ? t('authSubmitting') : mode === 'login' ? t('authSubmitLogin') : t('authSubmitRegister')}</span>
              <ArrowRight className="w-4 h-4 rtl:rotate-180" />
            </button>
          </form>

          <div className="relative my-5 flex items-center">
            <div className="flex-grow border-t border-slate-800" />
            <span className="px-3 text-xs text-slate-500">{t('authOr')}</span>
            <div className="flex-grow border-t border-slate-800" />
          </div>

          <button
            type="button"
            disabled={loading}
            onClick={handleGoogleSignIn}
            className="w-full py-2.5 px-4 text-sm font-medium rounded-lg bg-[#111C33] hover:bg-slate-800 border border-slate-700/80 text-slate-100 transition-colors"
          >
            {t('authGoogleSso')}
          </button>
        </div>
      </div>
    </div>
  );
}

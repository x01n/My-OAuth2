'use client';

import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { PageHeader } from '@/components/ui/page-header';
import { EmptyState } from '@/components/ui/empty-state';
import {
  Activity, AlertTriangle, ChevronLeft, ChevronRight, CheckCircle, ShieldAlert, XCircle, Loader2, RefreshCw,
} from 'lucide-react';
import type { LoginLog, RiskEvent } from '@/lib/types';

const PAGE_SIZE = 20;
type RiskDecisionFilter = '' | RiskEvent['decision'];

export default function AdminLoginLogsPage() {
  const { user } = useAuth();
  const router = useRouter();
  const { t, dateLocale } = useI18n();
  const [logs, setLogs] = useState<LoginLog[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [riskEvents, setRiskEvents] = useState<RiskEvent[]>([]);
  const [riskTotal, setRiskTotal] = useState(0);
  const [riskPage, setRiskPage] = useState(1);
  const [riskDecisionFilter, setRiskDecisionFilter] = useState<RiskDecisionFilter>('');
  const [riskReasonFilter, setRiskReasonFilter] = useState('');
  const [riskReasons, setRiskReasons] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [riskLoading, setRiskLoading] = useState(true);
  const [logsError, setLogsError] = useState<string | null>(null);
  const [riskError, setRiskError] = useState<string | null>(null);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const riskTotalPages = Math.max(1, Math.ceil(riskTotal / PAGE_SIZE));
  const logRangeStart = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const logRangeEnd = Math.min(page * PAGE_SIZE, total);
  const riskRangeStart = riskTotal === 0 ? 0 : (riskPage - 1) * PAGE_SIZE + 1;
  const riskRangeEnd = Math.min(riskPage * PAGE_SIZE, riskTotal);

  const loadLogs = useCallback(async (ignoreResult?: () => boolean) => {
    setLoading(true);
    setLogsError(null);
    const res = await api.getLoginLogs(page, PAGE_SIZE);
    if (ignoreResult?.()) {
      return;
    }
    if (res.success && res.data) {
      setLogs(res.data.logs || []);
      setTotal(res.data.total || 0);
    } else {
      setLogsError(res.error?.message || t('admin.logs.loadLogsFailed'));
    }
    setLoading(false);
  }, [page, t]);

  const loadRiskEvents = useCallback(async (ignoreResult?: () => boolean) => {
    setRiskLoading(true);
    setRiskError(null);
    const res = await api.getRiskEvents(riskPage, PAGE_SIZE, riskDecisionFilter, riskReasonFilter);
    if (ignoreResult?.()) {
      return;
    }
    if (res.success && res.data) {
      setRiskEvents(res.data.events || []);
      setRiskTotal(res.data.total || 0);
      setRiskReasons(res.data.reasons || []);
    } else {
      setRiskError(res.error?.message || t('admin.logs.loadRiskEventsFailed'));
    }
    setRiskLoading(false);
  }, [riskPage, riskDecisionFilter, riskReasonFilter, t]);

  useEffect(() => {
    if (user && user.role !== 'admin') {
      router.push('/dashboard');
    }
  }, [user, router]);

  useEffect(() => {
    if (user?.role === 'admin') {
      let ignore = false;
      loadLogs(() => ignore);
      return () => {
        ignore = true;
      };
    }
  }, [user?.role, loadLogs]);

  useEffect(() => {
    if (user?.role === 'admin') {
      let ignore = false;
      loadRiskEvents(() => ignore);
      return () => {
        ignore = true;
      };
    }
  }, [user?.role, loadRiskEvents]);

  const loginTypeLabel = (type: LoginLog['login_type']) => {
    switch (type) {
      case 'oauth':
        return t('admin.logs.oauthLogin');
      case 'sdk':
        return t('admin.logs.sdkLogin');
      default:
        return t('admin.logs.directLogin');
    }
  };

  const riskDecisionLabel = (decision: RiskEvent['decision']) => {
    switch (decision) {
      case 'challenge':
        return t('admin.logs.riskChallenge');
      case 'mfa':
        return t('admin.logs.riskMfa');
      case 'block':
        return t('admin.logs.riskBlock');
      default:
        return t('admin.logs.riskPass');
    }
  };

  const riskDecisionVariant = (decision: RiskEvent['decision']): 'default' | 'secondary' | 'destructive' | 'outline' | 'success' | 'warning' | 'info' => {
    switch (decision) {
      case 'block':
        return 'destructive';
      case 'challenge':
      case 'mfa':
        return 'warning';
      case 'pass':
        return 'success';
      default:
        return 'secondary';
    }
  };
  const riskDecisionOptions: { value: RiskDecisionFilter; label: string }[] = [
    { value: '', label: t('admin.logs.allRiskDecisions') },
    { value: 'pass', label: riskDecisionLabel('pass') },
    { value: 'challenge', label: riskDecisionLabel('challenge') },
    { value: 'mfa', label: riskDecisionLabel('mfa') },
    { value: 'block', label: riskDecisionLabel('block') },
  ];
  const riskReasonLabel = (reason: string) => {
    switch (reason) {
      case 'suspicious login':
        return t('admin.logs.reasonSuspiciousLogin');
      case 'additional verification required':
        return t('admin.logs.reasonAdditionalVerificationRequired');
      case 'account locked after failed login attempts':
        return t('admin.logs.reasonAccountLocked');
      case 'refresh token replay':
        return t('admin.logs.reasonRefreshTokenReplay');
      case 'sdk external identity conflict':
        return t('admin.logs.reasonSdkExternalIdentityConflict');
      case 'Cross-origin request blocked':
        return t('admin.logs.reasonCrossOriginBlocked');
      case 'CSRF token missing':
        return t('admin.logs.reasonCsrfTokenMissing');
      case 'CSRF token header missing':
        return t('admin.logs.reasonCsrfTokenHeaderMissing');
      case 'CSRF token mismatch':
        return t('admin.logs.reasonCsrfTokenMismatch');
      default:
        return reason;
    }
  };

  if (user?.role !== 'admin') {
    return null;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('admin.logs.title')}
        description={t('admin.logs.description')}
        icon={Activity}
      />

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4">
          <div>
            <CardTitle>{t('admin.logs.loginRecords')}</CardTitle>
            <CardDescription>
              {t('admin.logs.totalRecords', { count: String(total) })}
            </CardDescription>
          </div>
          <Button variant="outline" size="sm" onClick={() => loadLogs()} disabled={loading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            {t('admin.logs.refresh')}
          </Button>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          ) : logsError ? (
            <EmptyState
              icon={AlertTriangle}
              title={t('admin.logs.loadLogsFailed')}
              description={logsError}
            />
          ) : logs.length === 0 ? (
            <EmptyState
              icon={Activity}
              title={t('admin.logs.noLogs')}
              description={t('admin.logs.description')}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="pb-2 pr-4 font-medium">{t('admin.logs.user')}</th>
                    <th className="pb-2 pr-4 font-medium">{t('admin.logs.type')}</th>
                    <th className="pb-2 pr-4 font-medium">{t('admin.logs.result')}</th>
                    <th className="pb-2 pr-4 font-medium">{t('admin.logs.ipAddress')}</th>
                    <th className="pb-2 pr-4 font-medium">{t('admin.logs.browser')}</th>
                    <th className="pb-2 font-medium">{t('admin.logs.time')}</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log) => (
                    <tr key={log.id} className="border-b last:border-0 align-top">
                      <td className="py-3 pr-4">
                        <div className="font-medium">
                          {log.user?.username || log.user?.email || log.email || '—'}
                        </div>
                        {log.app?.name && (
                          <div className="text-xs text-muted-foreground">{log.app.name}</div>
                        )}
                      </td>
                      <td className="py-3 pr-4">
                        <Badge variant="outline">{loginTypeLabel(log.login_type)}</Badge>
                      </td>
                      <td className="py-3 pr-4">
                        {log.success ? (
                          <span className="inline-flex items-center gap-1 text-green-600 dark:text-green-400">
                            <CheckCircle className="h-4 w-4" />
                            {t('admin.logs.loginSuccess')}
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-red-600 dark:text-red-400">
                            <XCircle className="h-4 w-4" />
                            {t('admin.logs.loginFailed')}
                          </span>
                        )}
                        {!log.success && log.failure_reason && (
                          <div className="text-xs text-muted-foreground mt-1">{log.failure_reason}</div>
                        )}
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs">{log.ip_address || '—'}</td>
                      <td className="py-3 pr-4 max-w-[200px] truncate text-xs text-muted-foreground" title={log.user_agent}>
                        {log.user_agent || '—'}
                      </td>
                      <td className="py-3 whitespace-nowrap text-muted-foreground">
                        {new Date(log.created_at).toLocaleString(dateLocale)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {total > PAGE_SIZE && (
            <div className="flex items-center justify-between mt-6 pt-4 border-t">
              <div className="text-sm text-muted-foreground">
                <p>{t('common.paginationInfo', { start: String(logRangeStart), end: String(logRangeEnd), total: String(total) })}</p>
                <p className="text-xs">{t('admin.logs.pageInfo', { page: String(page), total: String(totalPages) })}</p>
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4">
          <div>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" />
              {t('admin.logs.riskEvents')}
            </CardTitle>
            <CardDescription>
              {t('admin.logs.totalRiskEvents', { count: String(riskTotal) })}
            </CardDescription>
          </div>
          <Button variant="outline" size="sm" onClick={() => loadRiskEvents()} disabled={riskLoading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${riskLoading ? 'animate-spin' : ''}`} />
            {t('admin.logs.refresh')}
          </Button>
        </CardHeader>
        <CardContent>
          <div className="mb-4 grid gap-3 md:grid-cols-[minmax(180px,240px)_minmax(220px,320px)_auto]">
            <label className="flex flex-col gap-1 text-xs font-medium text-muted-foreground">
              {t('admin.logs.decision')}
              <select
                className="h-9 rounded-md border bg-background px-3 text-sm text-foreground outline-none focus:border-ring focus:ring-ring/50 focus:ring-[3px]"
                value={riskDecisionFilter}
                onChange={(event) => {
                  setRiskDecisionFilter(event.target.value as RiskDecisionFilter);
                  setRiskPage(1);
                }}
              >
                {riskDecisionOptions.map((option) => (
                  <option key={option.value || 'all'} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-xs font-medium text-muted-foreground">
              {t('admin.logs.reason')}
              <select
                className="h-9 rounded-md border bg-background px-3 text-sm text-foreground outline-none focus:border-ring focus:ring-ring/50 focus:ring-[3px]"
                value={riskReasonFilter}
                onChange={(event) => {
                  setRiskReasonFilter(event.target.value);
                  setRiskPage(1);
                }}
              >
                <option value="">{t('admin.logs.allRiskReasons')}</option>
                {riskReasons.map((reason) => (
                  <option key={reason} value={reason}>
                    {riskReasonLabel(reason)}
                  </option>
                ))}
              </select>
            </label>
            {(riskDecisionFilter || riskReasonFilter) && (
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="self-end"
                onClick={() => {
                  setRiskDecisionFilter('');
                  setRiskReasonFilter('');
                  setRiskPage(1);
                }}
              >
                {t('admin.logs.clearFilters')}
              </Button>
            )}
          </div>

          {riskLoading ? (
            <div className="flex justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          ) : riskError ? (
            <EmptyState
              icon={AlertTriangle}
              title={t('admin.logs.loadRiskEventsFailed')}
              description={riskError}
            />
          ) : riskEvents.length === 0 ? (
            <EmptyState
              icon={AlertTriangle}
              title={t('admin.logs.noRiskEvents')}
              description={t('admin.logs.riskEventsDescription')}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="pb-2 pr-4 font-medium">{t('admin.logs.user')}</th>
                    <th className="pb-2 pr-4 font-medium">{t('admin.logs.riskScore')}</th>
                    <th className="pb-2 pr-4 font-medium">{t('admin.logs.decision')}</th>
                    <th className="pb-2 pr-4 font-medium">{t('admin.logs.reason')}</th>
                    <th className="pb-2 pr-4 font-medium">{t('admin.logs.context')}</th>
                    <th className="pb-2 font-medium">{t('admin.logs.time')}</th>
                  </tr>
                </thead>
                <tbody>
                  {riskEvents.map((event) => (
                    <tr key={event.id} className="border-b last:border-0 align-top">
                      <td className="py-3 pr-4">
                        <div className="font-medium">
                          {event.user?.username || event.user?.email || event.user_id || t('admin.logs.anonymousRiskEvent')}
                        </div>
                        {event.user?.email && event.user?.username && (
                          <div className="text-xs text-muted-foreground">{event.user.email}</div>
                        )}
                      </td>
                      <td className="py-3 pr-4">
                        <Badge variant={event.risk_score >= 80 ? 'destructive' : event.risk_score >= 50 ? 'warning' : 'secondary'}>
                          {event.risk_score}
                        </Badge>
                      </td>
                      <td className="py-3 pr-4">
                        <Badge variant={riskDecisionVariant(event.decision)}>
                          {riskDecisionLabel(event.decision)}
                        </Badge>
                      </td>
                      <td className="py-3 pr-4 text-sm text-muted-foreground">
                        {event.reason ? riskReasonLabel(event.reason) : '—'}
                      </td>
                      <td className="py-3 pr-4">
                        <div className="font-mono text-xs">{event.ip_address || '—'}</div>
                        <div className="max-w-[240px] truncate text-xs text-muted-foreground" title={event.user_agent}>
                          {event.user_agent || '—'}
                        </div>
                      </td>
                      <td className="py-3 whitespace-nowrap text-muted-foreground">
                        {new Date(event.created_at).toLocaleString(dateLocale)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {riskTotal > PAGE_SIZE && (
            <div className="flex items-center justify-between mt-6 pt-4 border-t">
              <div className="text-sm text-muted-foreground">
                <p>{t('common.paginationInfo', { start: String(riskRangeStart), end: String(riskRangeEnd), total: String(riskTotal) })}</p>
                <p className="text-xs">{t('admin.logs.pageInfo', { page: String(riskPage), total: String(riskTotalPages) })}</p>
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={riskPage <= 1}
                  onClick={() => setRiskPage((p) => Math.max(1, p - 1))}
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={riskPage >= riskTotalPages}
                  onClick={() => setRiskPage((p) => p + 1)}
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

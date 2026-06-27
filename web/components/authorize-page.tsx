'use client';

import { useEffect, useState, Suspense, useCallback, useRef } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Loader2, Shield, Check, X, AlertCircle } from 'lucide-react';

type OAuthAppInfoPayload = {
  app: {
    id: string;
    name: string;
    description: string;
    client_id?: string;
    scopes?: string[];
    issued_token_types?: string[];
  };
  requested_scopes?: string[];
  invalid_scopes?: string[];
  effective_scope?: string;
  has_openid?: boolean;
  issued_token_types?: string[];
};

/**
 * 共享的 OAuth 授权页面内容组件
 * @param basePath - 当前路由路径前缀，用于构建 returnUrl（如 '/oauth/authorize' 或 '/auth/authorize'）
 */
function AuthorizeContent({ basePath }: { basePath: string }) {
  const searchParams = useSearchParams();
  const router = useRouter();
  const { isAuthenticated, isLoading: authLoading } = useAuth();
  const { t } = useI18n();

  const [appInfo, setAppInfo] = useState<OAuthAppInfoPayload['app'] | null>(null);
  const [requestedScopes, setRequestedScopes] = useState<string[]>([]);
  const [issuedTokenTypes, setIssuedTokenTypes] = useState<string[]>([]);
  const [invalidScopes, setInvalidScopes] = useState<string[]>([]);
  const [hasOpenID, setHasOpenID] = useState(false);
  const [effectiveScope, setEffectiveScope] = useState('');
  const [appInfoReady, setAppInfoReady] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [redirectUrl, setRedirectUrl] = useState<string | null>(null);
  const consentSubmittedRef = useRef(false);

  const clientId = searchParams.get('client_id');
  const redirectUri = searchParams.get('redirect_uri');
  const responseType = searchParams.get('response_type');
  const scope = searchParams.get('scope') || '';
  const state = searchParams.get('state') || '';
  const nonce = searchParams.get('nonce') || '';
  const maxAge = searchParams.get('max_age') || '';
  const prompt = searchParams.get('prompt') || '';
  const codeChallenge = searchParams.get('code_challenge') || '';
  const codeChallengeMethod = searchParams.get('code_challenge_method') || '';

  const returnToAuthorize = `${basePath}?${searchParams.toString()}`;
  const loginUrl = `/login?return_to=${encodeURIComponent(returnToAuthorize)}`;
  const forceLoginUrl = `${loginUrl}&force_login=1`;
  const promptNone = prompt.split(/\s+/).includes('none');

  const buildAuthorizeErrorRedirect = useCallback((errorCode: string, errorDescription: string) => {
    if (!redirectUri) return null;
    try {
      const url = new URL(redirectUri);
      url.searchParams.set('error', errorCode);
      url.searchParams.set('error_description', errorDescription);
      if (state) url.searchParams.set('state', state);
      return url.toString();
    } catch {
      return null;
    }
  }, [redirectUri, state]);

  /** 从后端拉取授权上下文（公开接口，不依赖是否已登录） */
  const fetchAuthorizeContext = useCallback(async () => {
    if (!clientId || !redirectUri || responseType !== 'code') {
      setError(t('oauth.authorize.invalidRequest'));
      setAppInfoReady(false);
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    setAppInfoReady(false);
    setError(null);

    const response = await api.getOAuthAppInfo(
      clientId,
      redirectUri,
      scope || undefined,
      responseType || undefined
    );

    if (!response.success || !response.data?.app) {
      setError(response.error?.message || t('oauth.authorize.loadFailed'));
      setAppInfo(null);
      setRequestedScopes([]);
      setIssuedTokenTypes([]);
      setInvalidScopes([]);
      setHasOpenID(false);
      setEffectiveScope('');
      setAppInfoReady(false);
      setIsLoading(false);
      return;
    }

    const data = response.data;
    setAppInfo(data.app);
    setRequestedScopes(data.requested_scopes ?? []);
    setInvalidScopes(data.invalid_scopes ?? []);
    setHasOpenID(Boolean(data.has_openid));
    setEffectiveScope(data.effective_scope ?? '');
    setIssuedTokenTypes(
      uniqueList(data.issued_token_types ?? data.app.issued_token_types ?? [])
    );
    setAppInfoReady(true);
    setIsLoading(false);
  }, [clientId, redirectUri, responseType, scope, t]);

  /** 已登录时检查是否已有未兑换授权码，可直接跳转 callback */
  const checkPendingRedirect = useCallback(async () => {
    if (!clientId || !redirectUri || consentSubmittedRef.current) return;

    const pending = await api.getOAuthAuthorizePending({
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scope || undefined,
      state: state || undefined,
      nonce: nonce || undefined,
      max_age: maxAge || undefined,
      prompt: prompt || undefined,
      code_challenge: codeChallenge || undefined,
    });

    if (pending.success && pending.data?.redirect_url && !pending.data.pending) {
      consentSubmittedRef.current = true;
      setRedirectUrl(pending.data.redirect_url);
      return;
    }

    if (pending.success && pending.data?.login_required) {
      router.replace(forceLoginUrl);
      return;
    }

    if (pending.success && pending.data?.pending && pending.data.redirect_url) {
      consentSubmittedRef.current = true;
      setRedirectUrl(pending.data.redirect_url);
    }
  }, [clientId, redirectUri, scope, state, nonce, maxAge, prompt, codeChallenge, router, forceLoginUrl]);

  useEffect(() => {
    void fetchAuthorizeContext();
  }, [fetchAuthorizeContext]);

  useEffect(() => {
    if (authLoading || !appInfoReady || consentSubmittedRef.current) return;

    if (!isAuthenticated) {
      if (promptNone) {
        const errorRedirect = buildAuthorizeErrorRedirect('login_required', 'End-user authentication is required');
        if (errorRedirect) {
          consentSubmittedRef.current = true;
          setRedirectUrl(errorRedirect);
          return;
        }
      }
      router.replace(loginUrl);
      return;
    }

    void checkPendingRedirect();
  }, [authLoading, isAuthenticated, appInfoReady, router, loginUrl, promptNone, buildAuthorizeErrorRedirect, checkPendingRedirect]);

  useEffect(() => {
    if (redirectUrl) {
      window.location.href = redirectUrl;
    }
  }, [redirectUrl]);

  const handleConsent = async (allow: boolean) => {
    if (!clientId || !redirectUri || !responseType) return;
    if (consentSubmittedRef.current || isSubmitting) return;

    if (!isAuthenticated) {
      if (promptNone) {
        const errorRedirect = buildAuthorizeErrorRedirect('login_required', 'End-user authentication is required');
        if (errorRedirect) {
          consentSubmittedRef.current = true;
          setRedirectUrl(errorRedirect);
          return;
        }
      }
      router.push(loginUrl);
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await api.submitOAuthAuthorize({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: responseType,
        scope: scope || undefined,
        state: state || undefined,
        nonce: nonce || undefined,
        max_age: maxAge || undefined,
        prompt: prompt || undefined,
        code_challenge: codeChallenge || undefined,
        code_challenge_method: codeChallengeMethod || undefined,
        consent: allow ? 'allow' : 'deny',
      });

      if (response.success && response.data?.redirect_url && !response.data.code) {
        consentSubmittedRef.current = true;
        setRedirectUrl(response.data.redirect_url);
        return;
      }

      if (response.success && response.data?.login_required) {
        router.push(forceLoginUrl);
        return;
      }

      if (response.success && response.data?.redirect_url) {
        consentSubmittedRef.current = true;
        setRedirectUrl(response.data.redirect_url);
      } else {
        setError(response.error?.message || t('oauth.authorize.authFailed'));
        setIsSubmitting(false);
      }
    } catch {
      setError(t('oauth.authorize.error'));
      setIsSubmitting(false);
    }
  };

  const getScopeDescription = (scopeName: string) => {
    const key = `oauth.scopes.${scopeName}`;
    const translated = t(key);
    return translated !== key ? translated : scopeName;
  };

  const getTokenTypeLabel = (tokenType: string) => {
    const key = `oauth.tokenTypes.${tokenType}`;
    const translated = t(key);
    return translated !== key ? translated : tokenType;
  };

  if (isLoading || !appInfoReady) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (error || !appInfo) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <div className="flex justify-center mb-4">
              <div className="h-12 w-12 rounded-full bg-red-100 flex items-center justify-center">
                <AlertCircle className="h-6 w-6 text-red-500" />
              </div>
            </div>
            <CardTitle>{t('oauth.authorize.error')}</CardTitle>
            <CardDescription>{error || t('oauth.authorize.loadFailed')}</CardDescription>
          </CardHeader>
          <CardFooter className="justify-center">
            <Button variant="outline" onClick={() => window.history.back()}>
              {t('errors.goBack')}
            </Button>
          </CardFooter>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <div className="h-16 w-16 rounded-full bg-primary/10 flex items-center justify-center">
              <Shield className="h-8 w-8 text-primary" />
            </div>
          </div>
          <CardTitle className="text-xl">{t('oauth.authorize.title', { app: appInfo.name })}</CardTitle>
          <CardDescription>
            {appInfo.description || t('oauth.authorize.description')}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {(requestedScopes.length > 0 || hasOpenID) ? (
            <div className="space-y-2">
              <p className="text-sm font-medium">{t('oauth.authorize.permissions')}</p>
              <ul className="space-y-2">
                {hasOpenID && requestedScopes.length === 0 && (
                  <li className="flex items-start gap-2 text-sm">
                    <Check className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    <span>{t('oauth.scopes.openid')}</span>
                  </li>
                )}
                {requestedScopes.map((s) => (
                  <li key={s} className="flex items-start gap-2 text-sm">
                    <Check className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    <span>{getScopeDescription(s)}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">{t('oauth.authorize.noExtraScopes')}</p>
          )}

          {invalidScopes.length > 0 && (
            <p className="text-xs text-destructive">
              {t('oauth.authorize.invalidScopesHint', { scopes: invalidScopes.join(', ') })}
            </p>
          )}

          {issuedTokenTypes.length > 0 && (
            <p className="text-xs text-muted-foreground">
              {t('oauth.authorize.tokenTypes')}:{' '}
              {issuedTokenTypes.map(getTokenTypeLabel).join(', ')}
            </p>
          )}

          {effectiveScope ? (
            <p className="text-xs text-muted-foreground font-mono break-all">
              {t('oauth.authorize.effectiveScope')}: {effectiveScope}
            </p>
          ) : null}

          <div className="text-xs text-muted-foreground bg-slate-100 dark:bg-slate-800 p-3 rounded-md">
            <p>{t('oauth.authorize.redirectTo')}</p>
            <p className="font-mono break-all mt-1">{redirectUri}</p>
          </div>
        </CardContent>
        <CardFooter className="flex gap-3">
          <Button
            variant="outline"
            className="flex-1"
            onClick={() => handleConsent(false)}
            disabled={isSubmitting || !!redirectUrl}
          >
            <X className="mr-2 h-4 w-4" />
            {t('oauth.authorize.deny')}
          </Button>
          <Button
            className="flex-1"
            onClick={() => handleConsent(true)}
            disabled={isSubmitting || !!redirectUrl || invalidScopes.length > 0}
          >
            {isSubmitting ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Check className="mr-2 h-4 w-4" />
            )}
            {t('oauth.authorize.allow')}
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}

function uniqueList(items: string[]): string[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    if (!item || seen.has(item)) return false;
    seen.add(item);
    return true;
  });
}

export default function AuthorizePage({ basePath }: { basePath: string }) {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      }
    >
      <AuthorizeContent basePath={basePath} />
    </Suspense>
  );
}

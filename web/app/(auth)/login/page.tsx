'use client';

import { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/lib/auth-context';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { safeReturnPath } from '@/lib/redirect';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Loader2, Mail, Lock, Shield, AlertCircle, ArrowRight, Sparkles, Eye, EyeOff } from 'lucide-react';
import { ProviderIcon } from '@/components/provider-icon';
import type { EnterpriseProviderPublic, FederationProvider, SocialProvider } from '@/lib/types';

type LoginTab = 'local' | 'ldap';
type ExternalLoginProvider = {
  slug: string;
  name: string;
  icon_url?: string;
  button_text?: string;
  type: 'federation' | 'social' | 'saml';
};

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { login, loginWithLDAP, isAuthenticated, isLoading: authLoading } = useAuth();
  const { t } = useI18n();

  const [activeTab, setActiveTab] = useState<LoginTab>('local');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [ldapIdentifier, setLDAPIdentifier] = useState('');
  const [ldapPassword, setLDAPPassword] = useState('');
  const [selectedLDAPProvider, setSelectedLDAPProvider] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showLDAPPassword, setShowLDAPPassword] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [federationProviders, setFederationProviders] = useState<FederationProvider[]>([]);
  const [socialProviders, setSocialProviders] = useState<SocialProvider[]>([]);
  const [ldapProviders, setLDAPProviders] = useState<EnterpriseProviderPublic[]>([]);
  const [samlProviders, setSAMLProviders] = useState<EnterpriseProviderPublic[]>([]);
  const [redirectUrl, setRedirectUrl] = useState<string | null>(null);

  const returnTo = safeReturnPath(searchParams.get('return_to'));
  const forceLogin = searchParams.get('force_login') === '1';

  /* 已登录用户自动跳转，无需重复登录 */
  useEffect(() => {
    if (!authLoading && isAuthenticated && !forceLogin) {
      router.replace(returnTo);
    }
  }, [authLoading, forceLogin, isAuthenticated, returnTo, router]);

  /* 外部跳转统一通过 useEffect 处理，避免直接赋值 window.location.href */
  useEffect(() => {
    if (redirectUrl) {
      window.location.href = redirectUrl;
    }
  }, [redirectUrl]);

  /* 加载可用的第三方与企业登录提供商 */
  useEffect(() => {
    const loadProviders = async () => {
      const [fedRes, socialRes, enterpriseRes] = await Promise.all([
        api.getFederationProviders(),
        api.getSocialProviders(),
        api.getEnterpriseProviders(),
      ]);
      if (fedRes.success && fedRes.data) {
        setFederationProviders(fedRes.data.providers || []);
      }
      if (socialRes.success && socialRes.data) {
        setSocialProviders(socialRes.data.providers || []);
      }
      if (enterpriseRes.success && enterpriseRes.data) {
        const ldap = enterpriseRes.data.ldap_providers || [];
        setLDAPProviders(ldap);
        setSAMLProviders(enterpriseRes.data.saml_providers || []);
        setSelectedLDAPProvider((prev) => prev || ldap[0]?.slug || '');
      }
    };
    loadProviders();
  }, []);

  /* 检查 URL 中的错误参数（外部登录回调失败） */
  useEffect(() => {
    const errorParam = searchParams.get('error');
    if (errorParam) {
      setError(decodeURIComponent(errorParam));
    }
  }, [searchParams]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    const result = activeTab === 'ldap'
      ? await loginWithLDAP(selectedLDAPProvider, ldapIdentifier, ldapPassword)
      : await login(email, password);

    if (result.success) {
      router.push(returnTo);
    } else {
      setError(result.error || t('auth.callback.loginFailed'));
    }

    setIsLoading(false);
  };

  /* 处理外部一键登录 */
  const handleExternalLogin = (provider: string, type: ExternalLoginProvider['type']) => {
    if (type === 'federation') {
      setRedirectUrl(api.getFederationLoginUrl(provider, returnTo));
      return;
    }
    if (type === 'saml') {
      setRedirectUrl(api.getSAMLLoginUrl(provider, returnTo));
      return;
    }
    setRedirectUrl(api.getSocialLoginUrl(provider, returnTo));
  };

  const allProviders: ExternalLoginProvider[] = [
    ...socialProviders.map(p => ({ ...p, type: 'social' as const })),
    ...federationProviders.map(p => ({ slug: p.slug, name: p.name, icon_url: p.icon_url, button_text: p.button_text, type: 'federation' as const })),
    ...samlProviders.map(p => ({ ...p, type: 'saml' as const })),
  ];

  const submitText = activeTab === 'ldap' ? t('auth.login.directorySubmit') : t('auth.login.submit');

  /* 正在检查登录状态或已登录正在跳转 */
  if (authLoading || (isAuthenticated && !forceLogin)) {
    return (
      <div className="w-full max-w-md mx-auto flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
          <p className="mt-2 text-sm text-muted-foreground">
            {isAuthenticated ? t('auth.login.redirecting') : t('common.loading')}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-md mx-auto animate-slide-up">
      {/* Logo Section */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-gradient-to-br from-primary to-primary/70 shadow-xl shadow-primary/30 mb-4">
          <Shield className="h-8 w-8 text-primary-foreground" />
        </div>
        <h1 className="text-2xl font-bold">OAuth2</h1>
        <p className="text-sm text-muted-foreground">{t('common.brandSubtitle')}</p>
      </div>

      <Card className="shadow-xl border-0 bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl">
        <CardHeader className="space-y-1 pb-4">
          <CardTitle className="text-xl font-bold text-center">{t('auth.login.title')}</CardTitle>
          <CardDescription className="text-center">
            {t('auth.login.description')}
          </CardDescription>
        </CardHeader>
        <form onSubmit={handleSubmit}>
          <CardContent className="space-y-4">
            {error && (
              <Alert variant="destructive" className="animate-scale-in">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {/* 第三方与 SAML 一键登录按钮 */}
            {allProviders.length > 0 && (
              <div className="space-y-3">
                <div className="grid gap-2">
                  {allProviders.map((provider) => (
                    <Button
                      key={`${provider.type}-${provider.slug}`}
                      type="button"
                      variant="outline"
                      className="w-full h-11 gap-3 font-medium hover:bg-muted/80 transition-all"
                      onClick={() => handleExternalLogin(provider.slug, provider.type)}
                    >
                      <ProviderIcon slug={provider.type === 'saml' ? 'saml' : provider.slug} className="h-5 w-5" />
                      {provider.button_text || t('auth.login.signInWith').replace('{provider}', provider.name)}
                    </Button>
                  ))}
                </div>
                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <span className="w-full border-t" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-card px-2 text-muted-foreground">
                      {t('auth.login.or')}
                    </span>
                  </div>
                </div>
              </div>
            )}

            <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as LoginTab)} className="space-y-4">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="local" className="gap-2">
                  <Mail className="h-4 w-4" />
                  {t('auth.login.localAccount')}
                </TabsTrigger>
                <TabsTrigger value="ldap" className="gap-2">
                  <Shield className="h-4 w-4" />
                  {t('auth.login.enterpriseDirectory')}
                </TabsTrigger>
              </TabsList>

              <TabsContent value="local" className="space-y-4 mt-0">
                <div className="space-y-2">
                  <Label htmlFor="email" className="text-sm font-medium">{t('auth.login.email')}</Label>
                  <div className="relative group">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground transition-colors group-focus-within:text-primary" />
                    <Input
                      id="email"
                      type="email"
                      placeholder="name@example.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="pl-10 h-11 bg-muted/50 border-muted focus:bg-background transition-colors"
                      autoComplete="email"
                      required={activeTab === 'local'}
                      disabled={isLoading || activeTab !== 'local'}
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="password" className="text-sm font-medium">{t('auth.login.password')}</Label>
                    <Link
                      href="/forgot-password"
                      className="text-xs text-muted-foreground hover:text-primary transition-colors"
                    >
                      {t('auth.login.forgotPassword')}
                    </Link>
                  </div>
                  <div className="relative group">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground transition-colors group-focus-within:text-primary" />
                    <Input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      placeholder="••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="pl-10 pr-10 h-11 bg-muted/50 border-muted focus:bg-background transition-colors"
                      autoComplete="current-password"
                      required={activeTab === 'local'}
                      disabled={isLoading || activeTab !== 'local'}
                    />
                    <button
                      type="button"
                      tabIndex={-1}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                      onClick={() => setShowPassword(!showPassword)}
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="ldap" className="space-y-4 mt-0">
                {ldapProviders.length === 0 && (
                  <div className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
                    {t('auth.login.noEnterpriseDirectory')}
                  </div>
                )}
                {ldapProviders.length > 1 && (
                  <div className="space-y-2">
                    <Label htmlFor="ldap-provider" className="text-sm font-medium">{t('auth.login.enterpriseProvider')}</Label>
                    <select
                      id="ldap-provider"
                      value={selectedLDAPProvider}
                      onChange={(e) => setSelectedLDAPProvider(e.target.value)}
                      className="flex h-11 w-full rounded-md border border-input bg-muted/50 px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                      required={activeTab === 'ldap'}
                      disabled={isLoading || activeTab !== 'ldap'}
                    >
                      {ldapProviders.map((provider) => (
                        <option key={provider.slug} value={provider.slug}>{provider.name}</option>
                      ))}
                    </select>
                  </div>
                )}
                {ldapProviders.length === 1 && (
                  <div className="rounded-lg border bg-muted/40 p-3 text-sm">
                    <span className="text-muted-foreground">{t('auth.login.enterpriseProvider')}：</span>
                    <span className="font-medium">{ldapProviders[0].name}</span>
                  </div>
                )}
                <div className="space-y-2">
                  <Label htmlFor="ldap-identifier" className="text-sm font-medium">{t('auth.login.enterpriseIdentifier')}</Label>
                  <div className="relative group">
                    <Shield className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground transition-colors group-focus-within:text-primary" />
                    <Input
                      id="ldap-identifier"
                      type="text"
                      placeholder={t('auth.login.enterpriseIdentifierPlaceholder')}
                      value={ldapIdentifier}
                      onChange={(e) => setLDAPIdentifier(e.target.value)}
                      className="pl-10 h-11 bg-muted/50 border-muted focus:bg-background transition-colors"
                      autoComplete="username"
                      required={activeTab === 'ldap'}
                      disabled={isLoading || activeTab !== 'ldap' || ldapProviders.length === 0}
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="ldap-password" className="text-sm font-medium">{t('auth.login.password')}</Label>
                  <div className="relative group">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground transition-colors group-focus-within:text-primary" />
                    <Input
                      id="ldap-password"
                      type={showLDAPPassword ? 'text' : 'password'}
                      placeholder="••••••••"
                      value={ldapPassword}
                      onChange={(e) => setLDAPPassword(e.target.value)}
                      className="pl-10 pr-10 h-11 bg-muted/50 border-muted focus:bg-background transition-colors"
                      autoComplete="current-password"
                      required={activeTab === 'ldap'}
                      disabled={isLoading || activeTab !== 'ldap' || ldapProviders.length === 0}
                    />
                    <button
                      type="button"
                      tabIndex={-1}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                      onClick={() => setShowLDAPPassword(!showLDAPPassword)}
                      aria-label={showLDAPPassword ? 'Hide password' : 'Show password'}
                    >
                      {showLDAPPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
          <CardFooter className="flex flex-col gap-4 pt-2">
            <Button
              type="submit"
              className="w-full h-11 text-base font-medium shadow-lg shadow-primary/20 hover:shadow-xl hover:shadow-primary/30 transition-all"
              disabled={isLoading || (activeTab === 'ldap' && ldapProviders.length === 0)}
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  {t('auth.login.submitting')}
                </>
              ) : (
                <>
                  {submitText}
                  <ArrowRight className="ml-2 h-4 w-4" />
                </>
              )}
            </Button>

            {allProviders.length === 0 && (
              <div className="relative w-full">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-card px-2 text-muted-foreground">
                    {t('auth.login.or')}
                  </span>
                </div>
              </div>
            )}

            <p className="text-sm text-center text-muted-foreground">
              {t('auth.login.noAccount')}{' '}
              <Link href="/register" className="text-primary hover:underline font-semibold inline-flex items-center gap-1">
                {t('auth.login.signUp')}
                <Sparkles className="h-3 w-3" />
              </Link>
            </p>
          </CardFooter>
        </form>
      </Card>

      {/* Footer */}
      <p className="text-center text-xs text-muted-foreground mt-6">
        {t('common.poweredBy')}
      </p>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
          <p className="mt-2 text-sm text-muted-foreground animate-pulse">&nbsp;</p>
        </div>
      </div>
    }>
      <LoginForm />
    </Suspense>
  );
}

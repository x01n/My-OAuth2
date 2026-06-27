'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useAuth } from '@/lib/auth-context';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { PageHeader } from '@/components/ui/page-header';
import { EmptyState } from '@/components/ui/empty-state';
import { Skeleton } from '@/components/ui/skeleton';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ProviderIcon } from '@/components/provider-icon';
import {
  AlertCircle,
  Building2,
  Check,
  Copy,
  ExternalLink,
  Globe,
  Loader2,
  Plus,
  RefreshCw,
  Settings2,
  ShieldCheck,
  Trash2,
  Wand2,
  X,
} from 'lucide-react';
import type {
  CreateFederationProviderRequest,
  FederationProvider,
  LDAPProviderConfig,
  LDAPProviderUpdateRequest,
  SAMLProviderConfig,
  SAMLProviderUpdateRequest,
  UserRole,
} from '@/lib/types';

type ProviderKind = 'oidc' | 'ldap' | 'saml';

type ProviderRecord =
  | { kind: 'oidc'; data: FederationProvider }
  | { kind: 'ldap'; data: LDAPProviderConfig }
  | { kind: 'saml'; data: SAMLProviderConfig };

type OIDCFormState = CreateFederationProviderRequest;
type LDAPFormState = LDAPProviderUpdateRequest;
type SAMLFormState = SAMLProviderUpdateRequest;

type SaveResult = { ok: true } | { ok: false; error: string };
type MessageState = { type: 'success' | 'error'; text: string } | null;

const ROLE_OPTIONS: UserRole[] = ['user', 'admin'];
const DEFAULT_ROLE_MAPPINGS = '{\n  "cn=admins,ou=groups,dc=example,dc=com": "admin",\n  "cn=users,ou=groups,dc=example,dc=com": "user"\n}';
const DEFAULT_LDAP_FORM: LDAPFormState = {
  name: '',
  slug: '',
  description: '',
  ldap_url: '',
  use_starttls: true,
  insecure_skip_verify: false,
  bind_dn: '',
  bind_password: '',
  base_dn: '',
  user_filter: '',
  external_id_attr: 'dn',
  principal_attr: 'userPrincipalName',
  email_attr: 'mail',
  username_attr: 'sAMAccountName',
  employee_id_attr: 'employeeID',
  display_name_attr: 'displayName',
  given_name_attr: 'givenName',
  family_name_attr: 'sn',
  group_attr: 'memberOf',
  role_mappings: undefined,
  default_role: 'user',
  enabled: true,
  auto_create_user: true,
  trust_email_verified: true,
  sync_profile: true,
  sync_enabled: false,
  sync_interval_min: 60,
  sync_page_size: 200,
  icon_url: '',
  button_text: '',
};
const DEFAULT_SAML_FORM: SAMLFormState = {
  name: '',
  slug: '',
  description: '',
  metadata_url: '',
  metadata_xml: '',
  sp_entity_id: '',
  certificate_pem: '',
  private_key_pem: '',
  sign_requests: true,
  allow_idp_initiated: true,
  default_redirect_path: '/dashboard',
  name_id_format: '',
  email_attribute: 'mail',
  username_attribute: 'uid',
  employee_id_attribute: '',
  display_name_attribute: 'displayName',
  given_name_attribute: 'givenName',
  family_name_attribute: 'sn',
  group_attribute: 'memberOf',
  role_mappings: undefined,
  default_role: 'user',
  enabled: true,
  auto_create_user: true,
  trust_email_verified: true,
  sync_profile: true,
  icon_url: '',
  button_text: '',
};

function inferProviderIcon(kind: ProviderKind, slug: string) {
  if (kind === 'ldap') return 'ldap';
  if (kind === 'saml') return 'saml';
  return slug;
}

function formatDateTime(value: string | undefined, dateLocale: string) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(dateLocale, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function normalizeSlug(raw: string) {
  return raw.toLowerCase().replace(/[^a-z0-9-]/g, '');
}

function formatRoleMappingsInput(value?: Record<string, string>) {
  if (!value || Object.keys(value).length === 0) {
    return '';
  }
  return JSON.stringify(value, null, 2);
}

function parseRoleMappingsInput(raw: string) {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { ok: true as const, value: undefined };
  }
  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ok: false as const, error: 'role_mappings 必须是 JSON 对象' };
    }
    const result: Record<string, string> = {};
    for (const [key, value] of Object.entries(parsed)) {
      if (typeof value !== 'string') {
        return { ok: false as const, error: 'role_mappings 的值必须是字符串' };
      }
      result[key] = value;
    }
    return { ok: true as const, value: result };
  } catch {
    return { ok: false as const, error: 'role_mappings 必须是合法 JSON' };
  }
}

function ProviderTypeBadge({ kind }: { kind: ProviderKind }) {
  const variant = kind === 'ldap' ? 'info' : kind === 'saml' ? 'warning' : 'secondary';
  const label = kind === 'ldap' ? 'LDAP/AD' : kind === 'saml' ? 'SAML 2.0' : 'OIDC';
  return <Badge variant={variant}>{label}</Badge>;
}

function OIDCProviderForm({
  provider,
  onSave,
  onCancel,
}: {
  provider?: FederationProvider;
  onSave: (data: CreateFederationProviderRequest) => Promise<SaveResult>;
  onCancel: () => void;
}) {
  const { t } = useI18n();
  const [form, setForm] = useState<OIDCFormState>(() => ({
    name: provider?.name || '',
    slug: provider?.slug || '',
    description: provider?.description || '',
    auth_url: provider?.auth_url || '',
    token_url: provider?.token_url || '',
    userinfo_url: provider?.userinfo_url || '',
    client_id: provider?.client_id || '',
    client_secret: '',
    scopes: provider?.scopes || 'openid profile email',
    enabled: provider?.enabled ?? true,
    auto_create_user: provider?.auto_create_user ?? true,
    trust_email_verified: provider?.trust_email_verified ?? true,
    sync_profile: provider?.sync_profile ?? true,
    icon_url: provider?.icon_url || '',
    button_text: provider?.button_text || '',
  }));
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const updateForm = (field: keyof OIDCFormState, value: string | boolean) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async () => {
    setError(null);
    if (!form.name || !form.slug || !form.auth_url || !form.token_url || !form.userinfo_url || !form.client_id) {
      setError(t('admin.federation.requiredFields'));
      return;
    }
    if (!provider && !form.client_secret) {
      setError(t('admin.federation.secretRequired'));
      return;
    }

    setIsSaving(true);
    const result = await onSave(form);
    if (!result.ok) {
      setError(result.error);
    }
    setIsSaving(false);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Globe className="h-5 w-5" />
          {provider ? t('admin.federation.editProvider') : t('admin.federation.addProviderTitle')}
        </CardTitle>
        <CardDescription>{t('admin.federation.formDescription')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">{t('admin.federation.basicInfo')}</h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>{t('admin.federation.name')} *</Label>
              <Input value={form.name} onChange={(e) => updateForm('name', e.target.value)} placeholder={t('admin.federation.namePlaceholder')} />
            </div>
            <div className="space-y-2">
              <Label>{t('admin.federation.slug')} *</Label>
              <Input
                value={form.slug}
                onChange={(e) => updateForm('slug', normalizeSlug(e.target.value))}
                placeholder={t('admin.federation.slugPlaceholder')}
                disabled={!!provider}
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label>{t('admin.federation.descriptionLabel')}</Label>
            <Input value={form.description || ''} onChange={(e) => updateForm('description', e.target.value)} placeholder={t('admin.federation.descriptionPlaceholder')} />
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">{t('admin.federation.oauthEndpoints')}</h3>
          <div className="space-y-2">
            <Label>{t('admin.federation.authUrl')} *</Label>
            <Input value={form.auth_url} onChange={(e) => updateForm('auth_url', e.target.value)} placeholder="https://provider.example.com/oauth/authorize" />
          </div>
          <div className="space-y-2">
            <Label>{t('admin.federation.tokenUrl')} *</Label>
            <Input value={form.token_url} onChange={(e) => updateForm('token_url', e.target.value)} placeholder="https://provider.example.com/oauth/token" />
          </div>
          <div className="space-y-2">
            <Label>{t('admin.federation.userinfoUrl')} *</Label>
            <Input value={form.userinfo_url} onChange={(e) => updateForm('userinfo_url', e.target.value)} placeholder="https://provider.example.com/oauth/userinfo" />
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>{t('admin.federation.clientId')} *</Label>
              <Input value={form.client_id} onChange={(e) => updateForm('client_id', e.target.value)} placeholder="client-id" />
            </div>
            <div className="space-y-2">
              <Label>{t('admin.federation.clientSecret')} {provider ? '' : '*'}</Label>
              <Input
                type="password"
                value={form.client_secret}
                onChange={(e) => updateForm('client_secret', e.target.value)}
                placeholder={provider ? t('admin.federation.clientSecretEditPlaceholder') : 'client-secret'}
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label>{t('admin.federation.scopes')}</Label>
            <Input value={form.scopes || ''} onChange={(e) => updateForm('scopes', e.target.value)} placeholder={t('admin.federation.scopesPlaceholder')} />
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">{t('admin.federation.displayConfig')}</h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>{t('admin.federation.iconUrl')}</Label>
              <Input value={form.icon_url || ''} onChange={(e) => updateForm('icon_url', e.target.value)} placeholder="https://example.com/icon.svg" />
            </div>
            <div className="space-y-2">
              <Label>{t('admin.federation.buttonText')}</Label>
              <Input value={form.button_text || ''} onChange={(e) => updateForm('button_text', e.target.value)} placeholder={t('admin.federation.buttonTextPlaceholder')} />
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">{t('admin.federation.featureSettings')}</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">{t('admin.federation.enableProvider')}</p>
                <p className="text-xs text-muted-foreground">{t('admin.federation.enableProviderDesc')}</p>
              </div>
              <Switch checked={form.enabled} onCheckedChange={(checked) => updateForm('enabled', checked)} />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">{t('admin.federation.autoCreateUser')}</p>
                <p className="text-xs text-muted-foreground">{t('admin.federation.autoCreateUserDesc')}</p>
              </div>
              <Switch checked={form.auto_create_user} onCheckedChange={(checked) => updateForm('auto_create_user', checked)} />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">{t('admin.federation.trustEmailVerified')}</p>
                <p className="text-xs text-muted-foreground">{t('admin.federation.trustEmailVerifiedDesc')}</p>
              </div>
              <Switch checked={form.trust_email_verified} onCheckedChange={(checked) => updateForm('trust_email_verified', checked)} />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">{t('admin.federation.syncProfile')}</p>
                <p className="text-xs text-muted-foreground">{t('admin.federation.syncProfileDesc')}</p>
              </div>
              <Switch checked={form.sync_profile} onCheckedChange={(checked) => updateForm('sync_profile', checked)} />
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-3 border-t pt-4">
          <Button variant="outline" onClick={onCancel}>
            <X className="mr-2 h-4 w-4" />
            {t('common.cancel')}
          </Button>
          <Button onClick={handleSubmit} disabled={isSaving}>
            {isSaving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Check className="mr-2 h-4 w-4" />}
            {provider ? t('admin.federation.update') : t('common.create')}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function LDAPProviderForm({
  provider,
  onSave,
  onCancel,
}: {
  provider?: LDAPProviderConfig;
  onSave: (data: LDAPProviderUpdateRequest) => Promise<SaveResult>;
  onCancel: () => void;
}) {
  const { dateLocale } = useI18n();
  const [form, setForm] = useState<LDAPFormState>(() => ({
    ...DEFAULT_LDAP_FORM,
    name: provider?.name || DEFAULT_LDAP_FORM.name,
    slug: provider?.slug || DEFAULT_LDAP_FORM.slug,
    description: provider?.description || DEFAULT_LDAP_FORM.description,
    ldap_url: provider?.ldap_url || DEFAULT_LDAP_FORM.ldap_url,
    use_starttls: provider?.use_starttls ?? DEFAULT_LDAP_FORM.use_starttls,
    insecure_skip_verify: provider?.insecure_skip_verify ?? DEFAULT_LDAP_FORM.insecure_skip_verify,
    bind_dn: provider?.bind_dn || DEFAULT_LDAP_FORM.bind_dn,
    base_dn: provider?.base_dn || DEFAULT_LDAP_FORM.base_dn,
    user_filter: provider?.user_filter || DEFAULT_LDAP_FORM.user_filter,
    external_id_attr: provider?.external_id_attr || DEFAULT_LDAP_FORM.external_id_attr,
    principal_attr: provider?.principal_attr || DEFAULT_LDAP_FORM.principal_attr,
    email_attr: provider?.email_attr || DEFAULT_LDAP_FORM.email_attr,
    username_attr: provider?.username_attr || DEFAULT_LDAP_FORM.username_attr,
    employee_id_attr: provider?.employee_id_attr || DEFAULT_LDAP_FORM.employee_id_attr,
    display_name_attr: provider?.display_name_attr || DEFAULT_LDAP_FORM.display_name_attr,
    given_name_attr: provider?.given_name_attr || DEFAULT_LDAP_FORM.given_name_attr,
    family_name_attr: provider?.family_name_attr || DEFAULT_LDAP_FORM.family_name_attr,
    group_attr: provider?.group_attr || DEFAULT_LDAP_FORM.group_attr,
    role_mappings: provider?.role_mappings,
    default_role: provider?.default_role || DEFAULT_LDAP_FORM.default_role,
    enabled: provider?.enabled ?? DEFAULT_LDAP_FORM.enabled,
    auto_create_user: provider?.auto_create_user ?? DEFAULT_LDAP_FORM.auto_create_user,
    trust_email_verified: provider?.trust_email_verified ?? DEFAULT_LDAP_FORM.trust_email_verified,
    sync_profile: provider?.sync_profile ?? DEFAULT_LDAP_FORM.sync_profile,
    sync_enabled: provider?.sync_enabled ?? DEFAULT_LDAP_FORM.sync_enabled,
    sync_interval_min: provider?.sync_interval_min ?? DEFAULT_LDAP_FORM.sync_interval_min,
    sync_page_size: provider?.sync_page_size ?? DEFAULT_LDAP_FORM.sync_page_size,
    icon_url: provider?.icon_url || DEFAULT_LDAP_FORM.icon_url,
    button_text: provider?.button_text || DEFAULT_LDAP_FORM.button_text,
  }));
  const [roleMappingsText, setRoleMappingsText] = useState(() => formatRoleMappingsInput(provider?.role_mappings));
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const updateForm = (field: keyof LDAPFormState, value: string | boolean | number | UserRole | undefined) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const applyPreset = () => {
    setForm((prev) => ({
      ...prev,
      ldap_url: prev.ldap_url || 'ldaps://ad.example.com:636',
      base_dn: prev.base_dn || 'dc=example,dc=com',
      user_filter: prev.user_filter || '(|(userPrincipalName={identifier})(mail={identifier})(sAMAccountName={identifier})(employeeID={identifier}))',
      principal_attr: prev.principal_attr || 'userPrincipalName',
      email_attr: prev.email_attr || 'mail',
      username_attr: prev.username_attr || 'sAMAccountName',
      employee_id_attr: prev.employee_id_attr || 'employeeID',
      display_name_attr: prev.display_name_attr || 'displayName',
      given_name_attr: prev.given_name_attr || 'givenName',
      family_name_attr: prev.family_name_attr || 'sn',
      group_attr: prev.group_attr || 'memberOf',
    }));
    if (!roleMappingsText.trim()) {
      setRoleMappingsText(DEFAULT_ROLE_MAPPINGS);
    }
  };

  const handleSubmit = async () => {
    setError(null);
    if (!form.name || !form.slug || !form.ldap_url || !form.base_dn) {
      setError('name、slug、ldap_url、base_dn 为必填项');
      return;
    }
    const mappings = parseRoleMappingsInput(roleMappingsText);
    if (!mappings.ok) {
      setError(mappings.error);
      return;
    }

    setIsSaving(true);
    const result = await onSave({
      ...form,
      role_mappings: mappings.value,
      bind_password: form.bind_password?.trim() ? form.bind_password : undefined,
    });
    if (!result.ok) {
      setError(result.error);
    }
    setIsSaving(false);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Building2 className="h-5 w-5" />
          {provider ? '编辑 LDAP/AD 提供商' : '新建 LDAP/AD 提供商'}
        </CardTitle>
        <CardDescription>配置企业目录登录、首登建档、角色映射与定时同步。</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {provider && (
          <Alert variant="info">
            <Settings2 className="h-4 w-4" />
            <AlertDescription>
              上次同步：{formatDateTime(provider.last_sync_at, dateLocale)}；同步状态：{provider.last_sync_status || '—'}
            </AlertDescription>
          </Alert>
        )}

        <div className="space-y-4">
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">基本信息</h3>
            <Button type="button" variant="outline" size="sm" onClick={applyPreset}>
              <Wand2 className="mr-2 h-4 w-4" />
              填充 AD 预设
            </Button>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>名称 *</Label>
              <Input value={form.name || ''} onChange={(e) => updateForm('name', e.target.value)} placeholder="Corporate AD" />
            </div>
            <div className="space-y-2">
              <Label>标识 (Slug) *</Label>
              <Input value={form.slug || ''} onChange={(e) => updateForm('slug', normalizeSlug(e.target.value))} placeholder="corp-ad" disabled={!!provider} />
            </div>
          </div>
          <div className="space-y-2">
            <Label>描述</Label>
            <Input value={form.description || ''} onChange={(e) => updateForm('description', e.target.value)} placeholder="企业目录登录入口" />
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">连接与搜索</h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2 md:col-span-2">
              <Label>LDAP URL *</Label>
              <Input value={form.ldap_url || ''} onChange={(e) => updateForm('ldap_url', e.target.value)} placeholder="ldaps://ad.example.com:636" />
            </div>
            <div className="space-y-2 md:col-span-2">
              <Label>Base DN *</Label>
              <Input value={form.base_dn || ''} onChange={(e) => updateForm('base_dn', e.target.value)} placeholder="dc=example,dc=com" />
            </div>
            <div className="space-y-2">
              <Label>Bind DN</Label>
              <Input value={form.bind_dn || ''} onChange={(e) => updateForm('bind_dn', e.target.value)} placeholder="cn=svc-bind,ou=service,dc=example,dc=com" />
            </div>
            <div className="space-y-2">
              <Label>Bind Password {provider?.bind_password_configured ? '(留空保持现有)' : ''}</Label>
              <Input type="password" value={form.bind_password || ''} onChange={(e) => updateForm('bind_password', e.target.value)} placeholder={provider?.bind_password_configured ? '留空则不修改' : '目录服务账号密码'} />
            </div>
            <div className="space-y-2 md:col-span-2">
              <Label>User Filter</Label>
              <Input
                value={form.user_filter || ''}
                onChange={(e) => updateForm('user_filter', e.target.value)}
                placeholder="(|(userPrincipalName={identifier})(mail={identifier})(sAMAccountName={identifier})(employeeID={identifier}))"
              />
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">属性映射</h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>external_id_attr</Label>
              <Input value={form.external_id_attr || ''} onChange={(e) => updateForm('external_id_attr', e.target.value)} placeholder="dn" />
            </div>
            <div className="space-y-2">
              <Label>principal_attr</Label>
              <Input value={form.principal_attr || ''} onChange={(e) => updateForm('principal_attr', e.target.value)} placeholder="userPrincipalName" />
            </div>
            <div className="space-y-2">
              <Label>email_attr</Label>
              <Input value={form.email_attr || ''} onChange={(e) => updateForm('email_attr', e.target.value)} placeholder="mail" />
            </div>
            <div className="space-y-2">
              <Label>username_attr</Label>
              <Input value={form.username_attr || ''} onChange={(e) => updateForm('username_attr', e.target.value)} placeholder="sAMAccountName" />
            </div>
            <div className="space-y-2">
              <Label>employee_id_attr</Label>
              <Input value={form.employee_id_attr || ''} onChange={(e) => updateForm('employee_id_attr', e.target.value)} placeholder="employeeID" />
            </div>
            <div className="space-y-2">
              <Label>display_name_attr</Label>
              <Input value={form.display_name_attr || ''} onChange={(e) => updateForm('display_name_attr', e.target.value)} placeholder="displayName" />
            </div>
            <div className="space-y-2">
              <Label>given_name_attr</Label>
              <Input value={form.given_name_attr || ''} onChange={(e) => updateForm('given_name_attr', e.target.value)} placeholder="givenName" />
            </div>
            <div className="space-y-2">
              <Label>family_name_attr</Label>
              <Input value={form.family_name_attr || ''} onChange={(e) => updateForm('family_name_attr', e.target.value)} placeholder="sn" />
            </div>
            <div className="space-y-2 md:col-span-2">
              <Label>group_attr</Label>
              <Input value={form.group_attr || ''} onChange={(e) => updateForm('group_attr', e.target.value)} placeholder="memberOf" />
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">角色与同步</h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>default_role</Label>
              <select className="w-full h-10 px-3 rounded-md border border-input bg-background" value={form.default_role || 'user'} onChange={(e) => updateForm('default_role', e.target.value as UserRole)}>
                {ROLE_OPTIONS.map((role) => <option key={role} value={role}>{role}</option>)}
              </select>
            </div>
            <div className="space-y-2">
              <Label>sync_interval_min</Label>
              <Input type="number" min={1} value={String(form.sync_interval_min ?? 60)} onChange={(e) => updateForm('sync_interval_min', Number(e.target.value) || 0)} />
            </div>
            <div className="space-y-2">
              <Label>sync_page_size</Label>
              <Input type="number" min={1} value={String(form.sync_page_size ?? 200)} onChange={(e) => updateForm('sync_page_size', Number(e.target.value) || 0)} />
            </div>
            <div className="space-y-2 md:col-span-2">
              <Label>role_mappings</Label>
              <Textarea value={roleMappingsText} onChange={(e) => setRoleMappingsText(e.target.value)} placeholder={DEFAULT_ROLE_MAPPINGS} className="min-h-[160px] font-mono text-xs" />
              <p className="text-xs text-muted-foreground">使用 JSON 对象，将目录组 DN 或组名映射到本地角色。</p>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">显示配置</h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>icon_url</Label>
              <Input value={form.icon_url || ''} onChange={(e) => updateForm('icon_url', e.target.value)} placeholder="https://example.com/ldap.svg" />
            </div>
            <div className="space-y-2">
              <Label>button_text</Label>
              <Input value={form.button_text || ''} onChange={(e) => updateForm('button_text', e.target.value)} placeholder="使用企业目录登录" />
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">功能开关</h3>
          <div className="grid gap-3 md:grid-cols-2">
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">enabled</p>
                <p className="text-xs text-muted-foreground">控制登录入口是否对用户可见。</p>
              </div>
              <Switch checked={form.enabled ?? false} onCheckedChange={(checked) => updateForm('enabled', checked)} />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">use_starttls</p>
                <p className="text-xs text-muted-foreground">在 ldap:// 连接上升级到 TLS。</p>
              </div>
              <Switch checked={form.use_starttls ?? false} onCheckedChange={(checked) => updateForm('use_starttls', checked)} />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">insecure_skip_verify</p>
                <p className="text-xs text-muted-foreground">仅在受控环境中跳过证书校验。</p>
              </div>
              <Switch checked={form.insecure_skip_verify ?? false} onCheckedChange={(checked) => updateForm('insecure_skip_verify', checked)} />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">auto_create_user</p>
                <p className="text-xs text-muted-foreground">首次目录登录自动创建本地账号。</p>
              </div>
              <Switch checked={form.auto_create_user ?? false} onCheckedChange={(checked) => updateForm('auto_create_user', checked)} />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">trust_email_verified</p>
                <p className="text-xs text-muted-foreground">信任目录侧邮箱已验证状态。</p>
              </div>
              <Switch checked={form.trust_email_verified ?? false} onCheckedChange={(checked) => updateForm('trust_email_verified', checked)} />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">sync_profile</p>
                <p className="text-xs text-muted-foreground">登录时同步目录资料字段。</p>
              </div>
              <Switch checked={form.sync_profile ?? false} onCheckedChange={(checked) => updateForm('sync_profile', checked)} />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3 md:col-span-2">
              <div>
                <p className="font-medium text-sm">sync_enabled</p>
                <p className="text-xs text-muted-foreground">启用后台定时同步，拉取目录状态与组角色。</p>
              </div>
              <Switch checked={form.sync_enabled ?? false} onCheckedChange={(checked) => updateForm('sync_enabled', checked)} />
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-3 border-t pt-4">
          <Button variant="outline" onClick={onCancel}>
            <X className="mr-2 h-4 w-4" />
            取消
          </Button>
          <Button onClick={handleSubmit} disabled={isSaving}>
            {isSaving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Check className="mr-2 h-4 w-4" />}
            {provider ? '更新 LDAP/AD 提供商' : '创建 LDAP/AD 提供商'}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function SAMLProviderForm({
  provider,
  onSave,
  onCancel,
  onRefreshMetadata,
}: {
  provider?: SAMLProviderConfig;
  onSave: (data: SAMLProviderUpdateRequest) => Promise<SaveResult>;
  onCancel: () => void;
  onRefreshMetadata: () => Promise<SaveResult>;
}) {
  const { dateLocale } = useI18n();
  const [form, setForm] = useState<SAMLFormState>(() => ({
    ...DEFAULT_SAML_FORM,
    name: provider?.name || DEFAULT_SAML_FORM.name,
    slug: provider?.slug || DEFAULT_SAML_FORM.slug,
    description: provider?.description || DEFAULT_SAML_FORM.description,
    metadata_url: provider?.metadata_url || DEFAULT_SAML_FORM.metadata_url,
    sp_entity_id: provider?.sp_entity_id || DEFAULT_SAML_FORM.sp_entity_id,
    sign_requests: provider?.sign_requests ?? DEFAULT_SAML_FORM.sign_requests,
    allow_idp_initiated: provider?.allow_idp_initiated ?? DEFAULT_SAML_FORM.allow_idp_initiated,
    default_redirect_path: provider?.default_redirect_path || DEFAULT_SAML_FORM.default_redirect_path,
    name_id_format: provider?.name_id_format || DEFAULT_SAML_FORM.name_id_format,
    email_attribute: provider?.email_attribute || DEFAULT_SAML_FORM.email_attribute,
    username_attribute: provider?.username_attribute || DEFAULT_SAML_FORM.username_attribute,
    employee_id_attribute: provider?.employee_id_attribute || DEFAULT_SAML_FORM.employee_id_attribute,
    display_name_attribute: provider?.display_name_attribute || DEFAULT_SAML_FORM.display_name_attribute,
    given_name_attribute: provider?.given_name_attribute || DEFAULT_SAML_FORM.given_name_attribute,
    family_name_attribute: provider?.family_name_attribute || DEFAULT_SAML_FORM.family_name_attribute,
    group_attribute: provider?.group_attribute || DEFAULT_SAML_FORM.group_attribute,
    role_mappings: provider?.role_mappings,
    default_role: provider?.default_role || DEFAULT_SAML_FORM.default_role,
    enabled: provider?.enabled ?? DEFAULT_SAML_FORM.enabled,
    auto_create_user: provider?.auto_create_user ?? DEFAULT_SAML_FORM.auto_create_user,
    trust_email_verified: provider?.trust_email_verified ?? DEFAULT_SAML_FORM.trust_email_verified,
    sync_profile: provider?.sync_profile ?? DEFAULT_SAML_FORM.sync_profile,
    icon_url: provider?.icon_url || DEFAULT_SAML_FORM.icon_url,
    button_text: provider?.button_text || DEFAULT_SAML_FORM.button_text,
  }));
  const [roleMappingsText, setRoleMappingsText] = useState(() => formatRoleMappingsInput(provider?.role_mappings));
  const [isSaving, setIsSaving] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const updateForm = (field: keyof SAMLFormState, value: string | boolean | UserRole | undefined) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async () => {
    setError(null);
    if (!form.name || !form.slug) {
      setError('name、slug 为必填项');
      return;
    }
    if (form.enabled && !(form.metadata_url?.trim() || form.metadata_xml?.trim())) {
      setError('启用的 SAML provider 必须提供 metadata_url 或 metadata_xml');
      return;
    }
    const mappings = parseRoleMappingsInput(roleMappingsText);
    if (!mappings.ok) {
      setError(mappings.error);
      return;
    }

    setIsSaving(true);
    const result = await onSave({
      ...form,
      role_mappings: mappings.value,
      metadata_xml: form.metadata_xml?.trim() ? form.metadata_xml : undefined,
      certificate_pem: form.certificate_pem?.trim() ? form.certificate_pem : undefined,
      private_key_pem: form.private_key_pem?.trim() ? form.private_key_pem : undefined,
    });
    if (!result.ok) {
      setError(result.error);
    }
    setIsSaving(false);
  };

  const handleRefresh = async () => {
    setError(null);
    setIsRefreshing(true);
    const result = await onRefreshMetadata();
    if (!result.ok) {
      setError(result.error);
    }
    setIsRefreshing(false);
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5" />
              {provider ? '编辑 SAML 2.0 提供商' : '新建 SAML 2.0 提供商'}
            </CardTitle>
            <CardDescription>配置 IdP 元数据、断言属性映射、SP 发起与 IdP 发起登录。</CardDescription>
          </div>
          {provider && (
            <Button type="button" variant="outline" size="sm" onClick={handleRefresh} disabled={isRefreshing}>
              {isRefreshing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              刷新 Metadata
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {provider && (
          <div className="grid gap-3 md:grid-cols-3">
            <Alert variant="info">
              <Settings2 className="h-4 w-4" />
              <AlertDescription>Metadata 拉取：{formatDateTime(provider.metadata_fetched_at, dateLocale)}</AlertDescription>
            </Alert>
            <Alert variant={provider.metadata_xml_configured ? 'success' : 'warning'}>
              <ShieldCheck className="h-4 w-4" />
              <AlertDescription>Metadata XML：{provider.metadata_xml_configured ? '已配置' : '未配置'}</AlertDescription>
            </Alert>
            <Alert variant={provider.certificate_configured && provider.private_key_configured ? 'success' : 'warning'}>
              <Check className="h-4 w-4" />
              <AlertDescription>SP 证书/私钥：{provider.certificate_configured && provider.private_key_configured ? '已配置' : '待补充'}</AlertDescription>
            </Alert>
          </div>
        )}

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">基本信息</h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>名称 *</Label>
              <Input value={form.name || ''} onChange={(e) => updateForm('name', e.target.value)} placeholder="Okta Workforce" />
            </div>
            <div className="space-y-2">
              <Label>标识 (Slug) *</Label>
              <Input value={form.slug || ''} onChange={(e) => updateForm('slug', normalizeSlug(e.target.value))} placeholder="okta-workforce" disabled={!!provider} />
            </div>
          </div>
          <div className="space-y-2">
            <Label>描述</Label>
            <Input value={form.description || ''} onChange={(e) => updateForm('description', e.target.value)} placeholder="企业 SAML 登录入口" />
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">Metadata 与 SP 配置</h3>
          <div className="space-y-2">
            <Label>metadata_url</Label>
            <Input value={form.metadata_url || ''} onChange={(e) => updateForm('metadata_url', e.target.value)} placeholder="https://idp.example.com/metadata" />
          </div>
          <div className="space-y-2">
            <Label>metadata_xml</Label>
            <Textarea value={form.metadata_xml || ''} onChange={(e) => updateForm('metadata_xml', e.target.value)} placeholder="<EntityDescriptor>...</EntityDescriptor>" className="min-h-[180px] font-mono text-xs" />
            <p className="text-xs text-muted-foreground">填写后后端会立即解析并仅保存配置状态，不会在 safe DTO 中回传 XML 明文。</p>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>sp_entity_id</Label>
              <Input value={form.sp_entity_id || ''} onChange={(e) => updateForm('sp_entity_id', e.target.value)} placeholder="留空使用后端 metadata 路径" />
            </div>
            <div className="space-y-2">
              <Label>default_redirect_path</Label>
              <Input value={form.default_redirect_path || ''} onChange={(e) => updateForm('default_redirect_path', e.target.value)} placeholder="/dashboard" />
            </div>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>certificate_pem {provider?.certificate_configured ? '(留空保持现有)' : ''}</Label>
              <Textarea value={form.certificate_pem || ''} onChange={(e) => updateForm('certificate_pem', e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" className="min-h-[140px] font-mono text-xs" />
            </div>
            <div className="space-y-2">
              <Label>private_key_pem {provider?.private_key_configured ? '(留空保持现有)' : ''}</Label>
              <Textarea value={form.private_key_pem || ''} onChange={(e) => updateForm('private_key_pem', e.target.value)} placeholder="-----BEGIN RSA PRIVATE KEY-----" className="min-h-[140px] font-mono text-xs" />
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">断言属性映射</h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>name_id_format</Label>
              <Input value={form.name_id_format || ''} onChange={(e) => updateForm('name_id_format', e.target.value)} placeholder="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" />
            </div>
            <div className="space-y-2">
              <Label>email_attribute</Label>
              <Input value={form.email_attribute || ''} onChange={(e) => updateForm('email_attribute', e.target.value)} placeholder="mail" />
            </div>
            <div className="space-y-2">
              <Label>username_attribute</Label>
              <Input value={form.username_attribute || ''} onChange={(e) => updateForm('username_attribute', e.target.value)} placeholder="uid" />
            </div>
            <div className="space-y-2">
              <Label>employee_id_attribute</Label>
              <Input value={form.employee_id_attribute || ''} onChange={(e) => updateForm('employee_id_attribute', e.target.value)} placeholder="employeeID" />
            </div>
            <div className="space-y-2">
              <Label>display_name_attribute</Label>
              <Input value={form.display_name_attribute || ''} onChange={(e) => updateForm('display_name_attribute', e.target.value)} placeholder="displayName" />
            </div>
            <div className="space-y-2">
              <Label>given_name_attribute</Label>
              <Input value={form.given_name_attribute || ''} onChange={(e) => updateForm('given_name_attribute', e.target.value)} placeholder="givenName" />
            </div>
            <div className="space-y-2">
              <Label>family_name_attribute</Label>
              <Input value={form.family_name_attribute || ''} onChange={(e) => updateForm('family_name_attribute', e.target.value)} placeholder="sn" />
            </div>
            <div className="space-y-2">
              <Label>group_attribute</Label>
              <Input value={form.group_attribute || ''} onChange={(e) => updateForm('group_attribute', e.target.value)} placeholder="memberOf" />
            </div>
            <div className="space-y-2">
              <Label>default_role</Label>
              <select className="w-full h-10 px-3 rounded-md border border-input bg-background" value={form.default_role || 'user'} onChange={(e) => updateForm('default_role', e.target.value as UserRole)}>
                {ROLE_OPTIONS.map((role) => <option key={role} value={role}>{role}</option>)}
              </select>
            </div>
            <div className="space-y-2 md:col-span-2">
              <Label>role_mappings</Label>
              <Textarea value={roleMappingsText} onChange={(e) => setRoleMappingsText(e.target.value)} placeholder={DEFAULT_ROLE_MAPPINGS} className="min-h-[160px] font-mono text-xs" />
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">显示配置</h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>icon_url</Label>
              <Input value={form.icon_url || ''} onChange={(e) => updateForm('icon_url', e.target.value)} placeholder="https://example.com/saml.svg" />
            </div>
            <div className="space-y-2">
              <Label>button_text</Label>
              <Input value={form.button_text || ''} onChange={(e) => updateForm('button_text', e.target.value)} placeholder="使用 SAML 登录" />
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">功能开关</h3>
          <div className="grid gap-3 md:grid-cols-2">
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">enabled</p>
                <p className="text-xs text-muted-foreground">控制 SAML 登录入口是否对外开放。</p>
              </div>
              <Switch checked={form.enabled ?? false} onCheckedChange={(checked) => updateForm('enabled', checked)} />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">sign_requests</p>
                <p className="text-xs text-muted-foreground">由 SP 对 AuthnRequest 进行签名。</p>
              </div>
              <Switch checked={form.sign_requests ?? false} onCheckedChange={(checked) => updateForm('sign_requests', checked)} />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">allow_idp_initiated</p>
                <p className="text-xs text-muted-foreground">允许 IdP 发起登录直接进入 ACS。</p>
              </div>
              <Switch checked={form.allow_idp_initiated ?? false} onCheckedChange={(checked) => updateForm('allow_idp_initiated', checked)} />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">auto_create_user</p>
                <p className="text-xs text-muted-foreground">首次断言登录自动创建本地用户。</p>
              </div>
              <Switch checked={form.auto_create_user ?? false} onCheckedChange={(checked) => updateForm('auto_create_user', checked)} />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">trust_email_verified</p>
                <p className="text-xs text-muted-foreground">信任断言中的邮箱已验证状态。</p>
              </div>
              <Switch checked={form.trust_email_verified ?? false} onCheckedChange={(checked) => updateForm('trust_email_verified', checked)} />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <p className="font-medium text-sm">sync_profile</p>
                <p className="text-xs text-muted-foreground">登录时用断言属性同步用户资料。</p>
              </div>
              <Switch checked={form.sync_profile ?? false} onCheckedChange={(checked) => updateForm('sync_profile', checked)} />
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-3 border-t pt-4">
          <Button variant="outline" onClick={onCancel}>
            <X className="mr-2 h-4 w-4" />
            取消
          </Button>
          <Button onClick={handleSubmit} disabled={isSaving}>
            {isSaving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Check className="mr-2 h-4 w-4" />}
            {provider ? '更新 SAML 提供商' : '创建 SAML 提供商'}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function DeleteProviderDialog({
  open,
  provider,
  onOpenChange,
  onConfirm,
}: {
  open: boolean;
  provider: ProviderRecord | null;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => Promise<void>;
}) {
  const [isDeleting, setIsDeleting] = useState(false);

  const handleConfirm = async () => {
    setIsDeleting(true);
    await onConfirm();
    setIsDeleting(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>确认删除提供商</DialogTitle>
          <DialogDescription>
            {provider ? `即将删除 ${provider.data.name}。该操作会移除对应登录入口，请确认没有用户仍依赖此提供商。` : '请选择要删除的提供商。'}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isDeleting}>取消</Button>
          <Button variant="destructive" onClick={handleConfirm} disabled={isDeleting || !provider}>
            {isDeleting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="mr-2 h-4 w-4" />}
            删除
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function FederationPage() {
  const { user } = useAuth();
  const { t, dateLocale } = useI18n();
  const [activeTab, setActiveTab] = useState<ProviderKind>('oidc');
  const [oidcProviders, setOIDCProviders] = useState<FederationProvider[]>([]);
  const [ldapProviders, setLDAPProviders] = useState<LDAPProviderConfig[]>([]);
  const [samlProviders, setSAMLProviders] = useState<SAMLProviderConfig[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingProvider, setEditingProvider] = useState<ProviderRecord | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ProviderRecord | null>(null);
  const [message, setMessage] = useState<MessageState>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const currentProviders = useMemo(() => {
    if (activeTab === 'ldap') return ldapProviders;
    if (activeTab === 'saml') return samlProviders;
    return oidcProviders;
  }, [activeTab, ldapProviders, oidcProviders, samlProviders]);

  const currentEditingProvider = editingProvider?.kind === activeTab ? editingProvider.data : undefined;

  const flashMessage = useCallback((next: MessageState) => {
    setMessage(next);
    if (next) {
      setTimeout(() => setMessage(null), 3500);
    }
  }, []);

  const copyToClipboard = async (value: string) => {
    if (!value) return;
    await navigator.clipboard.writeText(value);
    setCopiedText(value);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const loadProviders = useCallback(async () => {
    setIsLoading(true);
    const [oidcRes, ldapRes, samlRes] = await Promise.all([
      api.getAdminFederationProviders(),
      api.getAdminLDAPProviders(),
      api.getAdminSAMLProviders(),
    ]);

    if (oidcRes.success && oidcRes.data) {
      setOIDCProviders(oidcRes.data.providers || []);
    }
    if (ldapRes.success && ldapRes.data) {
      setLDAPProviders(ldapRes.data.providers || []);
    }
    if (samlRes.success && samlRes.data) {
      setSAMLProviders(samlRes.data.providers || []);
    }
    if (!oidcRes.success && !ldapRes.success && !samlRes.success) {
      flashMessage({ type: 'error', text: oidcRes.error?.message || ldapRes.error?.message || samlRes.error?.message || '加载提供商失败' });
    }
    setIsLoading(false);
  }, [flashMessage]);

  useEffect(() => {
    if (user?.role === 'admin') {
      void loadProviders();
    } else if (user?.role === 'user') {
      setIsLoading(false);
    }
  }, [loadProviders, user]);

  if (user?.role !== 'admin') {
    return (
      <div className="flex items-center justify-center py-12">
        <p className="text-muted-foreground">{t('common.noAccess')}</p>
      </div>
    );
  }

  const resetFormState = () => {
    setShowForm(false);
    setEditingProvider(null);
  };

  const handleOIDCSave = async (data: CreateFederationProviderRequest): Promise<SaveResult> => {
    const response = editingProvider?.kind === 'oidc'
      ? await api.updateFederationProvider(editingProvider.data.id, data)
      : await api.createFederationProvider(data);
    if (!response.success) {
      return { ok: false, error: response.error?.message || (editingProvider ? t('admin.federation.updateFailed') : t('admin.federation.createFailed')) };
    }
    resetFormState();
    await loadProviders();
    flashMessage({ type: 'success', text: editingProvider ? 'OIDC 提供商已更新' : 'OIDC 提供商已创建' });
    return { ok: true };
  };

  const handleLDAPSave = async (data: LDAPProviderUpdateRequest): Promise<SaveResult> => {
    const response = editingProvider?.kind === 'ldap'
      ? await api.updateLDAPProvider(editingProvider.data.id, data)
      : await api.createLDAPProvider(data);
    if (!response.success) {
      return { ok: false, error: response.error?.message || (editingProvider ? '更新 LDAP/AD 提供商失败' : '创建 LDAP/AD 提供商失败') };
    }
    resetFormState();
    await loadProviders();
    flashMessage({ type: 'success', text: editingProvider ? 'LDAP/AD 提供商已更新' : 'LDAP/AD 提供商已创建' });
    return { ok: true };
  };

  const handleSAMLSave = async (data: SAMLProviderUpdateRequest): Promise<SaveResult> => {
    const response = editingProvider?.kind === 'saml'
      ? await api.updateSAMLProvider(editingProvider.data.id, data)
      : await api.createSAMLProvider(data);
    if (!response.success) {
      return { ok: false, error: response.error?.message || (editingProvider ? '更新 SAML 提供商失败' : '创建 SAML 提供商失败') };
    }
    resetFormState();
    await loadProviders();
    flashMessage({ type: 'success', text: editingProvider ? 'SAML 提供商已更新' : 'SAML 提供商已创建' });
    return { ok: true };
  };

  const handleRefreshSAMLMetadata = async (): Promise<SaveResult> => {
    if (editingProvider?.kind !== 'saml') {
      return { ok: false, error: '当前未选中 SAML 提供商' };
    }
    const response = await api.refreshSAMLMetadata(editingProvider.data.id);
    if (!response.success) {
      return { ok: false, error: response.error?.message || '刷新 Metadata 失败' };
    }
    await loadProviders();
    flashMessage({ type: 'success', text: 'SAML Metadata 已刷新' });
    return { ok: true };
  };

  const openCreateForm = (kind: ProviderKind) => {
    setActiveTab(kind);
    setEditingProvider(null);
    setShowForm(true);
  };

  const openEditForm = (provider: ProviderRecord) => {
    setActiveTab(provider.kind);
    setEditingProvider(provider);
    setShowForm(true);
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    let success = false;
    if (deleteTarget.kind === 'oidc') {
      const res = await api.deleteFederationProvider(deleteTarget.data.id);
      success = res.success;
      if (!res.success) flashMessage({ type: 'error', text: res.error?.message || '删除 OIDC 提供商失败' });
    }
    if (deleteTarget.kind === 'ldap') {
      const res = await api.deleteLDAPProvider(deleteTarget.data.id);
      success = res.success;
      if (!res.success) flashMessage({ type: 'error', text: res.error?.message || '删除 LDAP/AD 提供商失败' });
    }
    if (deleteTarget.kind === 'saml') {
      const res = await api.deleteSAMLProvider(deleteTarget.data.id);
      success = res.success;
      if (!res.success) flashMessage({ type: 'error', text: res.error?.message || '删除 SAML 提供商失败' });
    }
    if (success) {
      setDeleteTarget(null);
      await loadProviders();
      flashMessage({ type: 'success', text: '提供商已删除' });
    }
  };

  if (showForm) {
    return (
      <div className="max-w-5xl mx-auto space-y-6">
        <PageHeader
          icon={activeTab === 'ldap' ? Building2 : activeTab === 'saml' ? ShieldCheck : Globe}
          title={activeTab === 'ldap' ? (editingProvider ? '编辑 LDAP/AD 提供商' : '新建 LDAP/AD 提供商') : activeTab === 'saml' ? (editingProvider ? '编辑 SAML 提供商' : '新建 SAML 提供商') : (editingProvider ? t('admin.federation.editProvider') : t('admin.federation.addProviderTitle'))}
          description={activeTab === 'ldap' ? '管理企业目录连接、属性映射与同步策略。' : activeTab === 'saml' ? '管理 Metadata、断言映射与 SSO 行为。' : t('admin.federation.editPageDesc')}
        />

        {activeTab === 'oidc' && (
          <OIDCProviderForm provider={currentEditingProvider as FederationProvider | undefined} onSave={handleOIDCSave} onCancel={resetFormState} />
        )}
        {activeTab === 'ldap' && (
          <LDAPProviderForm provider={currentEditingProvider as LDAPProviderConfig | undefined} onSave={handleLDAPSave} onCancel={resetFormState} />
        )}
        {activeTab === 'saml' && (
          <SAMLProviderForm provider={currentEditingProvider as SAMLProviderConfig | undefined} onSave={handleSAMLSave} onCancel={resetFormState} onRefreshMetadata={handleRefreshSAMLMetadata} />
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Globe}
        title={t('admin.federation.title')}
        description="统一管理 OIDC、LDAP/AD 与 SAML 2.0 登录提供商。"
        actions={
          <div className="flex flex-wrap items-center gap-2 justify-end">
            <Button variant="outline" onClick={() => loadProviders()} disabled={isLoading}>
              {isLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              刷新
            </Button>
            <Button variant="outline" onClick={() => openCreateForm(activeTab)}>
              <Plus className="mr-2 h-4 w-4" />
              {activeTab === 'ldap' ? '新建 LDAP/AD' : activeTab === 'saml' ? '新建 SAML' : t('admin.federation.addProvider')}
            </Button>
          </div>
        }
      />

      {message && (
        <Alert variant={message.type === 'error' ? 'destructive' : 'success'}>
          {message.type === 'error' ? <AlertCircle className="h-4 w-4" /> : <Check className="h-4 w-4" />}
          <AlertDescription>{message.text}</AlertDescription>
        </Alert>
      )}

      <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as ProviderKind)} className="space-y-4">
        <TabsList className="flex w-full overflow-x-auto">
          <TabsTrigger value="oidc" className="flex-1 min-w-0 gap-2">
            <Globe className="h-4 w-4" />
            OIDC / OAuth2
            <Badge variant="secondary" className="ml-1 hidden sm:inline-flex">{oidcProviders.length}</Badge>
          </TabsTrigger>
          <TabsTrigger value="ldap" className="flex-1 min-w-0 gap-2">
            <Building2 className="h-4 w-4" />
            LDAP / AD
            <Badge variant="info" className="ml-1 hidden sm:inline-flex">{ldapProviders.length}</Badge>
          </TabsTrigger>
          <TabsTrigger value="saml" className="flex-1 min-w-0 gap-2">
            <ShieldCheck className="h-4 w-4" />
            SAML 2.0
            <Badge variant="warning" className="ml-1 hidden sm:inline-flex">{samlProviders.length}</Badge>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="oidc" className="space-y-4 mt-0">
          <Card>
            <CardContent className="pt-6">
              <div className="grid gap-4 md:grid-cols-3">
                <div className="rounded-lg border p-4">
                  <p className="text-sm text-muted-foreground">启用中的 OIDC 提供商</p>
                  <p className="mt-2 text-2xl font-semibold">{oidcProviders.filter((item) => item.enabled).length}</p>
                </div>
                <div className="rounded-lg border p-4">
                  <p className="text-sm text-muted-foreground">自动建档</p>
                  <p className="mt-2 text-2xl font-semibold">{oidcProviders.filter((item) => item.auto_create_user).length}</p>
                </div>
                <div className="rounded-lg border p-4">
                  <p className="text-sm text-muted-foreground">同步资料</p>
                  <p className="mt-2 text-2xl font-semibold">{oidcProviders.filter((item) => item.sync_profile).length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="ldap" className="space-y-4 mt-0">
          <Card>
            <CardContent className="pt-6">
              <div className="grid gap-4 md:grid-cols-4">
                <div className="rounded-lg border p-4">
                  <p className="text-sm text-muted-foreground">启用中的目录</p>
                  <p className="mt-2 text-2xl font-semibold">{ldapProviders.filter((item) => item.enabled).length}</p>
                </div>
                <div className="rounded-lg border p-4">
                  <p className="text-sm text-muted-foreground">启用同步</p>
                  <p className="mt-2 text-2xl font-semibold">{ldapProviders.filter((item) => item.sync_enabled).length}</p>
                </div>
                <div className="rounded-lg border p-4">
                  <p className="text-sm text-muted-foreground">信任邮箱验证</p>
                  <p className="mt-2 text-2xl font-semibold">{ldapProviders.filter((item) => item.trust_email_verified).length}</p>
                </div>
                <div className="rounded-lg border p-4">
                  <p className="text-sm text-muted-foreground">最近同步成功</p>
                  <p className="mt-2 text-sm font-medium">{ldapProviders.find((item) => item.last_sync_at)?.name || '—'}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="saml" className="space-y-4 mt-0">
          <Card>
            <CardContent className="pt-6">
              <div className="grid gap-4 md:grid-cols-4">
                <div className="rounded-lg border p-4">
                  <p className="text-sm text-muted-foreground">启用中的 SAML 提供商</p>
                  <p className="mt-2 text-2xl font-semibold">{samlProviders.filter((item) => item.enabled).length}</p>
                </div>
                <div className="rounded-lg border p-4">
                  <p className="text-sm text-muted-foreground">允许 IdP 发起</p>
                  <p className="mt-2 text-2xl font-semibold">{samlProviders.filter((item) => item.allow_idp_initiated).length}</p>
                </div>
                <div className="rounded-lg border p-4">
                  <p className="text-sm text-muted-foreground">已加载 Metadata</p>
                  <p className="mt-2 text-2xl font-semibold">{samlProviders.filter((item) => item.metadata_xml_configured).length}</p>
                </div>
                <div className="rounded-lg border p-4">
                  <p className="text-sm text-muted-foreground">SP 证书齐备</p>
                  <p className="mt-2 text-2xl font-semibold">{samlProviders.filter((item) => item.certificate_configured && item.private_key_configured).length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {isLoading ? (
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => (
            <Card key={i}>
              <CardContent className="p-6">
                <div className="flex items-center gap-4">
                  <Skeleton className="h-12 w-12 rounded-lg" />
                  <div className="flex-1">
                    <Skeleton className="h-5 w-40 mb-2" />
                    <Skeleton className="h-4 w-64" />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : currentProviders.length === 0 ? (
        <Card>
          <CardContent className="py-12">
            <EmptyState
              icon={activeTab === 'ldap' ? Building2 : activeTab === 'saml' ? ShieldCheck : Globe}
              title={activeTab === 'ldap' ? '暂无 LDAP/AD 提供商' : activeTab === 'saml' ? '暂无 SAML 提供商' : t('admin.federation.noProviders')}
              description={activeTab === 'ldap' ? '添加企业目录提供商以支持账号密码登录、角色映射和定时同步。' : activeTab === 'saml' ? '添加 SAML IdP 以支持 SP 发起与 IdP 发起登录。' : t('admin.federation.noProvidersDesc')}
              action={{
                label: activeTab === 'ldap' ? '添加 LDAP/AD 提供商' : activeTab === 'saml' ? '添加 SAML 提供商' : t('admin.federation.addProvider'),
                onClick: () => openCreateForm(activeTab),
              }}
            />
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {currentProviders.map((item) => {
            const record: ProviderRecord = activeTab === 'ldap'
              ? { kind: 'ldap', data: item as LDAPProviderConfig }
              : activeTab === 'saml'
                ? { kind: 'saml', data: item as SAMLProviderConfig }
                : { kind: 'oidc', data: item as FederationProvider };
            const iconSlug = inferProviderIcon(record.kind, record.data.slug);

            return (
              <Card key={record.data.id} className="transition-shadow hover:shadow-md">
                <CardContent className="p-6">
                  <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                    <div className="flex items-start gap-4 min-w-0 flex-1">
                      <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10 shrink-0">
                        {record.data.icon_url ? (
                          <img src={record.data.icon_url} alt={record.data.name} className="h-7 w-7" />
                        ) : (
                          <ProviderIcon slug={iconSlug} className="h-6 w-6 text-primary" />
                        )}
                      </div>
                      <div className="min-w-0 flex-1 space-y-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <h3 className="font-semibold truncate">{record.data.name}</h3>
                          <Badge variant={record.data.enabled ? 'default' : 'secondary'}>{record.data.enabled ? t('common.enabled') : t('common.disabled')}</Badge>
                          <ProviderTypeBadge kind={record.kind} />
                          {'auto_create_user' in record.data && record.data.auto_create_user && <Badge variant="outline">自动建档</Badge>}
                          {'sync_profile' in record.data && record.data.sync_profile && <Badge variant="outline">同步资料</Badge>}
                          {record.kind === 'ldap' && record.data.sync_enabled && <Badge variant="info">定时同步</Badge>}
                          {record.kind === 'saml' && record.data.allow_idp_initiated && <Badge variant="warning">IdP 发起</Badge>}
                        </div>
                        <p className="text-sm text-muted-foreground break-all">{record.data.description || record.data.slug}</p>

                        <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                          <span>Slug: <code className="rounded bg-muted px-1">{record.data.slug}</code></span>
                          {record.kind === 'oidc' && <span>Client ID: <code className="rounded bg-muted px-1">{(record.data.client_id || '').slice(0, 24)}{record.data.client_id.length > 24 ? '…' : ''}</code></span>}
                          {record.kind === 'ldap' && <span>LDAP URL: <code className="rounded bg-muted px-1">{record.data.ldap_url}</code></span>}
                          {record.kind === 'saml' && <span>Entity ID: <code className="rounded bg-muted px-1">{record.data.sp_entity_id || '自动生成'}</code></span>}
                        </div>

                        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3 text-xs">
                          {record.kind === 'oidc' && (
                            <>
                              <div className="rounded-lg border p-3">
                                <p className="text-muted-foreground">授权端点</p>
                                <p className="mt-1 break-all font-medium">{record.data.auth_url}</p>
                              </div>
                              <div className="rounded-lg border p-3">
                                <p className="text-muted-foreground">Token 端点</p>
                                <p className="mt-1 break-all font-medium">{record.data.token_url}</p>
                              </div>
                              <div className="rounded-lg border p-3">
                                <p className="text-muted-foreground">Scopes</p>
                                <p className="mt-1 break-all font-medium">{record.data.scopes || '—'}</p>
                              </div>
                            </>
                          )}
                          {record.kind === 'ldap' && (
                            <>
                              <div className="rounded-lg border p-3">
                                <p className="text-muted-foreground">Base DN</p>
                                <p className="mt-1 break-all font-medium">{record.data.base_dn}</p>
                              </div>
                              <div className="rounded-lg border p-3">
                                <p className="text-muted-foreground">Bind Password</p>
                                <p className="mt-1 font-medium">{record.data.bind_password_configured ? '已配置' : '未配置'}</p>
                              </div>
                              <div className="rounded-lg border p-3">
                                <p className="text-muted-foreground">上次同步</p>
                                <p className="mt-1 font-medium">{formatDateTime(record.data.last_sync_at, dateLocale)}</p>
                              </div>
                            </>
                          )}
                          {record.kind === 'saml' && (
                            <>
                              <div className="rounded-lg border p-3">
                                <p className="text-muted-foreground">Metadata</p>
                                <p className="mt-1 font-medium">{record.data.metadata_xml_configured ? '已加载' : '未加载'}</p>
                              </div>
                              <div className="rounded-lg border p-3">
                                <p className="text-muted-foreground">证书/私钥</p>
                                <p className="mt-1 font-medium">{record.data.certificate_configured && record.data.private_key_configured ? '已配置' : '待补充'}</p>
                              </div>
                              <div className="rounded-lg border p-3">
                                <p className="text-muted-foreground">Metadata 拉取时间</p>
                                <p className="mt-1 font-medium">{formatDateTime(record.data.metadata_fetched_at, dateLocale)}</p>
                              </div>
                            </>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      {record.kind === 'saml' && record.data.sp_entity_id && (
                        <Button variant="ghost" size="sm" onClick={() => copyToClipboard(record.data.sp_entity_id || '')}>
                          {copiedText === record.data.sp_entity_id ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                        </Button>
                      )}
                      {record.kind === 'oidc' && record.data.auth_url && (
                        <Button variant="ghost" size="sm" onClick={() => window.open(record.data.auth_url, '_blank', 'noopener,noreferrer')}>
                          <ExternalLink className="h-4 w-4" />
                        </Button>
                      )}
                      {record.kind === 'ldap' && record.data.ldap_url && (
                        <Button variant="ghost" size="sm" onClick={() => copyToClipboard(record.data.ldap_url)}>
                          {copiedText === record.data.ldap_url ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                        </Button>
                      )}
                      <Button variant="ghost" size="sm" onClick={() => openEditForm(record)}>
                        <Settings2 className="h-4 w-4" />
                      </Button>
                      <Button variant="ghost" size="sm" className="text-red-500 hover:text-red-600" onClick={() => setDeleteTarget(record)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      <DeleteProviderDialog open={!!deleteTarget} provider={deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)} onConfirm={handleDelete} />
    </div>
  );
}

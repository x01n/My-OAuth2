/** SSE / 实时事件类型 → i18n 键（admin.events.*） */
export const AUTH_EVENT_I18N_KEYS: Record<string, string> = {
  user_registered: 'userRegistered',
  user_login: 'userLogin',
  user_updated: 'userUpdated',
  oauth_authorized: 'oauthAuthorized',
  oauth_revoked: 'oauthRevoked',
  device_authorized: 'deviceAuthorized',
  token_issued: 'tokenIssued',
  token_refreshed: 'tokenRefreshed',
};

export function getAuthEventLabel(
  t: (key: string, params?: Record<string, string>) => string,
  eventType: string
): string {
  const key = AUTH_EVENT_I18N_KEYS[eventType];
  if (key) {
    return t(`admin.events.${key}`);
  }
  return t('admin.events.unknownEvent', { type: eventType });
}

export function authEventShowsUser(eventType: string): boolean {
  return eventType === 'user_registered' ||
    eventType === 'user_login' ||
    eventType === 'user_updated' ||
    eventType === 'oauth_authorized' ||
    eventType === 'oauth_revoked' ||
    eventType === 'device_authorized' ||
    eventType === 'token_issued' ||
    eventType === 'token_refreshed';
}

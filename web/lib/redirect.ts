const DEFAULT_RETURN_PATH = '/dashboard';

export function safeReturnPath(raw: string | null | undefined): string {
  if (!raw || /[\r\n\t]/.test(raw)) return DEFAULT_RETURN_PATH;

  try {
    const parsed = new URL(raw, window.location.origin);
    if (parsed.origin !== window.location.origin) return DEFAULT_RETURN_PATH;
    if (!raw.startsWith('/') || raw.startsWith('//')) return DEFAULT_RETURN_PATH;
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return DEFAULT_RETURN_PATH;
  }
}

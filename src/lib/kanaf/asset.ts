import { previewPathPrefix } from "@/lib/preview-path-prefix";

/** Keep static fetches on the preview prefix the proxy expects. */
export function assetUrl(path: string): string {
  const normalized = path.startsWith("/") ? path : `/${path}`;
  if (typeof window === "undefined") return normalized;
  const prefix = previewPathPrefix(window.location.hostname, window.location.pathname);
  return prefix ? `${prefix}${normalized}` : normalized;
}

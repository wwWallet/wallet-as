type Display = {
  name?: string;
  description?: string;
  locale?: string;
  logo?: { uri?: string };
  background_color?: string;
  text_color?: string;
  background_image?: { uri?: string };
  [k: string]: unknown;
};

export function getCredentialDisplayByScope(
  metadata: any,
  scope: string
): Display[] | null {
  if (!metadata?.credential_configurations_supported) return null;

  for (const cfg of Object.values<any>(metadata.credential_configurations_supported)) {
    if (cfg?.scope === scope) {
      return Array.isArray(cfg.display) ? (cfg.display as Display[]) : null;
    }
  }
  return null;
}
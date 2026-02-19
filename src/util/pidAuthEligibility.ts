const PID_AUTH_BLOCKED_SCOPES = new Set(["pid:sd_jwt_dc", "pid:mso_mdoc"]);

export function isPidAuthAllowed(scopeParam: string | undefined | null): boolean {
  if (!scopeParam) {
    return true;
  }
  const scopes = scopeParam.split(" ").map((s) => s.trim()).filter(Boolean);
  return !scopes.some((scope) => PID_AUTH_BLOCKED_SCOPES.has(scope));
}

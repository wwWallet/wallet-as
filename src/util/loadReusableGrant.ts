export async function loadReusableGrant(
  ctx: any,
  grantReuseWindowSeconds: number,
  now = Math.floor(Date.now() / 1000)
) {
  if (!ctx?.oidc?.session || !ctx?.oidc?.client) {
    return undefined;
  }

  const grantId =
    ctx.oidc.result?.consent?.grantId ||
    ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId);

  if (!grantId) {
    return undefined;
  }

  const grant = await ctx.oidc.provider.Grant.find(grantId);
  if (!grant || typeof grant.iat !== "number") {
    return undefined;
  }

  const age = now - grant.iat;
  if (age > grantReuseWindowSeconds) {
    return undefined;
  }

  return grant;
}

import { describe, expect, it, vi } from "vitest";
import { loadReusableGrant } from "../src/util/loadReusableGrant";

function buildContext(options: {
  grantId?: string;
  consentGrantId?: string;
  grant?: any;
}) {
  const grantIdFor = vi.fn().mockReturnValue(options.grantId);
  const find = vi.fn().mockResolvedValue(options.grant);

  return {
    ctx: {
      oidc: {
        result: options.consentGrantId
          ? { consent: { grantId: options.consentGrantId } }
          : undefined,
        session: { grantIdFor },
        client: { clientId: "client-1" },
        provider: { Grant: { find } },
      },
    },
    find,
    grantIdFor,
  };
}

describe("loadReusableGrant", () => {
  it("returns grant when age is within the configured window", async () => {
    const grant = { iat: 1000 };
    const { ctx } = buildContext({ grantId: "grant-1", grant });

    const result = await loadReusableGrant(ctx, 15, 1015);
    expect(result).toBe(grant);
  });

  it("returns undefined when age exceeds configured window", async () => {
    const grant = { iat: 1000 };
    const { ctx } = buildContext({ grantId: "grant-1", grant });

    const result = await loadReusableGrant(ctx, 15, 1016);
    expect(result).toBeUndefined();
  });

  it("returns undefined when grant does not include iat", async () => {
    const { ctx } = buildContext({ grantId: "grant-1", grant: {} });

    const result = await loadReusableGrant(ctx, 15, 1010);
    expect(result).toBeUndefined();
  });
});

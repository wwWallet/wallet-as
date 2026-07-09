const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..", "node_modules", "oidc-provider", "lib");

function patch(relativePath, marker, replacements) {
  const filename = path.join(root, relativePath);
  let source = fs.readFileSync(filename, "utf8");

  if (source.includes(marker)) {
    console.log(`[oidc-provider-attestation-no-iss] already patched ${relativePath}`);
    return;
  }

  for (const [needle, replacement] of replacements) {
    if (!source.includes(needle)) {
      throw new Error(`[oidc-provider-attestation-no-iss] could not find patch point in ${relativePath}: ${needle}`);
    }
    source = source.replace(needle, replacement);
  }

  fs.writeFileSync(filename, source);
  console.log(`[oidc-provider-attestation-no-iss] patched ${relativePath}`);
}

patch(
  "shared/attest_client_auth.js",
  "const attester = typeof payload.iss === 'string' ? payload.iss : payload.sub;",
  [
    [
      "const payload = jose.decodeJwt(attestation);\n        if (typeof payload.iss !== 'string') {\n          throw new Error('iss must be a string');\n        }\n        const key = await attestClientAuth.getAttestationSignaturePublicKey(\n          ctx,\n          payload.iss,\n          header,\n          ctx.oidc.client,\n        );",
      "const payload = jose.decodeJwt(attestation);\n        const attester = typeof payload.iss === 'string' ? payload.iss : payload.sub;\n        if (typeof attester !== 'string') {\n          throw new Error('sub must be a string when iss is omitted');\n        }\n        const key = await attestClientAuth.getAttestationSignaturePublicKey(\n          ctx,\n          attester,\n          header,\n          ctx.oidc.client,\n        );",
    ],
    [
      "requiredClaims: ['iss', 'sub', 'exp', 'cnf'],",
      "requiredClaims: ['sub', 'exp', 'cnf'],",
    ],
  ],
);

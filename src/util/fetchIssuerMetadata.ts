import axios from 'axios';

/**
 * Fetches OpenID Credential Issuer metadata from the issuer's well-known endpoint.
 * @param issuerUrl The base URL of the credential issuer (e.g., https://issuer.example.com)
 * @returns The issuer metadata as a JSON object
 */
export async function fetchIssuerMetadata(issuerUrl: string) {
  const wellKnownUrl = `${issuerUrl.replace(/\/$/, '')}/.well-known/openid-credential-issuer`;
  try {
    const response = await axios.get(wellKnownUrl, {
      headers: {
        'Accept': 'application/json',
      },
    });
    return response.data;
  } catch (error) {
    console.error(`Failed to fetch issuer metadata from ${wellKnownUrl}:`, error);
    throw error;
  }
}

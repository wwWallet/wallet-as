import axios from 'axios';

/**
 * Fetches OpenID Credential Issuer metadata from the issuer's well-known endpoint.
 * @param metadataUrl The metadata URL of the credential issuer (e.g., https://issuer.example.com/openid/.well-known/openid-credential-issuer)
 * @returns The issuer metadata as a JSON object
 */
export async function fetchIssuerMetadata(metadataUrl: string) {
  try {
    const response = await axios.get(metadataUrl, {
      headers: {
        'Accept': 'application/json',
      },
    });
    return response.data;
  } catch (error) {
    console.error(`Failed to fetch issuer metadata from ${metadataUrl}:`, error);
    throw error;
  }
}

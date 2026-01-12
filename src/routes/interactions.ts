import Express from "express";
import Provider from "oidc-provider";
import IAccountSource from "../interfaces/IAccountSource";
import { fetchIssuerMetadata } from '../util/fetchIssuerMetadata';
import { getCredentialDisplayByScope } from '../util/getCredentialDisplayByScope';

export default (app: Express.Application, provider: Provider, AccountSource: IAccountSource) => {
  app.get('/interaction/:uid', async (req, res, next) => {
      try {
        const {
          uid, prompt, params, session,
        } = await provider.interactionDetails(req, res);

        const client = await provider.Client.find(params.client_id as string);
        console.log(uid, prompt, params, session, client)
        let issuerMetadata: any = null;
        let credentialConfigs: Array<{scope: string, display: any}> = [];
        if (prompt.name === 'consent') {
          const issuerUrl = process.env.ISSUER_URL;
          if (issuerUrl) {
            try {
              issuerMetadata = await fetchIssuerMetadata(issuerUrl);
              console.log('Issuer Metadata:', issuerMetadata);
              if (issuerMetadata) {
                credentialConfigs = (params.scope as string).split(' ').map((scope: string) => {
                  return {
                    scope,
                    display: getCredentialDisplayByScope(issuerMetadata, scope)
                  };
                });
              }
            } catch (err) {
              console.error('Could not fetch issuer metadata:', err);
            }
          }
        }
        switch (prompt.name) {
          case 'login': {
            return res.render('login', {
              client,
              uid,
              details: prompt.details,
              params,
            });
          }
          case 'consent': {
            return res.render('consent', {
              client,
              uid,
              details: prompt.details,
              params,
              credentialConfigs
            });
          }
          default:
            return undefined;
        }
      } catch (err) {
        return next(err);
      }
    });

  app.post('/interaction/:uid/login', async (req, res, next) => {
    try {
      const interaction = await provider.interactionDetails(req, res);
      if (interaction.prompt.name !== 'login') {
        return res.sendStatus(404);
      }
      const account = await AccountSource.authenticate(req.body.login, req.body.password);

      if (!account) {
        const client = await provider.Client.find(interaction.params.client_id as string);
        return res.status(401).render('login', {
          client,
          uid: interaction.uid,
          details: interaction.prompt.details,
          params: interaction.params,
          error: 'Invalid credentials',
          login: req.body.login,
        });
      }

      const result = {
        login: {
          accountId: account.sub,
          remember: false
        },
      };

      await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
      next(err);
    }
  });

  app.post('/interaction/:uid/confirm', async (req, res, next) => {
      try {
        const interaction = await provider.interactionDetails(req, res);
        const {
          prompt: { name },
          params,
          session,
          grantId: existingGrantId,
        } = interaction;

        if (name !== 'consent') {
          return res.sendStatus(404);
        }

        const accountId = (session as any)?.accountId as string | undefined;
        if (!accountId) {
          return res.sendStatus(400);
        }

        const details = (interaction.prompt.details || {}) as any;
        let grantId = existingGrantId;
        let grant = grantId ? await provider.Grant.find(grantId) : undefined;

        const isNewGrant = !grant;
        if (!grant) {
          // establish a new grant if none exists or if lookup failed
          grant = new provider.Grant({
            accountId,
            clientId: params.client_id as string,
          });
        }

        if (details.missingOIDCScope) {
          grant.addOIDCScope(details.missingOIDCScope.join(' '));
        }
        if (details.missingOIDCClaims) {
          grant.addOIDCClaims(details.missingOIDCClaims);
        }
        const missingResourceScopes = details.missingResourceScopes as Record<string, string[]> | undefined;
        if (missingResourceScopes) {
          for (const [indicator, scopes] of Object.entries(missingResourceScopes)) {
            grant.addResourceScope(indicator, (scopes as string[]).join(' '));
          }
        }

        grantId = await grant.save();

        const consent: { grantId?: string } = {};
        if (isNewGrant) {
          // we don't have to pass grantId to consent when modifying an existing one
          consent.grantId = grantId;
        }

        const result = { consent };
        await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
      } catch (err) {
        next(err);
      }
    });

    app.post('/interaction/:uid/abort', async (req, res, next) => {
      try {
        const result = {
          error: 'access_denied',
          error_description: 'End-User aborted interaction',
        };
        await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
      } catch (err) {
        next(err);
      }
    });
}

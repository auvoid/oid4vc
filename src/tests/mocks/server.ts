import express from 'express';
import { Server } from 'http';
import { issuer, rp } from './openid';
import { presentationDefinition } from './presentation-defs';
import { credentials } from './keys.mock';
import 'express-async-errors';

export const requestsMap = new Map<string, string>();
export const offersMap = new Map<string, Record<string, any>>();
let server: Server;

export function startServer(port = 5999) {
    const app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.route('/siop/:id').get(async (req, res) => {
        res.send(requestsMap.get(req.params.id));
    });
    app.route('/.well-known/openid-credential-issuer').get(async (req, res) => {
        const metadata = issuer.getIssuerMetadata();
        res.json(metadata);
    });

    app.route('/.well-known/oauth-authorization-server').get(
        async (req, res) => {
            const metadata = issuer.getOauthServerMetadata();
            res.json(metadata);
        },
    );

    app.route('/token').post(async (req, res) => {
        const response = await issuer.createTokenResponse(req.body);
        res.json(response);
    });

    app.route('/api/credential').post(async (req, res) => {
        await issuer.validateCredentialsResponse({
            token: req.headers.authorization?.split('Bearer ')[1],
            proof: req.body.proof.jwt,
        });
        const response = await issuer.createSendCredentialsResponse({
            credentials: credentials,
            format: 'jwt_vc_json',
        });
        res.json(response);
    });

    app.route('/api/offers/:id').get(async (req, res) => {
        res.json(offersMap.get(req.params.id));
    });

    app.route('/api/credentials').post(async (req, res) => {
        await issuer.validateCredentialsResponse({
            token: req.headers.authorization?.split('Bearer ')[1],
            proof: req.body.credential_requests[0].proof.jwt,
        });
        const response = await issuer.createSendCredentialsResponse({
            credentials: [...credentials, ...credentials],
            format: 'jwt_vc_json',
        });
        res.json(response);
    });

    app.route('/api/auth').post(async (req, res) => {
        await rp.verifyAuthResponse(req.body, presentationDefinition);
        res.status(204).send();
    });
    server = app.listen(port);
}

export function stopServer() {
    server.close();
}

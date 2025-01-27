import {
    externalHolder,
    externalIssuer,
    externalOp,
    externalRp,
    holder,
    issuer,
    op,
    rp,
} from './mocks/openid';
import { startServer, stopServer } from './mocks/server';
import { oid4vciSuite } from './suites/oid4vci.suite';
import { oid4vpSuite } from './suites/oid4vp.suite';
import { siopSuite } from './suites/siop.suite';

beforeAll(() => {
    startServer();
});

afterAll(() => {
    stopServer();
});

describe('SIOPv2', siopSuite(op, rp));
describe('OpenID4VP', oid4vpSuite(op, rp));
describe('OpenID4VCI', oid4vciSuite(holder, issuer));
describe('SIOPv2: EXTERNAL', siopSuite(externalOp, externalRp));
describe('OpenID4VP: EXTERNAL', oid4vpSuite(externalOp, externalRp));
describe('OpenID4VCI: EXTERNAL', oid4vciSuite(externalHolder, externalIssuer));

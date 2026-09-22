import type { Consumer } from './consumers';
import {
  apiResourcePolicy,
  consumerConfigKeyPolicy,
  policiesEqual,
  roleInvokePolicy,
  roleTrustPolicy,
  secretResourcePolicy,
} from './policies';

const api = {
  region: 'eu-west-2',
  accountId: '542403648748',
  restApiId: 'abc123',
};

const flex: Consumer = {
  name: 'flex',
  accountId: '308036881389',
  permissions: ['read', 'write', 'delete'],
  rateLimit: 20,
  burstLimit: 10,
  vpcEndpointId: 'vpce-0fda65abeaa732a68',
};
const gdsuns: Consumer = {
  ...flex,
  name: 'gdsuns',
  accountId: '674663567518',
  vpcEndpointId: 'vpce-0f7de3952cb0bc5c1',
};

// The documents below are copied from the synthesised dev-main template
// produced by the CDK constructs this reconciler replaces. Adoption is only
// safe if the reconciler considers them equal to what it would write.
describe('equivalence with CDK-produced policies', () => {
  it('API resource policy (as returned by API Gateway)', () => {
    const cdk = {
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Condition: {
            StringNotEquals: {
              'aws:sourceVpce': [
                'vpce-own0000000000000',
                'vpce-0fda65abeaa732a68',
                'vpce-0f7de3952cb0bc5c1',
              ],
            },
          },
          Effect: 'Deny',
          Principal: '*',
          Resource: 'arn:aws:execute-api:eu-west-2:542403648748:abc123/*',
        },
        {
          Action: 'execute-api:Invoke',
          Condition: {
            StringEquals: {
              'aws:sourceVpce': [
                'vpce-own0000000000000',
                'vpce-0fda65abeaa732a68',
                'vpce-0f7de3952cb0bc5c1',
              ],
            },
          },
          Effect: 'Allow',
          Principal: '*',
          Resource: 'arn:aws:execute-api:eu-west-2:542403648748:abc123/*',
        },
      ],
      Version: '2012-10-17',
    };
    // API Gateway escapes quotes and slashes in the returned policy string.
    const returned = JSON.stringify(cdk)
      .replace(/"/g, '\\"')
      .replace(/\//g, '\\/');

    const desired = apiResourcePolicy({
      ...api,
      ownVpcEndpointId: 'vpce-own0000000000000',
      consumers: [gdsuns, flex],
      crossAccountPrincipals: [],
    });

    expect(policiesEqual(returned, desired, api)).toBe(true);
  });

  it('API resource policy written with the CDK "execute-api/*" shorthand', () => {
    const shorthand = apiResourcePolicy({
      ...api,
      ownVpcEndpointId: 'vpce-own0000000000000',
      consumers: [flex],
      crossAccountPrincipals: [],
    });
    shorthand.Statement.forEach((s) => (s.Resource = 'execute-api/*'));

    const desired = apiResourcePolicy({
      ...api,
      ownVpcEndpointId: 'vpce-own0000000000000',
      consumers: [flex],
      crossAccountPrincipals: [],
    });

    expect(policiesEqual(shorthand, desired, api)).toBe(true);
  });

  it('consumer config KMS key policy', () => {
    const cdk = JSON.stringify({
      Statement: [
        {
          Action: 'kms:*',
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::542403648748:root' },
          Resource: '*',
        },
        {
          Action: ['kms:Decrypt', 'kms:DescribeKey'],
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::308036881389:root' },
          Resource: '*',
          Sid: 'AllowDecryptForFLEX',
        },
        {
          Action: [
            'kms:CreateGrant',
            'kms:Decrypt',
            'kms:DescribeKey',
            'kms:Encrypt',
            'kms:GenerateDataKey*',
            'kms:ReEncrypt*',
          ],
          Condition: {
            StringEquals: {
              'kms:ViaService': 'secretsmanager.eu-west-2.amazonaws.com',
            },
          },
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::542403648748:root' },
          Resource: '*',
        },
        {
          Action: ['kms:Decrypt', 'kms:DescribeKey'],
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::674663567518:root' },
          Resource: '*',
          Sid: 'AllowDecryptForGDSUNS',
        },
      ],
      Version: '2012-10-17',
    });

    const desired = consumerConfigKeyPolicy({
      ...api,
      consumers: [flex, gdsuns],
    });

    expect(policiesEqual(cdk, desired)).toBe(true);
  });

  it('role trust policy (URL-encoded, as returned by IAM)', () => {
    const cdk = encodeURIComponent(
      JSON.stringify({
        Statement: [
          {
            Action: 'sts:AssumeRole',
            Effect: 'Allow',
            Principal: { AWS: 'arn:aws:iam::308036881389:root' },
          },
        ],
        Version: '2012-10-17',
      }),
    );

    expect(policiesEqual(cdk, roleTrustPolicy(flex))).toBe(true);
  });

  it('role invoke policy', () => {
    const arn = (m: string) =>
      `arn:aws:execute-api:eu-west-2:542403648748:abc123/*/${m}/*`;
    const cdk = {
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: ['DELETE', 'GET', 'PATCH', 'POST', 'PUT'].map(arn),
          Sid: 'AllowApiGatewayInvoke',
        },
      ],
      Version: '2012-10-17',
    };

    expect(
      policiesEqual(
        encodeURIComponent(JSON.stringify(cdk)),
        roleInvokePolicy({ ...api, permissions: flex.permissions }),
      ),
    ).toBe(true);
  });

  it('secret resource policy', () => {
    const cdk = JSON.stringify({
      Statement: [
        {
          Action: 'secretsmanager:GetSecretValue',
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::308036881389:root' },
          Resource: '*',
          Sid: 'AllowCrossAccountReadFLEX',
        },
      ],
      Version: '2012-10-17',
    });

    expect(policiesEqual(cdk, secretResourcePolicy(flex))).toBe(true);
  });
});

describe('drift detection', () => {
  const base = {
    ...api,
    ownVpcEndpointId: 'vpce-own0000000000000',
    crossAccountPrincipals: [],
  };

  it('detects a consumer VPC endpoint being added', () => {
    expect(
      policiesEqual(
        apiResourcePolicy({ ...base, consumers: [flex] }),
        apiResourcePolicy({ ...base, consumers: [flex, gdsuns] }),
        api,
      ),
    ).toBe(false);
  });

  it('detects an externalId being added to a trust policy', () => {
    expect(
      policiesEqual(
        roleTrustPolicy(flex),
        roleTrustPolicy({ ...flex, externalId: 'x1' }),
      ),
    ).toBe(false);
  });

  it('detects narrowed permissions', () => {
    expect(
      policiesEqual(
        roleInvokePolicy({ ...api, permissions: ['read', 'write'] }),
        roleInvokePolicy({ ...api, permissions: ['read'] }),
      ),
    ).toBe(false);
  });

  it('always keeps account administration on the KMS key', () => {
    const policy = consumerConfigKeyPolicy({ ...api, consumers: [] });

    expect(policy.Statement[0]).toMatchObject({
      Effect: 'Allow',
      Principal: { AWS: 'arn:aws:iam::542403648748:root' },
      Action: 'kms:*',
    });
  });

  it('adds a cross-account principal allow when configured', () => {
    const policy = apiResourcePolicy({
      ...base,
      consumers: [],
      crossAccountPrincipals: ['111111111111'],
    });

    expect(policy.Statement).toHaveLength(3);
    expect(policy.Statement[2].Principal).toEqual({
      AWS: ['arn:aws:iam::111111111111:root'],
    });
  });
});

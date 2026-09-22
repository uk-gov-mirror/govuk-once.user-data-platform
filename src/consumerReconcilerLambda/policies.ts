// Pure builders for every policy document and secret payload the reconciler
// owns. The shapes deliberately mirror what the CDK constructs produced
// (iam-consumer-construct, consumer-config-construct, api-gateway-construct)
// so that adopting resources created by CloudFormation is a no-op.

import type { Consumer, Permission } from './consumers';

export interface PolicyStatement {
  Sid?: string;
  Effect: 'Allow' | 'Deny';
  Principal?: '*' | Record<string, string | string[]>;
  Action: string | string[];
  Resource?: string | string[];
  Condition?: Record<string, Record<string, string | string[]>>;
}

export interface PolicyDocument {
  Version: '2012-10-17';
  Statement: PolicyStatement[];
}

const accountRoot = (accountId: string) => `arn:aws:iam::${accountId}:root`;

const PERMISSIONS_TO_METHODS: Record<Permission, string[]> = {
  read: ['GET'],
  write: ['POST', 'PUT', 'PATCH'],
  delete: ['DELETE'],
};

export interface ApiContext {
  region: string;
  accountId: string;
  restApiId: string;
}

export const executeApiArn = ({ region, accountId, restApiId }: ApiContext) =>
  `arn:aws:execute-api:${region}:${accountId}:${restApiId}`;

export function apiResourcePolicy(
  api: ApiContext & {
    ownVpcEndpointId: string;
    consumers: Consumer[];
    crossAccountPrincipals: string[];
  },
): PolicyDocument {
  const resource = `${executeApiArn(api)}/*`;
  const allowedVpces = [
    ...new Set([
      api.ownVpcEndpointId,
      ...api.consumers
        .map((c) => c.vpcEndpointId)
        .filter((id): id is string => !!id),
    ]),
  ];

  const statements: PolicyStatement[] = [
    {
      Effect: 'Deny',
      Principal: { AWS: '*' },
      Action: 'execute-api:Invoke',
      Resource: resource,
      Condition: { StringNotEquals: { 'aws:sourceVpce': allowedVpces } },
    },
    {
      Effect: 'Allow',
      Principal: { AWS: '*' },
      Action: 'execute-api:Invoke',
      Resource: resource,
      Condition: { StringEquals: { 'aws:sourceVpce': allowedVpces } },
    },
  ];

  if (api.crossAccountPrincipals.length > 0) {
    statements.push({
      Effect: 'Allow',
      Principal: { AWS: api.crossAccountPrincipals.map(accountRoot) },
      Action: 'execute-api:Invoke',
      Resource: resource,
      Condition: { StringEquals: { 'aws:sourceVpce': allowedVpces } },
    });
  }

  return { Version: '2012-10-17', Statement: statements };
}

export function consumerConfigKeyPolicy({
  region,
  accountId,
  consumers,
}: {
  region: string;
  accountId: string;
  consumers: Consumer[];
}): PolicyDocument {
  return {
    Version: '2012-10-17',
    Statement: [
      // Never removed: guarantees the account can always administer the key,
      // so a bad reconcile cannot lock the key.
      {
        Effect: 'Allow',
        Principal: { AWS: accountRoot(accountId) },
        Action: 'kms:*',
        Resource: '*',
      },
      {
        Effect: 'Allow',
        Principal: { AWS: accountRoot(accountId) },
        Action: [
          'kms:CreateGrant',
          'kms:Decrypt',
          'kms:DescribeKey',
          'kms:Encrypt',
          'kms:GenerateDataKey*',
          'kms:ReEncrypt*',
        ],
        Resource: '*',
        Condition: {
          StringEquals: {
            'kms:ViaService': `secretsmanager.${region}.amazonaws.com`,
          },
        },
      },
      ...consumers.map(
        (c): PolicyStatement => ({
          Sid: `AllowDecryptFor${c.name.toUpperCase()}`,
          Effect: 'Allow',
          Principal: { AWS: accountRoot(c.accountId) },
          Action: ['kms:Decrypt', 'kms:DescribeKey'],
          Resource: '*',
        }),
      ),
    ],
  };
}

export function roleTrustPolicy(consumer: Consumer): PolicyDocument {
  const statement: PolicyStatement = {
    Effect: 'Allow',
    Principal: { AWS: accountRoot(consumer.accountId) },
    Action: 'sts:AssumeRole',
  };
  if (consumer.externalId) {
    statement.Condition = {
      StringEquals: { 'sts:ExternalId': consumer.externalId },
    };
  }
  return { Version: '2012-10-17', Statement: [statement] };
}

export function roleInvokePolicy(
  api: ApiContext & { permissions: Permission[] },
): PolicyDocument {
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'AllowApiGatewayInvoke',
        Effect: 'Allow',
        Action: 'execute-api:Invoke',
        Resource: api.permissions
          .flatMap((p) => PERMISSIONS_TO_METHODS[p])
          .map((method) => `${executeApiArn(api)}/*/${method}/*`),
      },
    ],
  };
}

export function roleDescription(consumer: Consumer, environment: string) {
  // Matches the CDK default (including its double space) so adoption is a no-op.
  return (
    consumer.description ||
    `API Consumer role for  ${consumer.name} = ${environment}`
  );
}

export function secretResourcePolicy(consumer: Consumer): PolicyDocument {
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: `AllowCrossAccountRead${consumer.name.toUpperCase()}`,
        Effect: 'Allow',
        Principal: { AWS: accountRoot(consumer.accountId) },
        Action: 'secretsmanager:GetSecretValue',
        Resource: '*',
      },
    ],
  };
}

export function consumerSecretValue({
  region,
  accountId,
  apiUrl,
  consumerRoleArn,
  externalId,
  apiKey,
}: {
  region: string;
  accountId: string;
  apiUrl: string;
  consumerRoleArn: string;
  externalId?: string;
  apiKey?: string;
}): Record<string, string> {
  return {
    region,
    apiAccountId: accountId,
    apiUrl,
    consumerRoleArn,
    ...(externalId ? { externalId } : {}),
    ...(apiKey ? { apiKey } : {}),
  };
}

// ---------------------------------------------------------------------------
// Comparison
//
// AWS services hand policies back in slightly different shapes from what was
// written (URL-encoded, "*" vs {"AWS":"*"}, scalar vs single-item array,
// expanded execute-api resources, reordered statements). Normalise both sides
// into a canonical form so only semantic differences count as drift. Sids are
// ignored: they carry no access meaning.
// ---------------------------------------------------------------------------

type Json = Record<string, unknown>;

const toSortedArray = (v: unknown, map: (s: string) => string = (s) => s) =>
  [...new Set((Array.isArray(v) ? v : [v]).map((x) => map(String(x))))].sort();

export function parsePolicy(
  raw: string | PolicyDocument | undefined,
): Json | undefined {
  if (raw === undefined || raw === '') return undefined;
  if (typeof raw !== 'string') return raw as unknown as Json;

  const candidates = [raw];
  if (raw.startsWith('%7B')) candidates.push(decodeURIComponent(raw));
  // API Gateway returns the policy with escaped quotes and slashes.
  candidates.push(raw.replace(/\\"/g, '"').replace(/\\\//g, '/'));

  for (const candidate of candidates) {
    try {
      return JSON.parse(candidate) as Json;
    } catch {
      // try the next representation
    }
  }
  throw new Error(`Unable to parse policy document: ${raw.slice(0, 200)}`);
}

export function normalizePolicy(
  raw: string | PolicyDocument | undefined,
  api?: ApiContext,
): string {
  const doc = parsePolicy(raw);
  if (!doc) return '';

  const mapResource = (r: string) => {
    const match = api && /^execute-api:?\/(.*)$/.exec(r);
    return match && api ? `${executeApiArn(api)}/${match[1]}` : r;
  };

  const mapPrincipal = (p: unknown) => {
    if (p === undefined) return undefined;
    const obj = p === '*' ? { AWS: '*' } : (p as Json);
    return Object.fromEntries(
      Object.entries(obj)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [
          k,
          toSortedArray(v, (s) => (/^\d{12}$/.test(s) ? accountRoot(s) : s)),
        ]),
    );
  };

  const mapCondition = (c: unknown) => {
    if (!c) return undefined;
    return Object.fromEntries(
      Object.entries(c as Json)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([op, block]) => [
          op,
          Object.fromEntries(
            Object.entries(block as Json)
              .map(([k, v]) => [k.toLowerCase(), toSortedArray(v)] as const)
              .sort(([a], [b]) => a.localeCompare(b)),
          ),
        ]),
    );
  };

  const statements = toArray(doc.Statement).map((s) => {
    const st = s as Json;
    return JSON.stringify({
      Effect: st.Effect,
      Principal: mapPrincipal(st.Principal),
      NotPrincipal: mapPrincipal(st.NotPrincipal),
      Action: st.Action && toSortedArray(st.Action, (a) => a.toLowerCase()),
      NotAction:
        st.NotAction && toSortedArray(st.NotAction, (a) => a.toLowerCase()),
      Resource: st.Resource && toSortedArray(st.Resource, mapResource),
      NotResource: st.NotResource && toSortedArray(st.NotResource, mapResource),
      Condition: mapCondition(st.Condition),
    });
  });

  return JSON.stringify([...new Set(statements)].sort());
}

const toArray = (v: unknown): unknown[] =>
  v === undefined ? [] : Array.isArray(v) ? v : [v];

export function policiesEqual(
  a: string | PolicyDocument | undefined,
  b: string | PolicyDocument | undefined,
  api?: ApiContext,
): boolean {
  return normalizePolicy(a, api) === normalizePolicy(b, api);
}

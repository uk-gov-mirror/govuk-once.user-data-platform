// Converges live AWS state onto the consumers declared in SSM.
//
// Every write goes through `ctx.change()`, which records what would change and
// only performs it when running in apply mode. In dry-run mode the reconciler
// reads everything and reports the plan without writing anything.
//
// Resources are found by their deterministic names (the same names the CDK
// constructs used), which is how resources originally created by
// CloudFormation are adopted without being replaced: role ARNs, secret ARNs,
// the KMS key ARN and API key values all stay the same.

import {
  CreateRoleCommand,
  DeleteRolePolicyCommand,
  GetRoleCommand,
  GetRolePolicyCommand,
  IAMClient,
  ListRolePoliciesCommand,
  PutRolePermissionsBoundaryCommand,
  PutRolePolicyCommand,
  UpdateAssumeRolePolicyCommand,
  UpdateRoleCommand,
  type Role,
} from '@aws-sdk/client-iam';
import {
  APIGatewayClient,
  CreateApiKeyCommand,
  CreateDeploymentCommand,
  CreateUsagePlanCommand,
  CreateUsagePlanKeyCommand,
  GetApiKeysCommand,
  GetRestApiCommand,
  GetUsagePlanKeysCommand,
  GetUsagePlansCommand,
  UpdateApiKeyCommand,
  UpdateRestApiCommand,
  UpdateUsagePlanCommand,
  type ApiKey,
  type UsagePlan,
} from '@aws-sdk/client-api-gateway';
import {
  CreateAliasCommand,
  CreateKeyCommand,
  DescribeKeyCommand,
  EnableKeyRotationCommand,
  GetKeyPolicyCommand,
  KMSClient,
  PutKeyPolicyCommand,
} from '@aws-sdk/client-kms';
import {
  CreateSecretCommand,
  DeleteResourcePolicyCommand,
  DescribeSecretCommand,
  GetResourcePolicyCommand,
  GetSecretValueCommand,
  ListSecretsCommand,
  PutResourcePolicyCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager';
import { GetParametersByPathCommand, SSMClient } from '@aws-sdk/client-ssm';

import type { Consumer, RawConsumerParam } from './consumers';
import {
  apiResourcePolicy,
  consumerConfigKeyPolicy,
  consumerSecretValue,
  policiesEqual,
  roleDescription,
  roleInvokePolicy,
  roleTrustPolicy,
  secretResourcePolicy,
  type ApiContext,
} from './policies';

export const INLINE_POLICY_NAME = 'api-invoke';

export interface ReconcilerConfig extends ApiContext {
  environment: string;
  /** e.g. "prod" or "pr-12-dev"; prefixes role, API key and usage plan names */
  resourcePrefix: string;
  /** e.g. "/udp/prod"; prefixes secret names and the KMS alias */
  secretPathPrefix: string;
  consumerParamPath: string;
  stageName: string;
  apiUrl: string;
  ownVpcEndpointId: string;
  crossAccountPrincipals: string[];
  permissionsBoundaryArn: string;
  tags: Record<string, string>;
}

export interface Clients {
  iam: IAMClient;
  apigw: APIGatewayClient;
  kms: KMSClient;
  secrets: SecretsManagerClient;
  ssm: SSMClient;
}

export type Impact = 'access' | 'housekeeping';

export interface Change {
  resource: string;
  action: string;
  /** access = changes who can reach what; housekeeping = no effect on access */
  impact: Impact;
}

export class ReconcileContext {
  readonly changes: Change[] = [];
  readonly warnings: string[] = [];

  constructor(readonly apply: boolean) {}

  async change(
    resource: string,
    action: string,
    impact: Impact,
    write: () => Promise<unknown>,
  ): Promise<void> {
    this.changes.push({ resource, action, impact });
    if (this.apply) await write();
  }
}

// Placeholders stand in for values that only exist once a resource has been
// created; they can only ever appear in a dry-run plan.
const PENDING = (what: string) => `<pending:${what}>`;

const nameOf = (err: unknown) => (err as { name?: string })?.name;

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

export const roleName = (cfg: ReconcilerConfig, consumer: string) =>
  `${cfg.resourcePrefix}-consumer-${consumer}-role`;
export const apiKeyName = (cfg: ReconcilerConfig, consumer: string) =>
  `${cfg.resourcePrefix}-${consumer}-key`;
export const usagePlanName = (cfg: ReconcilerConfig, consumer: string) =>
  `${cfg.resourcePrefix}-${consumer}-usage-plan`;
export const secretName = (cfg: ReconcilerConfig, consumer: string) =>
  `${cfg.secretPathPrefix}/consumers/${consumer}/config`;
export const keyAlias = (cfg: ReconcilerConfig) =>
  `alias/${cfg.secretPathPrefix}-consumer-config`;

// ---------------------------------------------------------------------------
// SSM
// ---------------------------------------------------------------------------

export async function readConsumerParams(
  clients: Clients,
  cfg: ReconcilerConfig,
): Promise<RawConsumerParam[]> {
  // No trailing slash: SSM authorises GetParametersByPath against the exact
  // path passed, which must match the IAM grant.
  const path = cfg.consumerParamPath.replace(/\/+$/, '');
  const params: RawConsumerParam[] = [];
  let NextToken: string | undefined;

  do {
    const res = await clients.ssm.send(
      new GetParametersByPathCommand({
        Path: path,
        Recursive: false,
        WithDecryption: false,
        NextToken,
      }),
    );
    for (const p of res.Parameters ?? []) {
      if (!p.Name?.startsWith(`${path}/`)) continue;
      params.push({
        name: p.Name.slice(path.length + 1),
        value: p.Value ?? '',
      });
    }
    NextToken = res.NextToken;
  } while (NextToken);

  return params;
}

// ---------------------------------------------------------------------------
// KMS
// ---------------------------------------------------------------------------

export async function ensureConsumerConfigKey(
  ctx: ReconcileContext,
  clients: Clients,
  cfg: ReconcilerConfig,
  consumers: Consumer[],
): Promise<string> {
  const alias = keyAlias(cfg);
  const policy = consumerConfigKeyPolicy({ ...cfg, consumers });

  let keyArn: string | undefined;
  try {
    const res = await clients.kms.send(
      new DescribeKeyCommand({ KeyId: alias }),
    );
    keyArn = res.KeyMetadata?.Arn;
  } catch (err) {
    if (nameOf(err) !== 'NotFoundException') throw err;
  }

  if (!keyArn) {
    let created = PENDING('kms-key');
    if (consumers.length === 0) return created;
    await ctx.change(alias, 'create key', 'access', async () => {
      const res = await clients.kms.send(
        new CreateKeyCommand({
          Description: `Encrypts external consumer config secrets (${cfg.environment})`,
          Policy: JSON.stringify(policy),
          Tags: Object.entries(cfg.tags).map(([TagKey, TagValue]) => ({
            TagKey,
            TagValue,
          })),
        }),
      );
      created = res.KeyMetadata!.Arn!;
      await clients.kms.send(
        new CreateAliasCommand({ AliasName: alias, TargetKeyId: created }),
      );
      await clients.kms.send(new EnableKeyRotationCommand({ KeyId: created }));
    });
    return created;
  }

  const current = await clients.kms.send(
    new GetKeyPolicyCommand({ KeyId: keyArn, PolicyName: 'default' }),
  );
  if (!policiesEqual(current.Policy, policy)) {
    await ctx.change(alias, 'update key policy', 'access', () =>
      clients.kms.send(
        new PutKeyPolicyCommand({
          KeyId: keyArn,
          PolicyName: 'default',
          Policy: JSON.stringify(policy),
        }),
      ),
    );
  }

  return keyArn;
}

// ---------------------------------------------------------------------------
// IAM
// ---------------------------------------------------------------------------

export async function ensureConsumerRole(
  ctx: ReconcileContext,
  clients: Clients,
  cfg: ReconcilerConfig,
  consumer: Consumer,
): Promise<string> {
  const RoleName = roleName(cfg, consumer.name);
  const trust = roleTrustPolicy(consumer);
  const invoke = roleInvokePolicy({
    ...cfg,
    permissions: consumer.permissions,
  });
  const Description = roleDescription(consumer, cfg.environment);

  let role: Role | undefined;
  try {
    role = (await clients.iam.send(new GetRoleCommand({ RoleName }))).Role;
  } catch (err) {
    if (
      nameOf(err) !== 'NoSuchEntity' &&
      nameOf(err) !== 'NoSuchEntityException'
    )
      throw err;
  }

  if (!role) {
    await ctx.change(RoleName, 'create role', 'access', async () => {
      await clients.iam.send(
        new CreateRoleCommand({
          RoleName,
          Description,
          AssumeRolePolicyDocument: JSON.stringify(trust),
          PermissionsBoundary: cfg.permissionsBoundaryArn,
          Tags: Object.entries(cfg.tags).map(([Key, Value]) => ({
            Key,
            Value,
          })),
        }),
      );
      await clients.iam.send(
        new PutRolePolicyCommand({
          RoleName,
          PolicyName: INLINE_POLICY_NAME,
          PolicyDocument: JSON.stringify(invoke),
        }),
      );
    });
    return `arn:aws:iam::${cfg.accountId}:role/${RoleName}`;
  }

  // The boundary must be in place before any inline policy write: the
  // reconciler's own IAM permissions only allow policy writes on roles that
  // carry this boundary.
  if (
    role.PermissionsBoundary?.PermissionsBoundaryArn !==
    cfg.permissionsBoundaryArn
  ) {
    await ctx.change(RoleName, 'set permissions boundary', 'housekeeping', () =>
      clients.iam.send(
        new PutRolePermissionsBoundaryCommand({
          RoleName,
          PermissionsBoundary: cfg.permissionsBoundaryArn,
        }),
      ),
    );
  }

  if (!policiesEqual(role.AssumeRolePolicyDocument, trust)) {
    await ctx.change(RoleName, 'update trust policy', 'access', () =>
      clients.iam.send(
        new UpdateAssumeRolePolicyCommand({
          RoleName,
          PolicyDocument: JSON.stringify(trust),
        }),
      ),
    );
  }

  if ((role.Description ?? '') !== Description) {
    await ctx.change(RoleName, 'update description', 'housekeeping', () =>
      clients.iam.send(new UpdateRoleCommand({ RoleName, Description })),
    );
  }

  await ensureInlinePolicy(ctx, clients, RoleName, invoke);

  return role.Arn!;
}

async function ensureInlinePolicy(
  ctx: ReconcileContext,
  clients: Clients,
  RoleName: string,
  desired: ReturnType<typeof roleInvokePolicy>,
): Promise<void> {
  const names: string[] = [];
  let Marker: string | undefined;
  do {
    const res = await clients.iam.send(
      new ListRolePoliciesCommand({ RoleName, Marker }),
    );
    names.push(...(res.PolicyNames ?? []));
    Marker = res.IsTruncated ? res.Marker : undefined;
  } while (Marker);

  const documents = new Map<string, string | undefined>();
  for (const PolicyName of names) {
    const res = await clients.iam.send(
      new GetRolePolicyCommand({ RoleName, PolicyName }),
    );
    documents.set(PolicyName, res.PolicyDocument);
  }

  // Roles adopted from CloudFormation carry a single CDK-named policy
  // (e.g. IamConsumersConsumerRoleflexDefaultPolicyB02EA1C7). If it already
  // grants exactly the desired access, leave it alone rather than churn it.
  if (names.length === 1 && policiesEqual(documents.get(names[0]), desired)) {
    return;
  }

  const current = documents.get(INLINE_POLICY_NAME);
  if (!current || !policiesEqual(current, desired)) {
    await ctx.change(
      RoleName,
      `put inline policy ${INLINE_POLICY_NAME}`,
      'access',
      () =>
        clients.iam.send(
          new PutRolePolicyCommand({
            RoleName,
            PolicyName: INLINE_POLICY_NAME,
            PolicyDocument: JSON.stringify(desired),
          }),
        ),
    );
  }

  // Only now that the desired policy is in place, remove anything else so
  // the role grants exactly what the SSM declaration says.
  for (const PolicyName of names.filter((n) => n !== INLINE_POLICY_NAME)) {
    await ctx.change(
      RoleName,
      `delete inline policy ${PolicyName}`,
      'access',
      () =>
        clients.iam.send(new DeleteRolePolicyCommand({ RoleName, PolicyName })),
    );
  }
}

// ---------------------------------------------------------------------------
// API Gateway: API keys and usage plans
// ---------------------------------------------------------------------------

async function findApiKey(
  clients: Clients,
  name: string,
): Promise<ApiKey | undefined> {
  const matches: ApiKey[] = [];
  let position: string | undefined;
  do {
    const res = await clients.apigw.send(
      new GetApiKeysCommand({
        nameQuery: name,
        includeValues: true,
        limit: 500,
        position,
      }),
    );
    // nameQuery is a prefix match, so filter to the exact name.
    matches.push(...(res.items ?? []).filter((k) => k.name === name));
    position = res.position;
  } while (position);

  if (matches.length > 1) {
    throw new Error(
      `Found ${matches.length} API keys named ${name}; expected at most one`,
    );
  }
  return matches[0];
}

export async function ensureApiKey(
  ctx: ReconcileContext,
  clients: Clients,
  cfg: ReconcilerConfig,
  consumer: Consumer,
): Promise<{ id: string; value: string }> {
  const name = apiKeyName(cfg, consumer.name);
  const key = await findApiKey(clients, name);

  if (!key) {
    const created = {
      id: PENDING('api-key-id'),
      value: PENDING('api-key-value'),
    };
    await ctx.change(name, 'create api key', 'access', async () => {
      const res = await clients.apigw.send(
        new CreateApiKeyCommand({
          name,
          description: `API Key for consumer ${consumer.name}`,
          enabled: true,
          tags: cfg.tags,
        }),
      );
      created.id = res.id!;
      created.value = res.value!;
    });
    return created;
  }

  if (!key.enabled) {
    await ctx.change(name, 'enable api key', 'access', () =>
      clients.apigw.send(
        new UpdateApiKeyCommand({
          apiKey: key.id,
          patchOperations: [{ op: 'replace', path: '/enabled', value: 'true' }],
        }),
      ),
    );
  }

  return { id: key.id!, value: key.value! };
}

async function findUsagePlan(
  clients: Clients,
  name: string,
): Promise<UsagePlan | undefined> {
  const matches: UsagePlan[] = [];
  let position: string | undefined;
  do {
    const res = await clients.apigw.send(
      new GetUsagePlansCommand({ limit: 500, position }),
    );
    matches.push(...(res.items ?? []).filter((p) => p.name === name));
    position = res.position;
  } while (position);

  if (matches.length > 1) {
    throw new Error(
      `Found ${matches.length} usage plans named ${name}; expected at most one`,
    );
  }
  return matches[0];
}

export async function ensureUsagePlan(
  ctx: ReconcileContext,
  clients: Clients,
  cfg: ReconcilerConfig,
  consumer: Consumer,
  apiKeyId: string,
): Promise<void> {
  const name = usagePlanName(cfg, consumer.name);
  const plan = await findUsagePlan(clients, name);
  const throttle = {
    rateLimit: consumer.rateLimit,
    burstLimit: consumer.burstLimit,
  };

  if (!plan) {
    await ctx.change(name, 'create usage plan', 'access', async () => {
      const res = await clients.apigw.send(
        new CreateUsagePlanCommand({
          name,
          description: `Usage plan for consumer ${consumer.name}`,
          throttle,
          apiStages: [{ apiId: cfg.restApiId, stage: cfg.stageName }],
          tags: cfg.tags,
        }),
      );
      await clients.apigw.send(
        new CreateUsagePlanKeyCommand({
          usagePlanId: res.id,
          keyId: apiKeyId,
          keyType: 'API_KEY',
        }),
      );
    });
    return;
  }

  const patchOperations = [];
  if (plan.throttle?.rateLimit !== throttle.rateLimit) {
    patchOperations.push({
      op: 'replace' as const,
      path: '/throttle/rateLimit',
      value: String(throttle.rateLimit),
    });
  }
  if (plan.throttle?.burstLimit !== throttle.burstLimit) {
    patchOperations.push({
      op: 'replace' as const,
      path: '/throttle/burstLimit',
      value: String(throttle.burstLimit),
    });
  }
  if (patchOperations.length > 0) {
    await ctx.change(name, 'update throttle', 'access', () =>
      clients.apigw.send(
        new UpdateUsagePlanCommand({ usagePlanId: plan.id, patchOperations }),
      ),
    );
  }

  const hasStage = (plan.apiStages ?? []).some(
    (s) => s.apiId === cfg.restApiId && s.stage === cfg.stageName,
  );
  if (!hasStage) {
    await ctx.change(name, 'attach api stage', 'access', () =>
      clients.apigw.send(
        new UpdateUsagePlanCommand({
          usagePlanId: plan.id,
          patchOperations: [
            {
              op: 'add',
              path: '/apiStages',
              value: `${cfg.restApiId}:${cfg.stageName}`,
            },
          ],
        }),
      ),
    );
  }

  const keyIds: string[] = [];
  let position: string | undefined;
  do {
    const res = await clients.apigw.send(
      new GetUsagePlanKeysCommand({
        usagePlanId: plan.id,
        limit: 500,
        position,
      }),
    );
    keyIds.push(...(res.items ?? []).map((k) => k.id!));
    position = res.position;
  } while (position);

  if (!keyIds.includes(apiKeyId)) {
    await ctx.change(name, 'attach api key', 'access', () =>
      clients.apigw.send(
        new CreateUsagePlanKeyCommand({
          usagePlanId: plan.id,
          keyId: apiKeyId,
          keyType: 'API_KEY',
        }),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Secrets Manager
// ---------------------------------------------------------------------------

export async function ensureConsumerSecret(
  ctx: ReconcileContext,
  clients: Clients,
  cfg: ReconcilerConfig,
  consumer: Consumer,
  keyArn: string,
  value: Record<string, string>,
): Promise<string> {
  const Name = secretName(cfg, consumer.name);
  const policy = secretResourcePolicy(consumer);

  let exists = true;
  let secretArn = PENDING('secret-arn');
  try {
    const described = await clients.secrets.send(
      new DescribeSecretCommand({ SecretId: Name }),
    );
    secretArn = described.ARN ?? secretArn;
    if (described.DeletedDate) {
      throw new Error(
        `Secret ${Name} is scheduled for deletion; restore it manually before reconciling`,
      );
    }
    if (
      described.KmsKeyId &&
      described.KmsKeyId !== keyArn &&
      !keyArn.startsWith('<pending')
    ) {
      ctx.warnings.push(
        `${Name} is encrypted with ${described.KmsKeyId}, not the consumer config key ${keyArn}`,
      );
    }
  } catch (err) {
    if (nameOf(err) !== 'ResourceNotFoundException') throw err;
    exists = false;
  }

  if (!exists) {
    await ctx.change(Name, 'create secret', 'access', async () => {
      const created = await clients.secrets.send(
        new CreateSecretCommand({
          Name,
          Description: `Api configuration for external consumer ${consumer.name}`,
          KmsKeyId: keyArn,
          SecretString: JSON.stringify(value),
          Tags: Object.entries(cfg.tags).map(([Key, Value]) => ({
            Key,
            Value,
          })),
        }),
      );
      secretArn = created?.ARN ?? secretArn;
      await clients.secrets.send(
        new PutResourcePolicyCommand({
          SecretId: Name,
          ResourcePolicy: JSON.stringify(policy),
          BlockPublicPolicy: true,
        }),
      );
    });
    return secretArn;
  }

  const current = await clients.secrets.send(
    new GetSecretValueCommand({ SecretId: Name }),
  );
  if (!sameSecretValue(current.SecretString, value)) {
    await ctx.change(Name, 'update secret value', 'access', () =>
      clients.secrets.send(
        new PutSecretValueCommand({
          SecretId: Name,
          SecretString: JSON.stringify(value),
        }),
      ),
    );
  }

  const currentPolicy = await clients.secrets.send(
    new GetResourcePolicyCommand({ SecretId: Name }),
  );
  if (!policiesEqual(currentPolicy.ResourcePolicy, policy)) {
    await ctx.change(Name, 'update secret resource policy', 'access', () =>
      clients.secrets.send(
        new PutResourcePolicyCommand({
          SecretId: Name,
          ResourcePolicy: JSON.stringify(policy),
          BlockPublicPolicy: true,
        }),
      ),
    );
  }

  return secretArn;
}

function sameSecretValue(
  current: string | undefined,
  desired: Record<string, string>,
) {
  try {
    const parsed = JSON.parse(current ?? '') as Record<string, unknown>;
    const keys = Object.keys(parsed);
    return (
      keys.length === Object.keys(desired).length &&
      keys.every((k) => parsed[k] === desired[k])
    );
  } catch {
    return false;
  }
}

/** Names of consumers that currently have a config secret in this environment. */
export async function listProvisionedConsumers(
  clients: Clients,
  cfg: ReconcilerConfig,
): Promise<string[]> {
  const prefix = `${cfg.secretPathPrefix}/consumers/`;
  const names: string[] = [];
  let NextToken: string | undefined;
  do {
    const res = await clients.secrets.send(
      new ListSecretsCommand({
        Filters: [{ Key: 'name', Values: [prefix] }],
        NextToken,
      }),
    );
    for (const s of res.SecretList ?? []) {
      const match = s.Name?.startsWith(prefix)
        ? /^([^/]+)\/config$/.exec(s.Name.slice(prefix.length))
        : null;
      if (match) names.push(match[1]);
    }
    NextToken = res.NextToken;
  } while (NextToken);
  return names;
}

/**
 * Remove a consumer's access without deleting anything: its role loses all
 * permissions, its API key is disabled and it can no longer read its secret.
 * Its VPC endpoint and KMS statement disappear because the API and key
 * policies are composed only from declared consumers. Resources are retained
 * so a mistaken removal can be undone by restoring the SSM parameter.
 */
export async function revokeConsumer(
  ctx: ReconcileContext,
  clients: Clients,
  cfg: ReconcilerConfig,
  name: string,
): Promise<void> {
  const RoleName = roleName(cfg, name);
  try {
    const { Role: role } = await clients.iam.send(
      new GetRoleCommand({ RoleName }),
    );
    if (
      role?.PermissionsBoundary?.PermissionsBoundaryArn !==
      cfg.permissionsBoundaryArn
    ) {
      await ctx.change(
        RoleName,
        'set permissions boundary',
        'housekeeping',
        () =>
          clients.iam.send(
            new PutRolePermissionsBoundaryCommand({
              RoleName,
              PermissionsBoundary: cfg.permissionsBoundaryArn,
            }),
          ),
      );
    }
    const res = await clients.iam.send(
      new ListRolePoliciesCommand({ RoleName }),
    );
    for (const PolicyName of res.PolicyNames ?? []) {
      await ctx.change(
        RoleName,
        `revoke: delete inline policy ${PolicyName}`,
        'access',
        () =>
          clients.iam.send(
            new DeleteRolePolicyCommand({ RoleName, PolicyName }),
          ),
      );
    }
  } catch (err) {
    if (
      nameOf(err) !== 'NoSuchEntity' &&
      nameOf(err) !== 'NoSuchEntityException'
    )
      throw err;
  }

  const key = await findApiKey(clients, apiKeyName(cfg, name));
  if (key?.enabled) {
    await ctx.change(key.name!, 'revoke: disable api key', 'access', () =>
      clients.apigw.send(
        new UpdateApiKeyCommand({
          apiKey: key.id,
          patchOperations: [
            { op: 'replace', path: '/enabled', value: 'false' },
          ],
        }),
      ),
    );
  }

  const Name = secretName(cfg, name);
  const policy = await clients.secrets.send(
    new GetResourcePolicyCommand({ SecretId: Name }),
  );
  if (policy.ResourcePolicy) {
    await ctx.change(
      Name,
      'revoke: delete secret resource policy',
      'access',
      () =>
        clients.secrets.send(
          new DeleteResourcePolicyCommand({ SecretId: Name }),
        ),
    );
  }

  ctx.warnings.push(
    `Consumer ${name} is no longer declared in SSM: access revoked, resources retained for manual clean-up`,
  );
}

// ---------------------------------------------------------------------------
// API Gateway resource policy
// ---------------------------------------------------------------------------

export async function ensureApiResourcePolicy(
  ctx: ReconcileContext,
  clients: Clients,
  cfg: ReconcilerConfig,
  consumers: Consumer[],
): Promise<void> {
  const policy = apiResourcePolicy({ ...cfg, consumers });
  const api = await clients.apigw.send(
    new GetRestApiCommand({ restApiId: cfg.restApiId }),
  );

  if (policiesEqual(api.policy, policy, cfg)) return;

  await ctx.change(
    cfg.restApiId,
    'update resource policy and redeploy stage',
    'access',
    async () => {
      await clients.apigw.send(
        new UpdateRestApiCommand({
          restApiId: cfg.restApiId,
          patchOperations: [
            { op: 'replace', path: '/policy', value: JSON.stringify(policy) },
          ],
        }),
      );
      // Resource policy changes only take effect once the API is redeployed.
      await clients.apigw.send(
        new CreateDeploymentCommand({
          restApiId: cfg.restApiId,
          stageName: cfg.stageName,
          description: 'consumer-reconciler: apply resource policy',
        }),
      );
    },
  );
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

export interface ReconcileOptions {
  apply: boolean;
  allowRevokeAll: boolean;
}

/**
 * Everything an external consumer needs to connect. All of it is stable: the
 * reconciler adopts existing resources rather than recreating them, so these
 * values do not change once a consumer exists. Logged on every run so they can
 * be looked up without console access; see also scripts/consumer-details.sh.
 */
export interface ConsumerDetails {
  consumerRoleArn: string;
  configSecretArn: string;
  configSecretName: string;
  kmsKeyArn: string;
  apiUrl: string;
  region: string;
  apiAccountId: string;
  externalIdRequired: boolean;
}

export interface ReconcileReport {
  mode: 'apply' | 'dry-run';
  consumers: string[];
  revoked: string[];
  changes: Change[];
  warnings: string[];
  errors: string[];
  details: Record<string, ConsumerDetails>;
}

export async function reconcileConsumers(
  clients: Clients,
  cfg: ReconcilerConfig,
  consumers: Consumer[],
  options: ReconcileOptions,
): Promise<ReconcileReport> {
  const ctx = new ReconcileContext(options.apply);
  const declared = new Set(consumers.map((c) => c.name));
  const provisioned = await listProvisionedConsumers(clients, cfg);
  const undeclared = provisioned.filter((name) => !declared.has(name));

  // An empty declaration most likely means the params were not written (or the
  // path is wrong), not that every consumer should lose access.
  if (
    consumers.length === 0 &&
    undeclared.length > 0 &&
    !options.allowRevokeAll
  ) {
    return {
      mode: options.apply ? 'apply' : 'dry-run',
      consumers: [],
      revoked: [],
      changes: [],
      warnings: [],
      details: {},
      errors: [
        `No consumers declared under ${cfg.consumerParamPath} but ${undeclared.length} are provisioned (${undeclared.join(', ')}); refusing to revoke them all. Set ALLOW_REVOKE_ALL=true to override.`,
      ],
    };
  }

  // First, so that at deploy time the full consumer allow-list is back on the
  // API before CloudFormation creates its next stage deployment (see the
  // Trigger in consumer-reconciler-construct.ts). Admitting a VPC endpoint
  // ahead of its role is harmless: every method requires IAM auth.
  await ensureApiResourcePolicy(ctx, clients, cfg, consumers);

  // Key policy first so consumers can decrypt any secret created below.
  const keyArn = await ensureConsumerConfigKey(ctx, clients, cfg, consumers);

  const details: Record<string, ConsumerDetails> = {};

  for (const consumer of consumers) {
    const consumerRoleArn = await ensureConsumerRole(
      ctx,
      clients,
      cfg,
      consumer,
    );
    const apiKey = await ensureApiKey(ctx, clients, cfg, consumer);
    await ensureUsagePlan(ctx, clients, cfg, consumer, apiKey.id);
    const configSecretArn = await ensureConsumerSecret(
      ctx,
      clients,
      cfg,
      consumer,
      keyArn,
      consumerSecretValue({
        region: cfg.region,
        accountId: cfg.accountId,
        apiUrl: cfg.apiUrl,
        consumerRoleArn,
        externalId: consumer.externalId,
        apiKey: apiKey.value,
      }),
    );

    details[consumer.name] = {
      consumerRoleArn,
      configSecretArn,
      configSecretName: secretName(cfg, consumer.name),
      kmsKeyArn: keyArn,
      apiUrl: cfg.apiUrl,
      region: cfg.region,
      apiAccountId: cfg.accountId,
      externalIdRequired: !!consumer.externalId,
    };
  }

  for (const name of undeclared) {
    await revokeConsumer(ctx, clients, cfg, name);
  }

  return {
    mode: options.apply ? 'apply' : 'dry-run',
    consumers: consumers.map((c) => c.name),
    revoked: undeclared,
    changes: ctx.changes,
    warnings: ctx.warnings,
    errors: [],
    details,
  };
}

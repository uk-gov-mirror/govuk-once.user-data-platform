import {
  APIGatewayClient,
  CreateApiKeyCommand,
  CreateUsagePlanKeyCommand,
  GetApiKeysCommand,
  GetUsagePlanKeysCommand,
  GetUsagePlansCommand,
  UpdateApiKeyCommand,
  UpdateUsagePlanCommand,
} from '@aws-sdk/client-api-gateway';
import {
  CreateRoleCommand,
  DeleteRolePolicyCommand,
  GetRoleCommand,
  GetRolePolicyCommand,
  IAMClient,
  ListRolePoliciesCommand,
  PutRolePolicyCommand,
  UpdateAssumeRolePolicyCommand,
  UpdateRoleCommand,
} from '@aws-sdk/client-iam';
import {
  CreateAliasCommand,
  CreateKeyCommand,
  DescribeKeyCommand,
  EnableKeyRotationCommand,
  KMSClient,
} from '@aws-sdk/client-kms';
import {
  CreateSecretCommand,
  DescribeSecretCommand,
  GetResourcePolicyCommand,
  GetSecretValueCommand,
  ListSecretsCommand,
  PutResourcePolicyCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager';
import { GetParametersByPathCommand, SSMClient } from '@aws-sdk/client-ssm';
import { mockClient } from 'aws-sdk-client-mock';

import type { Consumer } from './consumers';
import {
  consumerConfigKeyPolicy,
  roleInvokePolicy,
  roleTrustPolicy,
  secretResourcePolicy,
} from './policies';
import {
  ensureApiKey,
  ensureConsumerConfigKey,
  ensureConsumerRole,
  ensureConsumerSecret,
  ensureUsagePlan,
  listProvisionedConsumers,
  readConsumerParams,
  ReconcileContext,
  reconcileConsumers,
  revokeConsumer,
  type Clients,
  type ReconcilerConfig,
} from './reconcile';

const ACCOUNT = '542403648748';
const REGION = 'eu-west-2';
const PARAM_PATH = '/development/udp-param/udp/externalConsumers';
const BOUNDARY = `arn:aws:iam::${ACCOUNT}:policy/dev-consumer-role-boundary`;
const KEY_ARN = `arn:aws:kms:${REGION}:${ACCOUNT}:key/1111`;

const cfg: ReconcilerConfig = {
  environment: 'dev',
  resourcePrefix: 'dev',
  secretPathPrefix: '/udp/dev',
  consumerParamPath: `${PARAM_PATH}/`,
  restApiId: 'abc123',
  stageName: 'dev',
  apiUrl: 'https://abc123.execute-api.eu-west-2.amazonaws.com/dev/',
  ownVpcEndpointId: 'vpce-own0000000000000',
  accountId: ACCOUNT,
  region: REGION,
  crossAccountPrincipals: [],
  permissionsBoundaryArn: BOUNDARY,
  tags: { Project: 'udp' },
};

const flex: Consumer = {
  name: 'flex',
  accountId: '308036881389',
  permissions: ['read'],
  rateLimit: 20,
  burstLimit: 10,
};

const iam = mockClient(IAMClient);
const apigw = mockClient(APIGatewayClient);
const kms = mockClient(KMSClient);
const secrets = mockClient(SecretsManagerClient);
const ssm = mockClient(SSMClient);

const clients = {
  iam: new IAMClient({}),
  apigw: new APIGatewayClient({}),
  kms: new KMSClient({}),
  secrets: new SecretsManagerClient({}),
  ssm: new SSMClient({}),
} as Clients;

const actions = (ctx: ReconcileContext) => ctx.changes.map((c) => c.action);

beforeEach(() => {
  [iam, apigw, kms, secrets, ssm].forEach((m) => m.reset());
});

describe('readConsumerParams', () => {
  it('paginates, strips the path and ignores parameters outside it', async () => {
    ssm
      .on(GetParametersByPathCommand)
      .resolvesOnce({
        Parameters: [
          { Name: `${PARAM_PATH}/flex`, Value: '{}' },
          { Name: '/elsewhere/other', Value: '{}' },
          { Value: 'nameless' },
        ],
        NextToken: 'next',
      })
      .resolvesOnce({ Parameters: [{ Name: `${PARAM_PATH}/empty` }] })
      .resolves({});

    const params = await readConsumerParams(clients, cfg);

    expect(params).toEqual([
      { name: 'flex', value: '{}' },
      { name: 'empty', value: '' },
    ]);
    const calls = ssm.commandCalls(GetParametersByPathCommand);
    expect(calls).toHaveLength(2);
    expect(calls[0].args[0].input.Path).toBe(PARAM_PATH);
    expect(calls[1].args[0].input.NextToken).toBe('next');
  });

  it('handles a response with no parameters', async () => {
    ssm.on(GetParametersByPathCommand).resolves({});

    expect(await readConsumerParams(clients, cfg)).toEqual([]);
  });
});

describe('ensureConsumerConfigKey', () => {
  it('rethrows unexpected DescribeKey errors', async () => {
    kms.on(DescribeKeyCommand).rejects({ name: 'AccessDeniedException' });

    await expect(
      ensureConsumerConfigKey(new ReconcileContext(true), clients, cfg, [flex]),
    ).rejects.toMatchObject({ name: 'AccessDeniedException' });
  });

  it('does not create a key when there are no consumers', async () => {
    kms.on(DescribeKeyCommand).rejects({ name: 'NotFoundException' });
    const ctx = new ReconcileContext(true);

    const arn = await ensureConsumerConfigKey(ctx, clients, cfg, []);

    expect(arn).toBe('<pending:kms-key>');
    expect(ctx.changes).toEqual([]);
    expect(kms.commandCalls(CreateKeyCommand)).toHaveLength(0);
  });

  it('plans a key without creating it in dry-run mode', async () => {
    kms.on(DescribeKeyCommand).resolves({});
    const ctx = new ReconcileContext(false);

    const arn = await ensureConsumerConfigKey(ctx, clients, cfg, [flex]);

    expect(arn).toBe('<pending:kms-key>');
    expect(actions(ctx)).toEqual(['create key']);
    expect(kms.commandCalls(CreateKeyCommand)).toHaveLength(0);
  });

  it('creates the key, alias and rotation in apply mode', async () => {
    kms.on(DescribeKeyCommand).rejects({ name: 'NotFoundException' });
    kms
      .on(CreateKeyCommand)
      .resolves({ KeyMetadata: { KeyId: '1111', Arn: KEY_ARN } });

    const arn = await ensureConsumerConfigKey(
      new ReconcileContext(true),
      clients,
      cfg,
      [flex],
    );

    expect(arn).toBe(KEY_ARN);
    const created = kms.commandCalls(CreateKeyCommand)[0].args[0].input;
    expect(created.Tags).toEqual([{ TagKey: 'Project', TagValue: 'udp' }]);
    expect(JSON.parse(created.Policy!)).toEqual(
      consumerConfigKeyPolicy({ ...cfg, consumers: [flex] }),
    );
    expect(kms.commandCalls(CreateAliasCommand)[0].args[0].input).toEqual({
      AliasName: 'alias//udp/dev-consumer-config',
      TargetKeyId: KEY_ARN,
    });
    expect(
      kms.commandCalls(EnableKeyRotationCommand)[0].args[0].input.KeyId,
    ).toBe(KEY_ARN);
  });
});

describe('ensureConsumerRole', () => {
  const roleArn = `arn:aws:iam::${ACCOUNT}:role/dev-consumer-flex-role`;
  const desiredInvoke = roleInvokePolicy({
    ...cfg,
    permissions: flex.permissions,
  });

  it('rethrows unexpected GetRole errors', async () => {
    iam.on(GetRoleCommand).rejects({ name: 'AccessDenied' });

    await expect(
      ensureConsumerRole(new ReconcileContext(true), clients, cfg, flex),
    ).rejects.toMatchObject({ name: 'AccessDenied' });
  });

  it('creates a tagged role with the invoke policy when it is missing', async () => {
    iam.on(GetRoleCommand).rejects({ name: 'NoSuchEntityException' });

    const arn = await ensureConsumerRole(
      new ReconcileContext(true),
      clients,
      cfg,
      flex,
    );

    expect(arn).toBe(roleArn);
    expect(iam.commandCalls(CreateRoleCommand)[0].args[0].input).toMatchObject({
      RoleName: 'dev-consumer-flex-role',
      Description: 'API Consumer role for  flex = dev',
      PermissionsBoundary: BOUNDARY,
      Tags: [{ Key: 'Project', Value: 'udp' }],
    });
    expect(
      JSON.parse(
        iam.commandCalls(PutRolePolicyCommand)[0].args[0].input.PolicyDocument!,
      ),
    ).toEqual(desiredInvoke);
  });

  it('corrects a drifted trust policy, description and inline policy', async () => {
    iam.on(GetRoleCommand).resolves({
      Role: {
        RoleName: 'dev-consumer-flex-role',
        Arn: roleArn,
        Path: '/',
        RoleId: 'AROAFLEX',
        CreateDate: new Date(),
        PermissionsBoundary: { PermissionsBoundaryArn: BOUNDARY },
        AssumeRolePolicyDocument: encodeURIComponent(
          JSON.stringify(
            roleTrustPolicy({ ...flex, accountId: '111111111111' }),
          ),
        ),
      },
    });
    iam
      .on(ListRolePoliciesCommand)
      .resolvesOnce({
        PolicyNames: ['api-invoke'],
        IsTruncated: true,
        Marker: 'm',
      })
      .resolvesOnce({ IsTruncated: false });
    iam.on(GetRolePolicyCommand).resolves({
      PolicyDocument: encodeURIComponent(
        JSON.stringify(
          roleInvokePolicy({ ...cfg, permissions: ['read', 'delete'] }),
        ),
      ),
    });
    const ctx = new ReconcileContext(true);

    const arn = await ensureConsumerRole(ctx, clients, cfg, flex);

    expect(arn).toBe(roleArn);
    expect(actions(ctx)).toEqual([
      'update trust policy',
      'update description',
      'put inline policy api-invoke',
    ]);
    expect(iam.commandCalls(ListRolePoliciesCommand)[1].args[0].input).toEqual({
      RoleName: 'dev-consumer-flex-role',
      Marker: 'm',
    });
    expect(
      JSON.parse(
        iam.commandCalls(UpdateAssumeRolePolicyCommand)[0].args[0].input
          .PolicyDocument!,
      ),
    ).toEqual(roleTrustPolicy(flex));
    expect(iam.commandCalls(UpdateRoleCommand)[0].args[0].input).toEqual({
      RoleName: 'dev-consumer-flex-role',
      Description: 'API Consumer role for  flex = dev',
    });
    expect(iam.commandCalls(DeleteRolePolicyCommand)).toHaveLength(0);
  });
  it('removes leftover inline policies once api-invoke is already correct', async () => {
    iam.on(GetRoleCommand).resolves({
      Role: {
        RoleName: 'dev-consumer-flex-role',
        Arn: roleArn,
        Path: '/',
        RoleId: 'AROAFLEX',
        CreateDate: new Date(),
        Description: 'API Consumer role for  flex = dev',
        PermissionsBoundary: { PermissionsBoundaryArn: BOUNDARY },
        AssumeRolePolicyDocument: JSON.stringify(roleTrustPolicy(flex)),
      },
    });
    iam
      .on(ListRolePoliciesCommand)
      .resolves({ PolicyNames: ['api-invoke', 'leftover'] });
    iam
      .on(GetRolePolicyCommand)
      .resolves({ PolicyDocument: JSON.stringify(desiredInvoke) });
    const ctx = new ReconcileContext(true);

    await ensureConsumerRole(ctx, clients, cfg, flex);

    expect(actions(ctx)).toEqual(['delete inline policy leftover']);
    expect(iam.commandCalls(PutRolePolicyCommand)).toHaveLength(0);
    expect(
      iam.commandCalls(DeleteRolePolicyCommand)[0].args[0].input.PolicyName,
    ).toBe('leftover');
  });
});

describe('ensureApiKey', () => {
  it('refuses to pick between API keys with the same name', async () => {
    const key = { id: 'k', name: 'dev-flex-key', enabled: true };
    apigw
      .on(GetApiKeysCommand)
      .resolvesOnce({
        items: [key, { id: 'x', name: 'dev-flex-key-old' }],
        position: 'p1',
      })
      .resolvesOnce({ position: 'p2' })
      .resolvesOnce({ items: [key] });

    await expect(
      ensureApiKey(new ReconcileContext(true), clients, cfg, flex),
    ).rejects.toThrow('Found 2 API keys named dev-flex-key');
  });

  it('plans a new key with placeholder values in dry-run mode', async () => {
    apigw.on(GetApiKeysCommand).resolves({});
    const ctx = new ReconcileContext(false);

    const key = await ensureApiKey(ctx, clients, cfg, flex);

    expect(key).toEqual({
      id: '<pending:api-key-id>',
      value: '<pending:api-key-value>',
    });
    expect(actions(ctx)).toEqual(['create api key']);
    expect(apigw.commandCalls(CreateApiKeyCommand)).toHaveLength(0);
  });

  it('re-enables a disabled key', async () => {
    apigw.on(GetApiKeysCommand).resolves({
      items: [{ id: 'k', name: 'dev-flex-key', enabled: false, value: 'v' }],
    });

    const key = await ensureApiKey(
      new ReconcileContext(true),
      clients,
      cfg,
      flex,
    );

    expect(key).toEqual({ id: 'k', value: 'v' });
    expect(apigw.commandCalls(UpdateApiKeyCommand)[0].args[0].input).toEqual({
      apiKey: 'k',
      patchOperations: [{ op: 'replace', path: '/enabled', value: 'true' }],
    });
  });
});

describe('ensureUsagePlan', () => {
  it('refuses to pick between usage plans with the same name', async () => {
    apigw
      .on(GetUsagePlansCommand)
      .resolvesOnce({ position: 'p' })
      .resolves({
        items: [
          { id: 'a', name: 'dev-flex-usage-plan' },
          { id: 'b', name: 'dev-flex-usage-plan' },
        ],
      });

    await expect(
      ensureUsagePlan(new ReconcileContext(true), clients, cfg, flex, 'k'),
    ).rejects.toThrow('Found 2 usage plans named dev-flex-usage-plan');
  });

  it('corrects throttle, stage and key drift on an existing plan', async () => {
    apigw.on(GetUsagePlansCommand).resolves({
      items: [
        {
          id: 'plan',
          name: 'dev-flex-usage-plan',
          throttle: { rateLimit: 5, burstLimit: 1 },
        },
      ],
    });
    apigw
      .on(GetUsagePlanKeysCommand)
      .resolvesOnce({ position: 'p' })
      .resolves({ items: [{ id: 'other-key' }] });
    const ctx = new ReconcileContext(true);

    await ensureUsagePlan(ctx, clients, cfg, flex, 'k');

    expect(actions(ctx)).toEqual([
      'update throttle',
      'attach api stage',
      'attach api key',
    ]);
    const updates = apigw
      .commandCalls(UpdateUsagePlanCommand)
      .map((c) => c.args[0].input);
    expect(updates).toEqual([
      {
        usagePlanId: 'plan',
        patchOperations: [
          { op: 'replace', path: '/throttle/rateLimit', value: '20' },
          { op: 'replace', path: '/throttle/burstLimit', value: '10' },
        ],
      },
      {
        usagePlanId: 'plan',
        patchOperations: [
          { op: 'add', path: '/apiStages', value: 'abc123:dev' },
        ],
      },
    ]);
    expect(
      apigw.commandCalls(CreateUsagePlanKeyCommand)[0].args[0].input,
    ).toEqual({ usagePlanId: 'plan', keyId: 'k', keyType: 'API_KEY' });
  });
});

describe('ensureConsumerSecret', () => {
  const Name = '/udp/dev/consumers/flex/config';
  const value = { region: REGION, apiKey: 'v' };

  it('refuses to reconcile a secret scheduled for deletion', async () => {
    secrets
      .on(DescribeSecretCommand)
      .resolves({ ARN: 'arn', DeletedDate: new Date() });

    await expect(
      ensureConsumerSecret(
        new ReconcileContext(true),
        clients,
        cfg,
        flex,
        KEY_ARN,
        value,
      ),
    ).rejects.toThrow(/scheduled for deletion/);
  });

  it('rethrows unexpected DescribeSecret errors', async () => {
    secrets
      .on(DescribeSecretCommand)
      .rejects({ name: 'AccessDeniedException' });

    await expect(
      ensureConsumerSecret(
        new ReconcileContext(true),
        clients,
        cfg,
        flex,
        KEY_ARN,
        value,
      ),
    ).rejects.toMatchObject({ name: 'AccessDeniedException' });
  });

  it('creates a tagged secret and keeps the placeholder ARN if none is returned', async () => {
    secrets
      .on(DescribeSecretCommand)
      .rejects({ name: 'ResourceNotFoundException' });
    secrets.on(CreateSecretCommand).resolves({});

    const arn = await ensureConsumerSecret(
      new ReconcileContext(true),
      clients,
      cfg,
      flex,
      KEY_ARN,
      value,
    );

    expect(arn).toBe('<pending:secret-arn>');
    expect(
      secrets.commandCalls(CreateSecretCommand)[0].args[0].input.Tags,
    ).toEqual([{ Key: 'Project', Value: 'udp' }]);
    expect(secrets.commandCalls(PutResourcePolicyCommand)).toHaveLength(1);
  });

  it('warns about a foreign KMS key and corrects value and policy drift', async () => {
    secrets
      .on(DescribeSecretCommand)
      .resolves({ ARN: 'secret-arn', KmsKeyId: 'other-key' });
    secrets.on(GetSecretValueCommand).resolves({});
    secrets.on(GetResourcePolicyCommand).resolves({});
    const ctx = new ReconcileContext(true);

    const arn = await ensureConsumerSecret(
      ctx,
      clients,
      cfg,
      flex,
      KEY_ARN,
      value,
    );

    expect(arn).toBe('secret-arn');
    expect(ctx.warnings).toEqual([
      `${Name} is encrypted with other-key, not the consumer config key ${KEY_ARN}`,
    ]);
    expect(actions(ctx)).toEqual([
      'update secret value',
      'update secret resource policy',
    ]);
    expect(
      secrets.commandCalls(PutSecretValueCommand)[0].args[0].input,
    ).toEqual({ SecretId: Name, SecretString: JSON.stringify(value) });
    expect(
      JSON.parse(
        secrets.commandCalls(PutResourcePolicyCommand)[0].args[0].input
          .ResourcePolicy!,
      ),
    ).toEqual(secretResourcePolicy(flex));
  });

  it('does not warn about the KMS key while the consumer key is still pending', async () => {
    secrets.on(DescribeSecretCommand).resolves({ KmsKeyId: 'other-key' });
    secrets
      .on(GetSecretValueCommand)
      .resolves({ SecretString: JSON.stringify({ ...value, apiKey: 'old' }) });
    secrets.on(GetResourcePolicyCommand).resolves({
      ResourcePolicy: JSON.stringify(secretResourcePolicy(flex)),
    });
    const ctx = new ReconcileContext(false);

    const arn = await ensureConsumerSecret(
      ctx,
      clients,
      cfg,
      flex,
      '<pending:kms-key>',
      value,
    );

    expect(arn).toBe('<pending:secret-arn>');
    expect(ctx.warnings).toEqual([]);
    expect(actions(ctx)).toEqual(['update secret value']);
  });

  it('treats an unparseable secret value as drift', async () => {
    secrets.on(DescribeSecretCommand).resolves({ ARN: 'secret-arn' });
    secrets.on(GetSecretValueCommand).resolves({ SecretString: 'not json' }); // pragma: allowlist secret
    secrets.on(GetResourcePolicyCommand).resolves({
      ResourcePolicy: JSON.stringify(secretResourcePolicy(flex)),
    });
    const ctx = new ReconcileContext(false);

    await ensureConsumerSecret(ctx, clients, cfg, flex, KEY_ARN, value);

    expect(actions(ctx)).toEqual(['update secret value']);
  });
});

describe('listProvisionedConsumers', () => {
  it('paginates and only returns direct consumer config secrets', async () => {
    secrets
      .on(ListSecretsCommand)
      .resolvesOnce({
        SecretList: [
          { Name: '/udp/dev/consumers/flex/config' },
          { Name: '/udp/dev/consumers/flex/other' },
          { Name: '/udp/dev/consumers/a/b/config' },
          { Name: '/udp/prod/consumers/gdsuns/config' },
          {},
        ],
        NextToken: 't',
      })
      .resolvesOnce({});

    expect(await listProvisionedConsumers(clients, cfg)).toEqual(['flex']);
    expect(
      secrets.commandCalls(ListSecretsCommand)[1].args[0].input.NextToken,
    ).toBe('t');
  });
});

describe('revokeConsumer', () => {
  it.each(['NoSuchEntity', 'NoSuchEntityException'])(
    'tolerates a missing role (%s) and skips resources already revoked',
    async (name) => {
      iam.on(GetRoleCommand).rejects({ name });
      apigw.on(GetApiKeysCommand).resolves({
        items: [{ id: 'k', name: 'dev-flex-key', enabled: false }],
      });
      secrets.on(GetResourcePolicyCommand).resolves({});
      const ctx = new ReconcileContext(true);

      await revokeConsumer(ctx, clients, cfg, 'flex');

      expect(ctx.changes).toEqual([]);
      expect(ctx.warnings).toEqual([
        expect.stringMatching(/^Consumer flex is no longer declared/),
      ]);
    },
  );

  it('leaves a bounded role with no inline policies alone', async () => {
    iam.on(GetRoleCommand).resolves({
      Role: {
        RoleName: 'dev-consumer-flex-role',
        Arn: 'arn',
        Path: '/',
        RoleId: 'AROAFLEX',
        CreateDate: new Date(),
        PermissionsBoundary: { PermissionsBoundaryArn: BOUNDARY },
      },
    });
    iam.on(ListRolePoliciesCommand).resolves({});
    apigw.on(GetApiKeysCommand).resolves({ items: [] });
    secrets.on(GetResourcePolicyCommand).resolves({});
    const ctx = new ReconcileContext(true);

    await revokeConsumer(ctx, clients, cfg, 'flex');

    expect(ctx.changes).toEqual([]);
  });

  it('rethrows unexpected GetRole errors', async () => {
    iam.on(GetRoleCommand).rejects({ name: 'AccessDenied' });

    await expect(
      revokeConsumer(new ReconcileContext(true), clients, cfg, 'flex'),
    ).rejects.toMatchObject({ name: 'AccessDenied' });
  });
});

describe('reconcileConsumers', () => {
  it('reports dry-run mode when refusing to revoke every consumer', async () => {
    secrets.on(ListSecretsCommand).resolves({
      SecretList: [{ Name: '/udp/dev/consumers/flex/config' }],
    });

    const report = await reconcileConsumers(clients, cfg, [], {
      apply: false,
      allowRevokeAll: false,
    });

    expect(report.mode).toBe('dry-run');
    expect(report.errors[0]).toMatch(/refusing to revoke them all/);
  });
});

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
} from '@aws-sdk/client-api-gateway';
import {
  CreateRoleCommand,
  DeleteRolePolicyCommand,
  GetRoleCommand,
  GetRolePolicyCommand,
  IAMClient,
  ListRolePoliciesCommand,
  PutRolePermissionsBoundaryCommand,
  PutRolePolicyCommand,
} from '@aws-sdk/client-iam';
import {
  DescribeKeyCommand,
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
  SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager';
import { GetParametersByPathCommand, SSMClient } from '@aws-sdk/client-ssm';
import { mockClient } from 'aws-sdk-client-mock';

import { handler } from './handler';
import {
  apiResourcePolicy,
  consumerConfigKeyPolicy,
  roleInvokePolicy,
  roleTrustPolicy,
  secretResourcePolicy,
} from './policies';
import type { Clients } from './reconcile';
import type { Consumer } from './consumers';

const ACCOUNT = '542403648748';
const REGION = 'eu-west-2';
const API_ID = 'abc123';
const OWN_VPCE = 'vpce-own0000000000000';
const BOUNDARY = `arn:aws:iam::${ACCOUNT}:policy/dev-consumer-role-boundary`;
const PARAM_PATH = '/development/udp-param/udp/externalConsumers';
const KEY_ARN = `arn:aws:kms:${REGION}:${ACCOUNT}:key/1111`;
const FLEX_SECRET_ARN = `arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:/udp/dev/consumers/flex/config-Xy98Zw`; // pragma: allowlist secret
const API_URL = `https://${API_ID}.execute-api.${REGION}.amazonaws.com/dev/`;

const baseEnv = {
  MODE: 'dry-run',
  ENVIRONMENT: 'dev',
  RESOURCE_PREFIX: 'dev',
  SECRET_PATH_PREFIX: '/udp/dev',
  CONSUMER_PARAM_PATH: PARAM_PATH,
  REST_API_ID: API_ID,
  STAGE_NAME: 'dev',
  API_URL,
  OWN_VPCE_ID: OWN_VPCE,
  ACCOUNT_ID: ACCOUNT,
  AWS_REGION: REGION,
  PERMISSIONS_BOUNDARY_ARN: BOUNDARY,
};

const flexParam = {
  accountId: '308036881389',
  permissions: ['read', 'write', 'delete'],
  description: 'Flex integration',
  vpcEndpointId: 'vpce-0fda65abeaa732a68',
};
const flex: Consumer = {
  name: 'flex',
  ...flexParam,
  rateLimit: 20,
  burstLimit: 10,
} as Consumer;
const api = { region: REGION, accountId: ACCOUNT, restApiId: API_ID };

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

const WRITE_COMMANDS = [
  CreateRoleCommand,
  DeleteRolePolicyCommand,
  PutRolePermissionsBoundaryCommand,
  PutRolePolicyCommand,
  CreateApiKeyCommand,
  CreateDeploymentCommand,
  CreateUsagePlanCommand,
  CreateUsagePlanKeyCommand,
  UpdateApiKeyCommand,
  UpdateRestApiCommand,
  PutKeyPolicyCommand,
  CreateSecretCommand,
  DeleteResourcePolicyCommand,
  PutResourcePolicyCommand,
];

const writeCalls = () =>
  [iam, apigw, kms, secrets].flatMap((m) =>
    m
      .calls()
      .filter((c) => WRITE_COMMANDS.some((cmd) => c.args[0] instanceof cmd)),
  );

const declare = (params: Record<string, unknown>) =>
  ssm.on(GetParametersByPathCommand).resolves({
    Parameters: Object.entries(params).map(([name, value]) => ({
      Name: `${PARAM_PATH}/${name}`,
      Value: typeof value === 'string' ? value : JSON.stringify(value),
    })),
  });

/** Live state exactly as the CDK constructs created it for `flex` today. */
const mockCloudFormationCreatedFlex = () => {
  kms
    .on(DescribeKeyCommand)
    .resolves({ KeyMetadata: { KeyId: '1111', Arn: KEY_ARN } });
  kms.on(GetKeyPolicyCommand).resolves({
    Policy: JSON.stringify(
      consumerConfigKeyPolicy({ ...api, consumers: [flex] }),
    ),
  });

  iam.on(GetRoleCommand, { RoleName: 'dev-consumer-flex-role' }).resolves({
    Role: {
      RoleName: 'dev-consumer-flex-role',
      Arn: `arn:aws:iam::${ACCOUNT}:role/dev-consumer-flex-role`,
      Path: '/',
      RoleId: 'AROAFLEX',
      CreateDate: new Date(),
      Description: 'Flex integration',
      AssumeRolePolicyDocument: encodeURIComponent(
        JSON.stringify(roleTrustPolicy(flex)),
      ),
    },
  });
  iam.on(ListRolePoliciesCommand).resolves({
    PolicyNames: ['IamConsumersConsumerRoleflexDefaultPolicyB02EA1C7'],
  });
  iam.on(GetRolePolicyCommand).resolves({
    PolicyDocument: encodeURIComponent(
      JSON.stringify(
        roleInvokePolicy({ ...api, permissions: flex.permissions }),
      ),
    ),
  });

  apigw.on(GetApiKeysCommand).resolves({
    items: [
      {
        id: 'key-flex',
        name: 'dev-flex-key',
        enabled: true,
        value: 'secret-key-value',
      },
    ],
  });
  apigw.on(GetUsagePlansCommand).resolves({
    items: [
      {
        id: 'plan-flex',
        name: 'dev-flex-usage-plan',
        throttle: { rateLimit: 20, burstLimit: 10 },
        apiStages: [{ apiId: API_ID, stage: 'dev' }],
      },
    ],
  });
  apigw.on(GetUsagePlanKeysCommand).resolves({ items: [{ id: 'key-flex' }] });
  apigw.on(GetRestApiCommand).resolves({
    policy: JSON.stringify(
      apiResourcePolicy({
        ...api,
        ownVpcEndpointId: OWN_VPCE,
        consumers: [flex],
        crossAccountPrincipals: [],
      }),
    ).replace(/"/g, '\\"'),
  });

  secrets.on(ListSecretsCommand).resolves({
    SecretList: [{ Name: '/udp/dev/consumers/flex/config' }],
  });
  secrets.on(DescribeSecretCommand).resolves({
    Name: '/udp/dev/consumers/flex/config',
    ARN: FLEX_SECRET_ARN,
    KmsKeyId: KEY_ARN,
  });
  secrets.on(GetSecretValueCommand).resolves({
    SecretString: JSON.stringify({
      region: REGION,
      apiAccountId: ACCOUNT,
      apiUrl: API_URL,
      consumerRoleArn: `arn:aws:iam::${ACCOUNT}:role/dev-consumer-flex-role`,
      apiKey: 'secret-key-value', // pragma: allowlist secret
    }),
  });
  secrets.on(GetResourcePolicyCommand).resolves({
    ResourcePolicy: JSON.stringify(secretResourcePolicy(flex)),
  });
};

describe('consumer reconciler handler', () => {
  beforeEach(() => {
    [iam, apigw, kms, secrets, ssm].forEach((m) => m.reset());
    Object.assign(process.env, baseEnv);
    delete process.env.ALLOW_REVOKE_ALL;
  });

  describe('adopting resources created by CloudFormation', () => {
    it('plans no access changes when SSM matches what CloudFormation created', async () => {
      declare({ flex: flexParam });
      mockCloudFormationCreatedFlex();

      const report = await handler({}, clients);

      expect(report.errors).toEqual([]);
      expect(report.changes.filter((c) => c.impact === 'access')).toEqual([]);
      // Only the boundary is new; the CDK-named inline policy is left in place.
      expect(report.changes).toEqual([
        {
          resource: 'dev-consumer-flex-role',
          action: 'set permissions boundary',
          impact: 'housekeeping',
        },
      ]);
    });

    it('writes nothing in dry-run mode even when there is drift', async () => {
      declare({ flex: { ...flexParam, rateLimit: 50 } });
      mockCloudFormationCreatedFlex();

      const report = await handler({}, clients);

      expect(report.changes).toContainEqual({
        resource: 'dev-flex-usage-plan',
        action: 'update throttle',
        impact: 'access',
      });
      expect(writeCalls()).toEqual([]);
    });

    it('sets the boundary before replacing the inline policy in apply mode', async () => {
      process.env.MODE = 'apply';
      declare({ flex: { ...flexParam, permissions: ['read'] } });
      mockCloudFormationCreatedFlex();

      await handler({}, clients);

      const iamWrites = iam
        .calls()
        .map((c) => c.args[0].constructor.name)
        .filter((n) => /^(Put|Delete)/.test(n));
      expect(iamWrites).toEqual([
        'PutRolePermissionsBoundaryCommand',
        'PutRolePolicyCommand',
        'DeleteRolePolicyCommand',
      ]);
      expect(
        iam.commandCalls(DeleteRolePolicyCommand)[0].args[0].input.PolicyName,
      ).toBe('IamConsumersConsumerRoleflexDefaultPolicyB02EA1C7');
    });
  });

  describe('onboarding a new consumer', () => {
    beforeEach(() => {
      process.env.MODE = 'apply';
      declare({
        flex: flexParam,
        travel: {
          ...flexParam,
          accountId: '999999999999',
          vpcEndpointId: 'vpce-0aaaaaaaaaaaaaaaa',
        },
      });
      mockCloudFormationCreatedFlex();

      iam
        .on(GetRoleCommand, { RoleName: 'dev-consumer-travel-role' })
        .rejects({ name: 'NoSuchEntity' });
      apigw
        .on(GetApiKeysCommand, { nameQuery: 'dev-travel-key' })
        .resolves({ items: [] });
      apigw
        .on(CreateApiKeyCommand)
        .resolves({ id: 'key-travel', value: 'travel-key-value' });
      apigw.on(CreateUsagePlanCommand).resolves({ id: 'plan-travel' });
      secrets
        .on(DescribeSecretCommand, {
          SecretId: '/udp/dev/consumers/travel/config',
        })
        .rejects({ name: 'ResourceNotFoundException' });
      secrets.on(CreateSecretCommand).resolves({
        ARN: `arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:/udp/dev/consumers/travel/config-Ab12Cd`,
      });
    });

    it('creates role, API key, usage plan and secret, then admits its VPC endpoint', async () => {
      const report = await handler({ source: 'aws.ssm' }, clients);

      expect(
        iam.commandCalls(CreateRoleCommand)[0].args[0].input,
      ).toMatchObject({
        RoleName: 'dev-consumer-travel-role',
        PermissionsBoundary: BOUNDARY,
      });
      expect(
        apigw.commandCalls(CreateUsagePlanKeyCommand)[0].args[0].input,
      ).toEqual({
        usagePlanId: 'plan-travel',
        keyId: 'key-travel',
        keyType: 'API_KEY',
      });

      const secret = secrets.commandCalls(CreateSecretCommand)[0].args[0].input;
      expect(secret.Name).toBe('/udp/dev/consumers/travel/config');
      expect(secret.KmsKeyId).toBe(KEY_ARN);
      expect(JSON.parse(secret.SecretString!)).toEqual({
        region: REGION,
        apiAccountId: ACCOUNT,
        apiUrl: API_URL,
        consumerRoleArn: `arn:aws:iam::${ACCOUNT}:role/dev-consumer-travel-role`,
        apiKey: 'travel-key-value', // pragma: allowlist secret
      });

      const keyPolicy = JSON.parse(
        kms.commandCalls(PutKeyPolicyCommand)[0].args[0].input.Policy!,
      );
      expect(JSON.stringify(keyPolicy)).toContain(
        'arn:aws:iam::999999999999:root',
      );

      const apiPolicy = JSON.parse(
        apigw.commandCalls(UpdateRestApiCommand)[0].args[0].input
          .patchOperations![0].value!,
      );
      expect(
        apiPolicy.Statement[0].Condition.StringNotEquals['aws:sourceVpce'],
      ).toEqual([OWN_VPCE, 'vpce-0fda65abeaa732a68', 'vpce-0aaaaaaaaaaaaaaaa']);
      expect(apigw.commandCalls(CreateDeploymentCommand)).toHaveLength(1);

      // Everything the consumer needs in order to connect.
      expect(report.details.travel).toEqual({
        consumerRoleArn: `arn:aws:iam::${ACCOUNT}:role/dev-consumer-travel-role`,
        configSecretArn: `arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:/udp/dev/consumers/travel/config-Ab12Cd`, // pragma: allowlist secret
        configSecretName: '/udp/dev/consumers/travel/config',
        kmsKeyArn: KEY_ARN,
        apiUrl: API_URL,
        region: REGION,
        apiAccountId: ACCOUNT,
        externalIdRequired: false,
      });
      // The existing consumer's details are reported from live state too.
      expect(report.details.flex.configSecretArn).toBe(FLEX_SECRET_ARN);

      // Existing consumer untouched apart from housekeeping.
      expect(
        secrets
          .commandCalls(PutResourcePolicyCommand)
          .map((c) => c.args[0].input.SecretId),
      ).toEqual(['/udp/dev/consumers/travel/config']);
    });
  });

  describe('safety', () => {
    it('aborts without writing when any parameter is invalid', async () => {
      process.env.MODE = 'apply';
      declare({ flex: flexParam, broken: { ...flexParam, accountId: 'nope' } });
      mockCloudFormationCreatedFlex();

      const report = await handler({}, clients);

      expect(report.errors).toEqual([
        expect.stringMatching(/^broken: accountId/),
      ]);
      expect(writeCalls()).toEqual([]);
    });

    it('fails SSM-triggered invocations on invalid parameters so the error alarm fires', async () => {
      declare({ broken: '{' });

      await expect(handler({ source: 'aws.ssm' }, clients)).rejects.toThrow(
        /broken: value is not valid JSON/,
      );
    });

    it('refuses to revoke every consumer when nothing is declared', async () => {
      process.env.MODE = 'apply';
      declare({});
      mockCloudFormationCreatedFlex();

      const report = await handler({}, clients);

      expect(report.errors[0]).toMatch(/refusing to revoke them all/);
      expect(writeCalls()).toEqual([]);
    });

    it('revokes access for a consumer removed from SSM but keeps its resources', async () => {
      process.env.MODE = 'apply';
      declare({
        gdsuns: {
          ...flexParam,
          accountId: '674663567518',
          vpcEndpointId: 'vpce-0f7de3952cb0bc5c1',
        },
      });
      mockCloudFormationCreatedFlex();
      iam
        .on(GetRoleCommand, { RoleName: 'dev-consumer-gdsuns-role' })
        .rejects({ name: 'NoSuchEntity' });
      apigw
        .on(GetApiKeysCommand, { nameQuery: 'dev-gdsuns-key' })
        .resolves({ items: [] });
      apigw
        .on(CreateApiKeyCommand)
        .resolves({ id: 'key-gdsuns', value: 'gdsuns-key-value' });
      apigw.on(CreateUsagePlanCommand).resolves({ id: 'plan-gdsuns' });
      secrets
        .on(DescribeSecretCommand, {
          SecretId: '/udp/dev/consumers/gdsuns/config',
        })
        .rejects({ name: 'ResourceNotFoundException' });

      const report = await handler({}, clients);

      expect(report.revoked).toEqual(['flex']);
      expect(
        apigw.commandCalls(UpdateApiKeyCommand)[0].args[0].input,
      ).toMatchObject({
        apiKey: 'key-flex', // pragma: allowlist secret
        patchOperations: [{ op: 'replace', path: '/enabled', value: 'false' }],
      });
      expect(
        secrets.commandCalls(DeleteResourcePolicyCommand)[0].args[0].input
          .SecretId,
      ).toBe('/udp/dev/consumers/flex/config');
      expect(
        iam
          .commandCalls(DeleteRolePolicyCommand)
          .some((c) => c.args[0].input.RoleName === 'dev-consumer-flex-role'),
      ).toBe(true);
    });

    it('never fails a deploy-time dry-run on an AWS error', async () => {
      declare({ flex: flexParam });
      mockCloudFormationCreatedFlex();
      apigw
        .on(GetRestApiCommand)
        .rejects({ name: 'AccessDeniedException', message: 'denied' });

      const report = await handler({}, clients);

      expect(report.errors).toEqual(['Dry-run failed: denied']);
    });

    it('fails an apply run on an AWS error', async () => {
      process.env.MODE = 'apply';
      declare({ flex: flexParam });
      mockCloudFormationCreatedFlex();
      apigw
        .on(GetRestApiCommand)
        .rejects({ name: 'AccessDeniedException', message: 'denied' });

      await expect(handler({}, clients)).rejects.toMatchObject({
        message: 'denied',
      });
    });

    it('falls back to its own AWS clients when none are injected', async () => {
      declare({});
      secrets.on(ListSecretsCommand).resolves({ SecretList: [] });
      apigw.on(GetRestApiCommand).resolves({});
      kms.on(DescribeKeyCommand).rejects({ name: 'NotFoundException' });

      // Twice, so the second invocation reuses the cached clients.
      await handler();
      const report = await handler();

      expect(report.errors).toEqual([]);
      expect(ssm.commandCalls(GetParametersByPathCommand)).toHaveLength(2);
    });

    it('rejects an unknown MODE', async () => {
      process.env.MODE = 'yolo';
      await expect(handler({}, clients)).rejects.toThrow(/MODE must be/);
    });
  });
});

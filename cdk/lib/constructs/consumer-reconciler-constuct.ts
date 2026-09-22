import * as path from 'node:path';
import { Duration, Stack } from 'aws-cdk-lib';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Trigger } from 'aws-cdk-lib/triggers';
import { Construct } from 'constructs';

import { getRemovalPolicy } from 'cdk/constants/environment';
import { Checkov } from 'cdk/lib/checkov/checkov';

export type ConsumerReconcilerMode = 'dry-run' | 'apply';

export interface ConsumerReconcilerConstructProps {
  readonly developerId?: string;
  readonly environment: string;
  readonly mode: ConsumerReconcilerMode;
  readonly api: apigateway.RestApi;
  /**
   * Passed as a literal rather than read from `api.deploymentStage`: the
   * function must not depend on the stage, because the stage's deployment
   * depends on the deploy-time Trigger (see below).
   */
  readonly stageName: string;
  readonly ownVpcEndpointId: string;
  /** SSM path the external params repo writes one parameter per consumer under */
  readonly consumerParamPath: string;
  readonly crossAccountPrincipals?: string[];
  readonly kmsKey: kms.IKey;
  readonly logRetentionDays?: logs.RetentionDays;
  /** Changes every release so the deploy-time Trigger re-asserts state each time */
  readonly version: string;
  readonly tags: Record<string, string>;
}

/**
 * Provisions external API consumers from SSM at runtime, so onboarding or
 * changing a consumer in the params repo does not need a deploy of this repo.
 * See src/consumerReconcilerLambda/handler.ts and docs/external-consumers.md.
 */
export class ConsumerReconcilerConstruct extends Construct {
  public readonly function: lambda.Function;
  public readonly permissionsBoundary: iam.ManagedPolicy;

  constructor(
    scope: Construct,
    id: string,
    props: ConsumerReconcilerConstructProps,
  ) {
    super(scope, id);

    const {
      developerId,
      environment,
      mode,
      api,
      stageName,
      ownVpcEndpointId,
      consumerParamPath,
      crossAccountPrincipals = [],
      kmsKey,
      logRetentionDays = logs.RetentionDays.ONE_YEAR,
      version,
      tags,
    } = props;

    const { region, account, urlSuffix } = Stack.of(this);
    const resourcePrefix = developerId
      ? `${developerId}-${environment}`
      : environment;
    // Must match ConsumerConfigConstruct so existing secrets and key are adopted.
    const secretPathPrefix = developerId
      ? `/udp/${developerId}/${environment}`
      : `/udp/${environment}`;
    const keyAlias = `alias/${secretPathPrefix}-consumer-config`;
    const paramPath = consumerParamPath.replace(/\/+$/, '');
    const functionName = `${resourcePrefix}-consumer-reconciler`;
    const consumerRoleArns = `arn:aws:iam::${account}:role/${resourcePrefix}-consumer-*-role`;
    const apigw = (p: string) => `arn:aws:apigateway:${region}::${p}`;

    // Ceiling on anything the reconciler can grant a consumer role: invoking
    // this API. Even a compromised params repo cannot use the reconciler to
    // mint a role with broader access.
    this.permissionsBoundary = new iam.ManagedPolicy(
      this,
      'ConsumerRoleBoundary',
      {
        managedPolicyName: `${resourcePrefix}-consumer-role-boundary`,
        description: `Permissions boundary for external API consumer roles (${resourcePrefix})`,
        statements: [
          new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: ['execute-api:Invoke'],
            resources: [
              `arn:aws:execute-api:${region}:${account}:${api.restApiId}/*`,
            ],
          }),
        ],
      },
    );

    const logGroup = new logs.LogGroup(this, 'LogGroup', {
      logGroupName: `/aws/lambda/${functionName}`,
      retention: logRetentionDays,
      removalPolicy: getRemovalPolicy(environment),
      encryptionKey: kmsKey,
    });

    const deadLetterQueue = new sqs.Queue(this, 'DeadLetterQueue', {
      queueName: `${functionName}-dlq`,
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: kmsKey,
      retentionPeriod: Duration.days(14),
    });

    this.function = new lambda.Function(this, 'Function', {
      functionName,
      description: `Reconciles external API consumers from SSM (${mode})`,
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(
        path.resolve(process.cwd(), '..', 'build', 'consumerReconcilerLambda'),
      ),
      timeout: Duration.minutes(5),
      memorySize: 256,
      logGroup,
      tracing: lambda.Tracing.ACTIVE,
      environmentEncryption: kmsKey,
      // Serialise runs so two SSM changes can never interleave their writes.
      reservedConcurrentExecutions: 1,
      deadLetterQueue,
      retryAttempts: 2,
      environment: {
        MODE: mode,
        ENVIRONMENT: environment,
        RESOURCE_PREFIX: resourcePrefix,
        SECRET_PATH_PREFIX: secretPathPrefix,
        CONSUMER_PARAM_PATH: paramPath,
        REST_API_ID: api.restApiId,
        STAGE_NAME: stageName,
        // Same value as api.url, without the dependency on the stage.
        API_URL: `https://${api.restApiId}.execute-api.${region}.${urlSuffix}/${stageName}/`,
        OWN_VPCE_ID: ownVpcEndpointId,
        ACCOUNT_ID: account,
        PERMISSIONS_BOUNDARY_ARN: this.permissionsBoundary.managedPolicyArn,
        CROSS_ACCOUNT_PRINCIPALS: JSON.stringify(crossAccountPrincipals),
        RESOURCE_TAGS: JSON.stringify({
          ...tags,
          ManagedBy: 'consumer-reconciler',
        }),
        RELEASE_VERSION: version,
      },
    });
    Checkov.suppress(this.function, 'CKV_AWS_117');

    this.grantPermissions({
      paramPath,
      consumerRoleArns,
      keyAlias,
      secretPathPrefix,
      apigw,
      restApiId: api.restApiId,
      region,
      account,
    });

    new events.Rule(this, 'ParamChangeRule', {
      ruleName: `${functionName}-param-change`,
      description: `Reconcile external consumers when ${paramPath}/* changes`,
      eventPattern: {
        source: ['aws.ssm'],
        detailType: ['Parameter Store Change'],
        detail: {
          name: [{ prefix: `${paramPath}/` }],
          operation: ['Create', 'Update', 'Delete'],
        },
      },
      targets: [
        new targets.LambdaFunction(this.function, {
          retryAttempts: 2,
          maxEventAge: Duration.hours(1),
        }),
      ],
    });

    // Runs on every deploy (RELEASE_VERSION changes the function each release).
    //
    // Ordering matters. CDK hashes the whole RestApi (including its resource
    // policy) into the API Deployment's logical id, so when CloudFormation
    // changes the policy it also creates a new Deployment, which snapshots
    // whatever policy is live at that moment. Running after the RestApi update
    // but before the Deployment means the reconciler has already restored the
    // full consumer policy by the time that snapshot is taken, so consumers
    // are never locked out by the static policy in the template.
    new Trigger(this, 'DeployReconcile', {
      handler: this.function,
      executeAfter: [
        api.node.defaultChild as apigateway.CfnRestApi,
        this.function,
        this.permissionsBoundary,
      ],
      executeBefore: [api.latestDeployment!],
      executeOnHandlerChange: true,
      timeout: Duration.minutes(5),
    });
  }

  private grantPermissions({
    paramPath,
    consumerRoleArns,
    keyAlias,
    secretPathPrefix,
    apigw,
    restApiId,
    region,
    account,
  }: {
    paramPath: string;
    consumerRoleArns: string;
    keyAlias: string;
    secretPathPrefix: string;
    apigw: (p: string) => string;
    restApiId: string;
    region: string;
    account: string;
  }): void {
    const boundaryArn = this.permissionsBoundary.managedPolicyArn;
    const keyArns = `arn:aws:kms:${region}:${account}:key/*`;
    const keyHasAlias = {
      'ForAnyValue:StringEquals': { 'kms:ResourceAliases': keyAlias },
    };

    const statements = [
      new iam.PolicyStatement({
        sid: 'ReadConsumerParams',
        actions: ['ssm:GetParametersByPath'],
        resources: [`arn:aws:ssm:${region}:${account}:parameter${paramPath}`],
      }),

      // IAM: read and reshape consumer roles by name only.
      new iam.PolicyStatement({
        sid: 'ManageConsumerRoles',
        actions: [
          'iam:GetRole',
          'iam:GetRolePolicy',
          'iam:ListRolePolicies',
          'iam:TagRole',
          'iam:UpdateAssumeRolePolicy',
          'iam:UpdateRole',
        ],
        resources: [consumerRoleArns],
      }),
      // Anything that creates a role or changes what it can do requires the
      // role to carry (or be given) the boundary.
      new iam.PolicyStatement({
        sid: 'ManageConsumerRolePermissionsWithinBoundary',
        actions: [
          'iam:CreateRole',
          'iam:DeleteRolePolicy',
          'iam:PutRolePermissionsBoundary',
          'iam:PutRolePolicy',
        ],
        resources: [consumerRoleArns],
        conditions: {
          StringEquals: { 'iam:PermissionsBoundary': boundaryArn },
        },
      }),
      new iam.PolicyStatement({
        sid: 'NeverRemoveBoundaryOrDeleteRoles',
        effect: iam.Effect.DENY,
        actions: [
          'iam:AttachRolePolicy',
          'iam:DeleteRole',
          'iam:DeleteRolePermissionsBoundary',
        ],
        resources: ['*'],
      }),

      // API Gateway: API keys, usage plans, and this API's policy/deployments.
      new iam.PolicyStatement({
        sid: 'ManageApiKeysAndUsagePlans',
        actions: [
          'apigateway:GET',
          'apigateway:POST',
          'apigateway:PATCH',
          'apigateway:PUT',
        ],
        resources: [
          apigw('/apikeys'),
          apigw('/apikeys/*'),
          apigw('/usageplans'),
          apigw('/usageplans/*'),
          apigw('/tags/*'),
        ],
      }),
      new iam.PolicyStatement({
        sid: 'ManageApiResourcePolicy',
        actions: ['apigateway:GET', 'apigateway:PATCH'],
        resources: [apigw(`/restapis/${restApiId}`)],
      }),
      new iam.PolicyStatement({
        sid: 'RedeployApiStage',
        actions: ['apigateway:POST'],
        resources: [apigw(`/restapis/${restApiId}/deployments`)],
      }),

      // KMS: only the consumer config key, identified by its alias.
      new iam.PolicyStatement({
        sid: 'ManageConsumerConfigKey',
        actions: ['kms:GetKeyPolicy', 'kms:PutKeyPolicy'],
        resources: [keyArns],
        conditions: keyHasAlias,
      }),
      new iam.PolicyStatement({
        // DescribeKey is unconditional so looking up a not-yet-created alias
        // returns NotFound rather than AccessDenied.
        sid: 'DescribeAndCreateConsumerConfigKey',
        actions: ['kms:CreateKey', 'kms:DescribeKey', 'kms:TagResource'],
        resources: ['*'],
      }),
      new iam.PolicyStatement({
        sid: 'CreateConsumerConfigKeyAlias',
        actions: ['kms:CreateAlias', 'kms:EnableKeyRotation'],
        resources: [keyArns, `arn:aws:kms:${region}:${account}:${keyAlias}`],
      }),
      new iam.PolicyStatement({
        sid: 'NeverBypassKeyLockoutCheck',
        effect: iam.Effect.DENY,
        actions: ['kms:CreateKey', 'kms:PutKeyPolicy'],
        resources: ['*'],
        conditions: {
          Bool: { 'kms:BypassPolicyLockoutSafetyCheck': 'true' },
        },
      }),
      new iam.PolicyStatement({
        sid: 'UseConsumerConfigKeyViaSecretsManager',
        actions: ['kms:Decrypt', 'kms:Encrypt', 'kms:GenerateDataKey'],
        resources: [keyArns],
        conditions: {
          ...keyHasAlias,
          StringEquals: {
            'kms:ViaService': `secretsmanager.${region}.amazonaws.com`,
          },
        },
      }),

      // Secrets Manager: consumer config secrets only.
      new iam.PolicyStatement({
        sid: 'ManageConsumerSecrets',
        actions: [
          'secretsmanager:CreateSecret',
          'secretsmanager:DeleteResourcePolicy',
          'secretsmanager:DescribeSecret',
          'secretsmanager:GetResourcePolicy',
          'secretsmanager:GetSecretValue',
          'secretsmanager:PutResourcePolicy',
          'secretsmanager:PutSecretValue',
          'secretsmanager:TagResource',
        ],
        resources: [
          `arn:aws:secretsmanager:${region}:${account}:secret:${secretPathPrefix}/consumers/*`,
        ],
      }),
      new iam.PolicyStatement({
        sid: 'ListSecrets',
        actions: ['secretsmanager:ListSecrets'],
        resources: ['*'],
      }),
    ];

    statements.forEach((s) => this.function.addToRolePolicy(s));
  }
}

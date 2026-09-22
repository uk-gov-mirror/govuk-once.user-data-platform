import { CfnOutput, Stack, StackProps } from 'aws-cdk-lib';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as iam from 'aws-cdk-lib/aws-iam';
import { SlackChannelConfiguration } from 'aws-cdk-lib/aws-chatbot';

import { KmsConstruct } from '../constructs/kms-construct';
import { DynamoDBConstruct } from '../constructs/dynamodb-construct';
import { ApiGatewayConstruct } from '../constructs/api-gateway-construct';
import { LambdaApiConstruct } from '../constructs/lambda-construct';
import { AppConfigConstruct } from '../constructs/appconfig-construct';
import { featureFlagsByEnvironment } from '../../constants/appconfig-feature-flags';
import { WafConstruct } from '../constructs/waf-construct';
import { MacieAccess } from '../macie/macie-access';

import type { ISecret } from 'aws-cdk-lib/aws-secretsmanager';
import type { IRole } from 'aws-cdk-lib/aws-iam';

import { routes } from '@libs/utils';
import {
  ConsumerConfigConstruct,
  ExternalConsumerConfig,
} from '../constructs/consumer-config-construct';
import {
  IamConsumerConfig,
  IamConsumerConstruct,
} from '../constructs/iam-consumer-construct';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import {
  environmentLongNames,
  getLogRetentionPeriod,
} from 'cdk/constants/environment';
import {
  ConsumerThrottleConfig,
  ConsumerUsagePlanConstruct,
} from '../constructs/consumer-usage-plan-construct';
import { ConsumerReconcilerConstruct } from '../constructs/consumer-reconciler-constuct';
import { ConsumerProvisioningByEnvironment } from 'cdk/constants/consumers';

// type RoutesConfig = Record<string, RouteConfig>;

export interface MainStackProps extends StackProps {
  developerId?: string;
  environment: string;
  serviceName: string;
  teamName: string;
  repositoryUrl: string;
  version: string;
  stackPrefix: string;
  vpcEndpointId?: string;
  crossAccountPrincipals?: string[];
  vpc?: ec2.IVpc;
  lambdaSecurityGroup?: ec2.ISecurityGroup;
  codebuildSecurityGroup?: ec2.ISecurityGroup;
  availabilityZones?: string[];
  dynamoDbEndpointUrl?: string;
}

export class MainStack extends Stack {
  public readonly table: dynamodb.Table;
  public readonly identityTable: dynamodb.Table;
  public readonly api: apigateway.RestApi;
  public readonly lambdas: lambda.Function[];
  public readonly kmsKey: kms.IKey;
  public readonly dbKmsKey: kms.IKey;
  public readonly dsarQueue?: sqs.Queue;
  public readonly sarQueue?: sqs.Queue;
  public readonly appConfigApplicationId: string;
  public readonly appConfigEnvironmentId: string;
  public readonly appConfigProfileId: string;
  public readonly e2eTestConsumerSecret?: ISecret;
  public readonly e2eTestConsumerRole?: IRole;
  public readonly e2eTestConsumerApiKeyValue?: string;
  public readonly waf: WafConstruct;
  public readonly consumerReconciler?: ConsumerReconcilerConstruct;

  constructor(scope: Construct, id: string, props: MainStackProps) {
    super(scope, id, props);

    const {
      developerId,
      environment,
      serviceName,
      teamName,
      version,
      stackPrefix,
      vpcEndpointId,
      crossAccountPrincipals = [],
      vpc,
      lambdaSecurityGroup,
      dynamoDbEndpointUrl,
    } = props;

    // Filter out SAR / DSAR routes based on env !== prod
    // let routes: RoutesConfig = _routes;
    // const isProd = environment === GovUkOnceEnvironments.Prod;
    // if (isProd) {
    //   routes = Object.fromEntries(
    //     Object.entries(_routes).filter(([, route]) => !route?.disableRoute),
    //   );
    // }

    const consumerParamPath = `/${environmentLongNames[environment]}/udp-params/udp/externalConsumers`;

    const isSharedEnvironment = !developerId;
    const consumersOwnedByReconciler =
      isSharedEnvironment &&
      ConsumerProvisioningByEnvironment[environment] === 'reconciler';

    let externalConsumers: Record<
      string,
      ExternalConsumerConfig & { vpcEndpointId?: string }
    > = {};
    if (!consumersOwnedByReconciler) {
      try {
        const ssmValue = StringParameter.valueFromLookup(
          this,
          consumerParamPath,
          '{}',
        );

        externalConsumers = JSON.parse(ssmValue);
      } catch {
        console.log(
          'JSON.parse(externalConsumers) error externalConsumers in MainStack',
        );
      }
    }
    const retainConsumers = isSharedEnvironment
      ? Object.keys(externalConsumers)
      : [];

    const consumerVpcEndpointIds: string[] = Object.values(externalConsumers)
      .map((c) => c.vpcEndpointId)
      .filter((id): id is string => !!id);

    cdk.Tags.of(this).add('ServiceName', serviceName || 'UnknownService');
    cdk.Tags.of(this).add('TeamName', teamName || 'UnknownTeam');
    cdk.Tags.of(this).add('Environment', environment || 'UnknownEnvironment');
    cdk.Tags.of(this).add('Version', version || '0.0.0');

    //Disabling caching temporarily -- need to seek out a better way to invalidate the caches rather than allowing default TTL to run down
    // const cachingEnabled = environment !== GovUkOnceEnvironments.Dev;
    const cachingEnabled = false;

    const kmsConstruct = new KmsConstruct(this, 'Kms', {
      developerId,
      environment,
      namePrefix: 'encryption',
    });
    this.kmsKey = kmsConstruct.key;
    MacieAccess.markKMSKeyForAccess(this.kmsKey);

    const dbKms = new KmsConstruct(this, 'dbKms', {
      developerId,
      environment,
      namePrefix: 'db-kms-encryption',
    });
    this.dbKmsKey = dbKms.key;

    const db = new DynamoDBConstruct(this, 'DynamoDb', {
      developerId,
      environment,
      tableName: 'udp-data',
      kmsKey: kmsConstruct.key,
      ttlAttributeName: 'ttl',
    });

    this.table = db.table;

    const identityDb = new DynamoDBConstruct(this, 'IdentityDynamoDb', {
      developerId,
      environment,
      tableName: 'udp-identity',
      kmsKey: kmsConstruct.key,
      globalSecondaryIndexes: [
        {
          indexName: 'sk-index',
          partitionKeyName: 'sk',
          sortKeyName: 'pk',
        },
      ],
      ttlAttributeName: 'ttl',
    });

    this.identityTable = identityDb.table;

    const featureFlags =
      featureFlagsByEnvironment[environment] ?? featureFlagsByEnvironment.dev;

    const appConfig = new AppConfigConstruct(this, 'AppConfig', {
      developerId,
      environment,
      applicationName: `${serviceName}-appconfig`,
      featureFlags,
    });

    this.appConfigApplicationId = appConfig.application.ref;
    this.appConfigEnvironmentId = appConfig.environment.ref;
    this.appConfigProfileId = appConfig.configurationProfile.ref;

    const apiGateway = new ApiGatewayConstruct(this, 'Api', {
      developerId,
      environment,
      apiName: 'api',
      ownVpcEndpointId: vpcEndpointId,
      policyVpcEndpointIds: vpcEndpointId
        ? [vpcEndpointId, ...consumerVpcEndpointIds]
        : [],
      crossAccountPrincipals,
      kmsKey: kmsConstruct.key,
      cachingEnabled,
    });
    this.api = apiGateway.api;

    if (isSharedEnvironment && vpcEndpointId) {
      this.consumerReconciler = new ConsumerReconcilerConstruct(
        this,
        'ConsumerReconciler',
        {
          environment,
          mode: consumersOwnedByReconciler ? 'apply' : 'dry-run',
          api: this.api,
          stageName: environment,
          ownVpcEndpointId: vpcEndpointId,
          consumerParamPath,
          crossAccountPrincipals,
          kmsKey: kmsConstruct.key,
          logRetentionDays: getLogRetentionPeriod(environment),
          version,
          tags: {
            Environment: environment,
            ServiceName: serviceName,
            teamName: teamName,
          },
        },
      );
    }

    this.waf = new WafConstruct(this, 'waf', {
      developerId,
      environment,
      namePrefix: 'api',
      apiGatewayStageArn: apiGateway.stageArn,
      rateLimiting: { enabled: true, limit: 300000 },
      sqlInjectionRule: { enabled: true, action: 'block' },
      commonRuleSet: { enabled: true, action: 'block' },
      kmsKey: kmsConstruct.key,
      logRetentionDays: getLogRetentionPeriod(environment),
    });

    const eventQueues = this.createEventQueues(
      developerId,
      environment,
      kmsConstruct.key,
    );

    this.lambdas = this.createLambdaFunctions({
      developerId,
      environment,
      stackPrefix,
      kmsKey: kmsConstruct.key,
      dbKmsKey: dbKms.key,
      db,
      identityDb,
      api: apiGateway.api,
      eventQueues,
      vpc,
      lambdaSecurityGroup,
      cachingEnabled,
      dynamoDbEndpointUrl,
    });

    this.dsarQueue = eventQueues.get('dsarQueue')!;
    this.sarQueue = eventQueues.get('sarQueue')!;

    const { IamConsumerConfigs, consumerthrottleConfigs } =
      this.buildConsumerConfigs(externalConsumers);

    const iamConsumers = new IamConsumerConstruct(this, 'IamConsumers', {
      developerId,
      environment,
      api: this.api,
      consumers: IamConsumerConfigs,
      retainConsumers,
    });

    const usagePlans = new ConsumerUsagePlanConstruct(this, `UsagePlans`, {
      developerId,
      environment,
      api: this.api,
      consumers: consumerthrottleConfigs,
      retainConsumers,
    });

    this.e2eTestConsumerApiKeyValue = usagePlans.apiKeyValues.get('test');
    this.e2eTestConsumerRole = iamConsumers.consumerRoles.get('test');

    if (Object.keys(externalConsumers).length > 0) {
      const consumerConfig = new ConsumerConfigConstruct(
        this,
        'ConsumerConfig',
        {
          developerId,
          environment,
          region: this.region,
          accountId: this.account,
          consumerRoles: iamConsumers.consumerRoles,
          externalConsumers,
          apiUrl: this.api.url,
          apiKeyValues: usagePlans.apiKeyValues,
          retainOnRemoval: isSharedEnvironment,
        },
      );

      this.e2eTestConsumerSecret = consumerConfig.consumerSecrets.get('flex');
    }

    if (!developerId?.startsWith('pr')) {
      this.createReleaseNotifications(environment);
    }

    this.createCfnOutputs(id, [
      {
        outputId: 'ApiEndpoint',
        value: this.api.url,
        description: 'Api Endpoint url',
      },
      {
        outputId: 'TableName',
        value: db.table.tableName,
        description: 'DynamoTableName',
      },
      {
        outputId: 'IdentityTableName',
        value: identityDb.table.tableName,
        description: 'Identity DynamoTableName',
      },
      { outputId: 'AwsRegion', value: this.region, description: 'Aws Region' },
      {
        outputId: 'AppConfigApplicationId',
        value: this.appConfigApplicationId,
        description: 'AppConfig Application ID',
      },
      {
        outputId: 'AppConfigEnvironmentId',
        value: this.appConfigEnvironmentId,
        description: 'AppConfig Environment ID',
      },
      {
        outputId: 'AppConfigProfileId',
        value: this.appConfigProfileId,
        description: 'AppConfig Configuration Profile ID',
      },
      {
        outputId: 'KmsKeyArn',
        value: this.kmsKey.keyArn,
        description: 'KMS Key ARN',
      },
    ]);
  }

  private createEventQueues(
    developerId: string | undefined,
    environment: string,
    kmsKey: kms.IKey,
  ): Map<string, sqs.Queue> {
    const eventQueueNames = [
      ...new Set(
        Object.values(routes)
          .map((r) => r.queueName)
          .filter((q): q is string => !!q),
      ),
    ];

    const eventQueues = new Map<string, sqs.Queue>();
    for (const eventQueueName of eventQueueNames) {
      const fullQueueName = developerId
        ? `${developerId}-${eventQueueName}-queue-${environment}`
        : `${eventQueueName}-queue-${environment}`;

      const constructId = `${eventQueueName.replaceAll('-', '')}Queue`;
      const queue = new sqs.Queue(this, constructId, {
        queueName: fullQueueName,
        encryption: sqs.QueueEncryption.KMS,
        encryptionMasterKey: kmsKey,
      });
      eventQueues.set(eventQueueName, queue);
    }
    return eventQueues;
  }

  private createLambdaFunctions(params: {
    developerId: string | undefined;
    environment: string;
    stackPrefix: string;
    kmsKey: kms.IKey;
    dbKmsKey: kms.IKey;
    db: DynamoDBConstruct;
    identityDb: DynamoDBConstruct;
    api: apigateway.RestApi;
    eventQueues: Map<string, sqs.Queue>;
    vpc: ec2.IVpc | undefined;
    lambdaSecurityGroup: ec2.ISecurityGroup | undefined;
    cachingEnabled: boolean;
    dynamoDbEndpointUrl?: string;
  }): lambda.Function[] {
    const {
      developerId,
      environment,
      stackPrefix,
      kmsKey,
      dbKmsKey,
      db,
      identityDb,
      api,
      eventQueues,
      vpc,
      lambdaSecurityGroup,
      cachingEnabled,
      dynamoDbEndpointUrl,
    } = params;

    const lambdasList = [];
    for (const route of Object.values(routes)) {
      const routeQueue = route.queueName
        ? eventQueues.get(route.queueName)
        : undefined;

      const lambdaConstruct = new LambdaApiConstruct(this, route.name, {
        developerId,
        environment,
        functionName: `${route.name}Lambda`,
        sourcePath: `${route.name}Lambda`,
        kmsKey,
        dbKmsKey,
        dynamoDBtable: db.table,
        identityDbTable: identityDb.table,
        identityDbActions: route.identityTableActions ?? ['dynamodb:GetItem'],
        dynamoDbActions: route.dynamoDbActions ?? ['dynamodb:GetItem'],
        api,
        httpMethod: route.method,
        routePath: route.path,
        environmentVariables: {
          STACK: stackPrefix,
          SERVICE_NAME: route.name,
          POWERTOOLS_SERVICE_NAME: route.name,
          ...(dynamoDbEndpointUrl
            ? { DYNAMODB_ENDPOINT: dynamoDbEndpointUrl }
            : {}),
        },
        ...(routeQueue
          ? {
              sqsQueueUrl: routeQueue.queueUrl,
              sqsQueueArn: routeQueue.queueArn,
            }
          : {}),
        vpc,
        securityGroups: lambdaSecurityGroup ? [lambdaSecurityGroup] : [],
        cachingEnabled,
        logRetentionDays: getLogRetentionPeriod(environment),
      });

      lambdasList.push(lambdaConstruct.function);
    }
    return lambdasList;
  }

  private buildConsumerConfigs(
    externalConsumers: Record<
      string,
      ExternalConsumerConfig & { vpcEndpointId?: string }
    >,
  ): {
    IamConsumerConfigs: Record<string, IamConsumerConfig>;
    consumerthrottleConfigs: Record<string, ConsumerThrottleConfig>;
  } {
    const IamConsumerConfigs: Record<string, IamConsumerConfig> = {
      test: {
        permissions: ['read', 'write', 'delete'],
        description: 'Internal E2E test consumer {codebuild}',
      },
    };

    const consumerthrottleConfigs: Record<string, ConsumerThrottleConfig> = {
      test: { rateLimit: 500, burstLimit: 1000 },
    };

    for (const [consumerName, consumerConfig] of Object.entries(
      externalConsumers,
    )) {
      IamConsumerConfigs[consumerName] = {
        permissions: consumerConfig.permissions,
        accountId: consumerConfig.accountId,
        externalId: consumerConfig.externalId,
        description: consumerConfig.description,
      };

      consumerthrottleConfigs[consumerName] = {
        rateLimit: consumerConfig.rateLimit,
        burstLimit: consumerConfig.burstLimit,
      };
    }

    return { IamConsumerConfigs, consumerthrottleConfigs };
  }

  private createCfnOutputs(
    id: string,
    outputs: { outputId: string; value: string; description: string }[],
  ): void {
    for (const { value, description, outputId } of outputs) {
      new CfnOutput(this, outputId, {
        value,
        description,
        exportName: `${id}-${outputId}`,
      });
    }
  }

  private createReleaseNotifications(environment: string): void {
    const releaseTopic = new sns.Topic(this, 'ReleaseTopic', {
      topicName: `${environment}-release-notifications`,
      displayName: `${environment}-release-notifications`,
      masterKey: this.kmsKey,
    });

    const param = `/${environmentLongNames[environment]}/udp-param/udp/release`;
    const ssmValue = StringParameter.valueFromLookup(this, param, '{}');

    let releaseConfig: {
      workspaceId?: string;
      channelId?: string;
    } = {};
    try {
      releaseConfig = JSON.parse(ssmValue);
    } catch {
      console.log('JSON.parse(releaseConfig) error in MainStack');
    }

    if (releaseConfig.workspaceId && releaseConfig.channelId) {
      const slack = new SlackChannelConfiguration(this, `ReleaseSlackChannel`, {
        slackChannelConfigurationName: `${environment}-release-notifications`,
        slackWorkspaceId: releaseConfig.workspaceId,
        slackChannelId: releaseConfig.channelId,
        notificationTopics: [releaseTopic],
        guardrailPolicies: [
          iam.ManagedPolicy.fromAwsManagedPolicyName('ReadOnlyAccess'),
        ],
      });

      slack.role?.addToPrincipalPolicy(
        new iam.PolicyStatement({
          actions: ['kms:Decrypt', 'kms:GenerateDataKey'],
          resources: [this.kmsKey.keyArn],
        }),
      );
    }
  }
}

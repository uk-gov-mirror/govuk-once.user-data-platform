import { RemovalPolicy } from 'aws-cdk-lib';
import {
  ApiKey,
  CfnUsagePlanKey,
  RestApi,
  UsagePlan,
} from 'aws-cdk-lib/aws-apigateway';
import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import {
  AwsCustomResource,
  AwsCustomResourcePolicy,
  PhysicalResourceId,
} from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';

export interface ConsumerThrottleConfig {
  readonly rateLimit?: number;
  readonly burstLimit?: number;
}

export interface ConsumerUsagePlanConstructProps {
  readonly developerId?: string;
  readonly environment: string;
  readonly api: RestApi;
  readonly consumers: Record<string, ConsumerThrottleConfig>;
  readonly defaultRateLimit?: number;
  readonly defaultBurstLimit?: number;
  readonly retainConsumers?: string[];
}

export class ConsumerUsagePlanConstruct extends Construct {
  public readonly apiKeyValues: Map<string, string> = new Map();

  constructor(
    scope: Construct,
    id: string,
    props: ConsumerUsagePlanConstructProps,
  ) {
    super(scope, id);

    const {
      developerId,
      environment,
      api,
      consumers,
      defaultBurstLimit = 10,
      defaultRateLimit = 20,
      retainConsumers = [],
    } = props;

    const prefix = developerId ? `${developerId}-${environment}` : environment;

    for (const [consumerName, config] of Object.entries(consumers)) {
      const rateLimit = config.rateLimit ?? defaultRateLimit;
      const burstLimit = config.burstLimit ?? defaultBurstLimit;

      const apiKey = new ApiKey(this, `ApiKey-${consumerName}`, {
        apiKeyName: `${prefix}-${consumerName}-key`,
        description: `API Key for consumer ${consumerName}`,
        enabled: true,
      });

      const usagePlan = new UsagePlan(this, `UsagePlan-${consumerName}`, {
        name: `${prefix}-${consumerName}-usage-plan`,
        description: `Usage plan for consumer ${consumerName}`,
        throttle: {
          rateLimit,
          burstLimit,
        },
        apiStages: [
          {
            api,
            stage: api.deploymentStage,
          },
        ],
      });

      usagePlan.addApiKey(apiKey);

      if (retainConsumers.includes(consumerName)) {
        apiKey.applyRemovalPolicy(RemovalPolicy.RETAIN);
        usagePlan.applyRemovalPolicy(RemovalPolicy.RETAIN);
        usagePlan.node.children
          .filter((c) => c instanceof CfnUsagePlanKey)
          .forEach((k) => k.applyRemovalPolicy(RemovalPolicy.RETAIN));
      }

      const getApiKeyResource = new AwsCustomResource(
        this,
        `GetApiKeyValue-${consumerName}`,
        {
          onCreate: {
            service: 'APIGateway',
            action: 'getApiKey',
            parameters: {
              apiKey: apiKey.keyId,
              includeValue: true,
            },
            physicalResourceId: PhysicalResourceId.of(apiKey.keyId),
          },
          onUpdate: {
            service: 'APIGateway',
            action: 'getApiKey',
            parameters: {
              apiKey: apiKey.keyId,
              includeValue: true,
            },
            physicalResourceId: PhysicalResourceId.of(apiKey.keyId),
          },
          policy: AwsCustomResourcePolicy.fromStatements([
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['apigateway:GET'],
              resources: [`arn:aws:apigateway:*::/apikeys/*`],
            }),
          ]),
        },
      );
      getApiKeyResource.node.addDependency(apiKey);

      const keyValue = getApiKeyResource.getResponseField('value');
      this.apiKeyValues.set(consumerName, keyValue);
    }
  }
}

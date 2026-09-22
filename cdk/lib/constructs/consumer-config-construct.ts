import { CfnOutput, RemovalPolicy, SecretValue } from 'aws-cdk-lib';
import {
  AccountPrincipal,
  Effect,
  PolicyStatement,
  Role,
} from 'aws-cdk-lib/aws-iam';
import { Alias, Key } from 'aws-cdk-lib/aws-kms';
import { Secret } from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';

export interface ExternalConsumerConfig {
  readonly accountId: string;
  readonly permissions: ('read' | 'write' | 'delete')[];
  readonly externalId?: string;
  readonly description?: string;
  readonly rateLimit?: number;
  readonly burstLimit?: number;
}

export interface ConsumerConfigProps {
  readonly developerId?: string;
  readonly environment: string;
  readonly region: string;
  readonly accountId: string;
  readonly consumerRoles: Map<string, Role>;
  readonly externalConsumers: Record<string, ExternalConsumerConfig>;
  readonly apiUrl: string;
  readonly apiKeyValues?: Map<string, string>;

  readonly retainOnRemoval?: boolean;
}

export class ConsumerConfigConstruct extends Construct {
  public readonly consumerSecrets: Map<string, Secret> = new Map();

  constructor(scope: Construct, id: string, props: ConsumerConfigProps) {
    super(scope, id);

    const {
      developerId,
      environment,
      region,
      accountId,
      consumerRoles,
      externalConsumers,
      apiUrl,
      apiKeyValues,
      retainOnRemoval = false,
    } = props;

    const secretPathPrefix = developerId
      ? `/udp/${developerId}/${environment}`
      : `/udp/${environment}`;

    const key = new Key(this, 'ConsumerConfigKey', {
      alias: `alias/${secretPathPrefix}-consumer-config`,
      enableKeyRotation: true,
    });

    if (retainOnRemoval) {
      key.applyRemovalPolicy(RemovalPolicy.RETAIN);
      (key.node.tryFindChild('Alias') as Alias).applyRemovalPolicy(
        getRemovalPolicy.RETAIN,
      );
    }

    for (const [consumerName, consumerConfig] of Object.entries(
      externalConsumers,
    )) {
      key.addToResourcePolicy(
        new PolicyStatement({
          sid: `AllowDecryptFor${consumerName.toUpperCase()}`,
          principals: [new AccountPrincipal(consumerConfig.accountId)],
          actions: ['kms:Decrypt', 'kms:DescribeKey'],
          resources: ['*'],
        }),
      );

      const consumerRole = consumerRoles.get(consumerName);

      if (!consumerRole) {
        throw new Error(
          `External consumer ${consumerName} does not have a matching IAM Consumer Role`,
        );
      }

      const secretValue: Record<string, SecretValue> = {
        region: SecretValue.unsafePlainText(region),
        apiAccountId: SecretValue.unsafePlainText(accountId),
        apiUrl: SecretValue.unsafePlainText(apiUrl),
        consumerRoleArn: SecretValue.unsafePlainText(consumerRole.roleArn),
      };

      if (consumerConfig.externalId) {
        secretValue.externalId = SecretValue.unsafePlainText(
          consumerConfig.externalId,
        );
      }
      const apiKeyValue = apiKeyValues?.get(consumerName);
      if (apiKeyValue) {
        secretValue.apiKey = SecretValue.unsafePlainText(apiKeyValue);
      }

      const secret = new Secret(this, `Secret${consumerName.toUpperCase()}`, {
        secretName: `${secretPathPrefix}/consumers/${consumerName}/config`,
        description: `Api configuration for external consumer ${consumerName}`,
        secretObjectValue: secretValue,
        encryptionKey: key,
      });

      secret.addToResourcePolicy(
        new PolicyStatement({
          sid: `AllowCrossAccountRead${consumerName.toUpperCase()}`,
          effect: Effect.ALLOW,
          principals: [new AccountPrincipal(consumerConfig.accountId)],
          actions: ['secretsmanager:GetSecretValue'],
          resources: ['*'],
        }),
      );

      if (retainOnRemoval) {
        secret.applyRemovalPolicy(RemovalPolicy.RETAIN);
        (
          secret.node.tryFindChild('Policy') as RemovalPolicy
        ).applyRemovalPolicy(RemovalPolicy.RETAIN);
      }

      this.consumerSecrets.set(consumerName, secret);

      new CfnOutput(this, `ConsumerSecretArn-${consumerName}`, {
        value: secret.secretArn,
        description: `Secret ARN for external consumer ${consumerName}`,
      });

      new CfnOutput(this, `ConsumerSecretName-${consumerName}`, {
        value: secret.secretName,
        description: `Secret Name for external consumer ${consumerName}`,
      });
    }
  }
}

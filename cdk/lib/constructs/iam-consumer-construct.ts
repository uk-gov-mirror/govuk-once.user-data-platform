import { CfnOutput, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { RestApi } from 'aws-cdk-lib/aws-apigateway';
import {
  AccountPrincipal,
  Effect,
  IPrincipal,
  Policy,
  PolicyStatement,
  Role,
  ServicePrincipal,
} from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export type Permission = 'read' | 'write' | 'delete';

export interface IamConsumerConfig {
  readonly permissions: Permission[];
  readonly accountId?: string;
  readonly externalId?: string;
  readonly description?: string;
}

export interface IamConsumerConstructProps {
  readonly developerId?: string;
  readonly environment: string;
  readonly api: RestApi;
  readonly consumers: Record<string, IamConsumerConfig>;
  readonly retainConsumers?: string[];
}

const PERMISSIONS_TO_METHODS: Record<Permission, string[]> = {
  read: ['GET'],
  write: ['POST', 'PUT', 'PATCH'],
  delete: ['DELETE'],
};

export class IamConsumerConstruct extends Construct {
  public readonly consumerRoles: Map<string, Role> = new Map();

  constructor(scope: Construct, id: string, props: IamConsumerConstructProps) {
    super(scope, id);

    const {
      developerId,
      environment,
      api,
      consumers,
      retainConsumers = [],
    } = props;

    const stack = Stack.of(this);
    const resourcePrefix = developerId
      ? `${developerId}-${environment}`
      : environment;

    for (const [consumerName, consumerConfig] of Object.entries(consumers)) {
      const roleName = `${resourcePrefix}-consumer-${consumerName}-role`;

      const trustPrincipal = consumerConfig.accountId
        ? this.createCrossAccountTrustPrincipal(
            consumerConfig.accountId,
            consumerConfig.externalId,
          )
        : new ServicePrincipal('codebuild.amazonaws.com');

      const role = new Role(this, `ConsumerRole-${consumerName}`, {
        roleName,
        assumedBy: trustPrincipal,
        description:
          consumerConfig.description ||
          `API Consumer role for  ${consumerName} = ${environment}`,
      });

      const apiResources = this.buildApiResourceArns(
        stack,
        api,
        consumerConfig.permissions,
      );

      role.addToPolicy(
        new PolicyStatement({
          sid: 'AllowApiGatewayInvoke',
          effect: Effect.ALLOW,
          actions: [`execute-api:Invoke`],
          resources: apiResources,
        }),
      );

      if (retainConsumers.includes(consumerName)) {
        role.applyRemovalPolicy(RemovalPolicy.RETAIN);
        (role.node.tryFindChild('DefaultPolicy') as Policy).applyRemovalPolicy(
          RemovalPolicy.RETAIN,
        );
      }

      this.consumerRoles.set(consumerName, role);

      new CfnOutput(this, `ConsumerRoleArns-${consumerName}`, {
        value: role.roleArn,
        description: `IAM Role ARN for consumer ${consumerName}`,
        exportName: `${stack.stackName}-ConsumerRoleArn-${consumerName}`,
      });

      new CfnOutput(this, `ConsumerRoleName-${consumerName}`, {
        value: role.roleName,
        description: `IAM Role name for consumer ${consumerName}`,
        exportName: `${stack.stackName}-ConsumerRoleName-${consumerName}`,
      });
    }
  }

  private createCrossAccountTrustPrincipal(
    accountId: string,
    externalId?: string,
  ): IPrincipal {
    const principal = new AccountPrincipal(accountId);

    if (externalId) {
      return principal.withConditions({
        StringEquals: {
          'sts:ExternalId': externalId,
        },
      });
    }

    return principal;
  }

  private buildApiResourceArns(
    stack: Stack,
    api: RestApi,
    permissions: Permission[],
  ): string[] {
    const resources: string[] = [];

    for (const permission of permissions) {
      const methods = PERMISSIONS_TO_METHODS[permission];
      for (const method of methods) {
        resources.push(
          `arn:aws:execute-api:${stack.region}:${stack.account}:${api.restApiId}/*/${method}/*`,
        );
      }
    }

    return resources;
  }
}

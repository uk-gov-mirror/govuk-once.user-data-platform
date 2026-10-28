import { Aws, CfnOutput, Duration, Fn, Stack, StackProps } from 'aws-cdk-lib';
import { CfnCluster } from 'aws-cdk-lib/aws-dsql';
import {
  FilterCriteria,
  FilterRule,
  IFunction,
  StartingPosition,
} from 'aws-cdk-lib/aws-lambda';
import { IQueue, Queue, QueueEncryption } from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import { GovUkOnceEnvironments } from '../macie';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { IKey, Key, KeySpec, KeyUsage } from 'aws-cdk-lib/aws-kms';
import { Table } from 'aws-cdk-lib/aws-dynamodb';
import {
  InterfaceVpcEndpoint,
  InterfaceVpcEndpointService,
  IVpc,
  Peer,
  Port,
  SecurityGroup,
  SubnetSelection,
  SubnetType,
  Vpc,
} from 'aws-cdk-lib/aws-ec2';
import {
  getLogRetentionPeriod,
  getRemovalPolicy,
} from 'cdk/constants/environment';
import { LambdaApiConstruct } from '../constructs/lambda-construct';
import { PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { mainStackParameterNames } from 'cdk/constants/shared-parameters';
import { SqsDlq } from 'aws-cdk-lib/aws-lambda-event-sources';
import { GovUKTag } from '../gov-uk-tag';
import { Trigger } from 'aws-cdk-lib/triggers';
import { RetentionDays } from 'aws-cdk-lib/aws-logs';

const DSQL_PORT = 5432;

export interface LiveSchemaStackProps extends StackProps {
  developerId?: string;
  environment: string;
  stackPrefix: string;
  createDsqlVpcEndpoint?: boolean;
}

export type CommonProps = {
  developerId?: string;
  environment: string;
  kmsKey: IKey;
  vpc: IVpc;
  vpcSubnets: SubnetSelection;
  securityGroups: SecurityGroup[];
  logRetentionDays: RetentionDays;
};

export class LiveSchemaStack extends Stack {
  public readonly schemaExtractorLambda: IFunction;

  public readonly lambdas: IFunction[];
  public readonly cluster: CfnCluster;
  public readonly failureQueue: IQueue;

  public readonly commonLambdaProps: CommonProps;

  constructor(scope: Construct, id: string, props: LiveSchemaStackProps) {
    super(scope, id, props);

    const {
      developerId,
      environment,
      stackPrefix,
      createDsqlVpcEndpoint = !developerId,
    } = props;

    const isStageOrProd =
      environment === GovUkOnceEnvironments.Prod ||
      environment === GovUkOnceEnvironments.Stag;

    const namePrefix = developerId ? `${developerId}-` : '';

    const params = mainStackParameterNames(stackPrefix);
    const resolve = (name: string) =>
      StringParameter.valueForStringParameter(this, name);

    const kmsKey = Key.fromKeyArn(this, 'KmsKey', resolve(params.kmsKeyArn));
    const dbKmsKey = Key.fromKeyArn(
      this,
      'DbKmsKey',
      resolve(params.dbKmsKeyArn),
    );

    const dataTable = Table.fromTableAttributes(this, 'DataTable', {
      tableName: `${namePrefix}udp-data-${environment}`,
      tableStreamArn: resolve(params.dataTableStreamArn),
      encryptionKey: kmsKey,
    });

    const vpc = Vpc.fromLookup(this, 'Vpc', {
      vpcName: `udp-api-vpc-${environment}`,
      tags: { 'aws:cloudformation:stack-name': `${environment}-vpc` },
    });

    const isolatedSubnets = { subnetType: SubnetType.PRIVATE_ISOLATED };

    const lambdaSecurityGroup = this.createLambdaSecurityGroup(
      vpc,
      `${namePrefix}live-schema-lambda-dg-${environment}`,
    );

    this.cluster = new CfnCluster(this, 'Cluster', {
      deletionProtectionEnabled: isStageOrProd,
      tags: [{ key: 'Name', value: `${namePrefix}live-schema-${environment}` }],
    });

    this.cluster.applyRemovalPolicy(getRemovalPolicy(environment));

    const dsqlEndpoint = createDsqlVpcEndpoint
      ? this.createDsqlEndpoint(vpc, isolatedSubnets, environment)
      : undefined;

    this.commonLambdaProps = {
      developerId,
      environment,
      kmsKey,
      vpc,
      vpcSubnets: isolatedSubnets,
      securityGroups: [lambdaSecurityGroup],
      logRetentionDays: getLogRetentionPeriod(environment),
    };

    const userIdHmacKey = new Key(this, 'UserIdHmacKey', {
      description: `${namePrefix}live-user-id-hmac-${environment} udpUserId key`,
      keySpec: KeySpec.HMAC_256,
      keyUsage: KeyUsage.GENERATE_VERIFY_MAC,
      alias: `${namePrefix}live-user-id-hmac-${environment}`,
      removalPolicy: getRemovalPolicy(environment),
    });

    GovUKTag.of(userIdHmacKey).DataClassification.OFFICIAL_SENSITIVE();

    const schemaExtractorConstruct = new LambdaApiConstruct(
      this,
      'LiveSchemaExtractor',
      {
        ...this.commonLambdaProps,
        functionName: 'liveSchemaExtractorLambda',
        sourcePath: 'liveSchemaExtractorLambda',
        dbKmsKey,
        timeout: Duration.seconds(60),
        environmentVariables: {
          ...this.lambdaEnv(stackPrefix, 'liveSchemaExtractor'),
          DATA_TABLE_NAME: dataTable.tableName,
          DYNAMO_ENDPOINT: resolve(params.dynamoDbEndpointUrl),
          USER_ID_HMAC_KEY_ID: userIdHmacKey.keyArn,
        },
      },
    );

    GovUKTag.of(schemaExtractorConstruct)
      .DataClassification.OFFICIAL_SENSITIVE()
      .PII.TRUE()
      .Exposure.INTERNAL();

    const schemaExtractor = schemaExtractorConstruct.function;

    this.setupMigration(
      stackPrefix,
      dsqlEndpoint,
      schemaExtractor.role?.roleArn,
    );

    this.grantDsql(schemaExtractor, 'dsql:DbConnect');

    this.failureQueue = new Queue(this, 'StreamFailurQueue', {
      queueName: `${namePrefix}live-schema-stream-failures-${environment}`,
      encryption: QueueEncryption.KMS,
      encryptionMasterKey: kmsKey,
      retentionPeriod: Duration.days(14),
    });

    GovUKTag.of(this.failureQueue)
      .DataClassification.OFFICIAL_SENSITIVE()
      .PII.FALSE()
      .Exposure.INTERNAL();

    dataTable.grantStreamRead(schemaExtractor);
    dataTable.grant(schemaExtractor, 'dynamodb:UpdateItem');
    schemaExtractor.addEventSourceMapping('DataTableStream', {
      eventSourceArn: dataTable.tableStreamArn,
      startingPosition: StartingPosition.LATEST,
      batchSize: 100,
      maxBatchingWindow: Duration.seconds(5),
      bisectBatchOnError: true,
      reportBatchItemFailures: true,
      retryAttempts: 5,
      maxRecordAge: Duration.days(1),
      onFailure: new SqsDlq(this.failureQueue),
      filters: [
        FilterCriteria.filter({
          eventName: FilterRule.or('INSERT', 'MODIFY'),
          dynamodb: {
            NewImage: { schemaEvaluationRequired: { BOOL: [true] } },
          },
        }),
      ],
    });

    this.schemaExtractorLambda = schemaExtractor;
    this.lambdas = [schemaExtractor];

    new CfnOutput(this, 'DsqlClusterEndpoint', {
      value: this.cluster.attrEndpoint,
      description: 'Aurora DSQL cluster endpoint for live schmeas',
    });

    new CfnOutput(this, 'DsqlClusterArn', {
      value: this.cluster.attrResourceArn,
      description: 'Aurora DSQL cluster Arn for live schmeas',
    });
  }

  private lambdaEnv(
    stackPrefix: string,
    serviceName: string,
  ): Record<string, string> {
    return {
      STACK: stackPrefix,
      SERVICE_NAME: serviceName,
      POWERTOOLS_SERVICE_NAME: serviceName,
      DSQL_ENDPOINT: this.privateLinkHostname(),
    };
  }

  private setupMigration(
    stackPrefix: string,
    dsqlEndpoint?: InterfaceVpcEndpoint,
    roleArn?: string,
  ) {
    const migration = new LambdaApiConstruct(this, 'LiveSchemaMigration', {
      ...this.commonLambdaProps,
      functionName: 'liveSchemaMigrationLambda',
      sourcePath: 'liveSchemaMigrationLambda',
      timeout: Duration.minutes(5),
      environmentVariables: {
        ...this.lambdaEnv(stackPrefix, 'liveSchemaMigration'),
        ...(roleArn && { SCHEMA_EXTRACTOR_ROLE_ARN: roleArn }),
      },
    });

    GovUKTag.of(migration)
      .DataClassification.OFFICIAL_SENSITIVE()
      .PII.TRUE()
      .Exposure.INTERNAL();

    this.grantDsql(migration.function, 'dsql:DbConnectAdmin');

    new Trigger(this, 'MigrationTrigger', {
      handler: migration.function,
      timeout: Duration.minutes(5),
      executeAfter: dsqlEndpoint
        ? [this.cluster, dsqlEndpoint]
        : [this.cluster],
    });
  }

  private privateLinkHostname(): string {
    const serviceIdentifier = Fn.select(
      3,
      Fn.split('.', this.cluster.attrVpcEndpointServiceName),
    );
    return `${this.cluster.attrIdentifier}.${serviceIdentifier}.${Aws.REGION}.on.aws`;
  }

  private grantDsql(fn: IFunction, action: string): void {
    fn.addToRolePolicy(
      new PolicyStatement({
        actions: [action],
        resources: [this.cluster.attrResourceArn],
      }),
    );
  }

  private createLambdaSecurityGroup(
    vpc: IVpc,
    securityGroupName: string,
  ): SecurityGroup {
    const sg = new SecurityGroup(this, 'LambdaSg', {
      vpc,
      securityGroupName,
      description: 'Live Schema lambdas - outbound to VPX endpoints and DSQL',
      allowAllOutbound: false,
    });

    const vpcCidr = Peer.ipv4(vpc.vpcCidrBlock);
    sg.addEgressRule(vpcCidr, Port.tcp(443), 'HTTPS to VPC endpoints');
    sg.addEgressRule(vpcCidr, Port.tcp(DSQL_PORT), 'POSTgress tp DSQL');
    sg.addEgressRule(vpcCidr, Port.udp(53), 'DNS (UDP) to VPC resolver');
    sg.addEgressRule(vpcCidr, Port.tcp(53), 'DNS (TCP) to VPC resolver');
    GovUKTag.of(sg).DataClassification.OFFICIAL_SENSITIVE().Exposure.ISOLATED();

    return sg;
  }

  private createDsqlEndpoint(
    vpc: IVpc,
    subnets: SubnetSelection,
    environment: string,
  ): InterfaceVpcEndpoint {
    const sg = new SecurityGroup(this, 'DSQLEndpointSg', {
      vpc,
      securityGroupName: `dsql-endpojnt-sg-${environment}`,
      description: `DSQL VPC endpoint - Postgres from VPC CIDR`,
      allowAllOutbound: false,
    });

    sg.addIngressRule(
      Peer.ipv4(vpc.vpcCidrBlock),
      Port.tcp(DSQL_PORT),
      'Postgres from VPC CIDR',
    );
    GovUKTag.of(sg).DataClassification.OFFICIAL_SENSITIVE().Exposure.ISOLATED();

    const endpoint = new InterfaceVpcEndpoint(this, 'DSQLEndpoint', {
      vpc,
      service: new InterfaceVpcEndpointService(
        this.cluster.attrVpcEndpointServiceName,
        DSQL_PORT,
      ),
      privateDnsEnabled: true,
      subnets,
      securityGroups: [sg],
    });

    GovUKTag.of(endpoint)
      .DataClassification.OFFICIAL_SENSITIVE()
      .Exposure.ISOLATED();

    return endpoint;
  }
}

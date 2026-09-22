import { Construct } from 'constructs';
import { Stack, StackProps, Duration } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as xray from 'aws-cdk-lib/aws-xray';
import * as kms from 'aws-cdk-lib/aws-kms';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { SlackChannelConfiguration } from 'aws-cdk-lib/aws-chatbot';
import { ManagedPolicy, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { GovUkOnceEnvironments } from 'cdk/constants/environment';
import { NFR } from 'cdk/constants/nfr';

export interface MonitorStackProps extends StackProps {
  readonly developerId?: string;
  readonly environment: string;
  readonly table: dynamodb.ITable;
  readonly api: apigateway.RestApi;
  readonly lambdas: lambda.IFunction[];
  readonly consumerReconciler?: lambda.IFunction;
  readonly notificationEmails?: string[];
  readonly stackPrefix: string;
  readonly kmsKeyAlias: string;
}

const mapEnvironments = {
  [GovUkOnceEnvironments.Dev]: 'development',
  [GovUkOnceEnvironments.Stag]: 'staging',
  [GovUkOnceEnvironments.Prod]: 'production',
};

export class MonitoringStack extends Stack {
  public readonly criticalTopic: sns.Topic;
  public readonly warningTopic: sns.Topic;
  public readonly dashboard: cloudwatch.Dashboard;
  public readonly performanceDashboard: cloudwatch.Dashboard;
  public readonly xrayTraceGroup?: xray.CfnGroup;

  constructor(scope: Construct, id: string, props: MonitorStackProps) {
    super(scope, id, props);

    const {
      developerId,
      environment,
      table,
      api,
      lambdas,
      consumerReconciler,
      notificationEmails = [],
      stackPrefix,
      kmsKeyAlias,
    } = props;

    const resourcePrefix = developerId
      ? `${developerId}-${environment}`
      : environment;

    const kmsKey = kms.Alias.fromAliasName(this, 'KmsKeyAlias', kmsKeyAlias);

    this.criticalTopic = new sns.Topic(this, 'CriticalTopic', {
      topicName: `${resourcePrefix}-critical-alarms`,
      displayName: `${resourcePrefix} Critical Alerts`,
      masterKey: kmsKey,
    });

    this.warningTopic = new sns.Topic(this, 'WarningTopic', {
      topicName: `${resourcePrefix}-warning-alarms`,
      displayName: `${resourcePrefix} Warning Alerts`,
      masterKey: kmsKey,
    });

    this.xrayTraceGroup = new xray.CfnGroup(this, developerId || environment, {
      groupName: stackPrefix,
      filterExpression: `annotation[stack] = "${stackPrefix}"`,
      insightsConfiguration: {
        insightsEnabled: true,
        notificationsEnabled: true,
      },
    });

    for (const email of notificationEmails) {
      new sns.Subscription(
        this,
        `Email-${email.replace(/[^a-zA-Z0-9]/g, '')}`,
        {
          topic: this.criticalTopic,
          protocol: sns.SubscriptionProtocol.EMAIL,
          endpoint: email,
        },
      );
    }

    if (!developerId) {
      const param = `/${mapEnvironments[environment as GovUkOnceEnvironments]}/udp-param/udp/monitoring`;
      const ssmValue = StringParameter.valueFromLookup(this, param, '{}');

      let monitoringConfig: {
        workspaceId?: string;
        channelId?: string;
        pagerDutyUrl?: string;
      } = {};
      try {
        monitoringConfig = JSON.parse(ssmValue);
      } catch {
        console.log(
          'JSON.parse(monitoringConfig) error externalConsumers in MonitoringStack',
        );
      }

      if (monitoringConfig.workspaceId && monitoringConfig.channelId) {
        const slackChannel = new SlackChannelConfiguration(
          this,
          'SlackChannel',
          {
            slackChannelConfigurationName: `${resourcePrefix}-alarm-notifications`,
            slackWorkspaceId: monitoringConfig.workspaceId,
            slackChannelId: monitoringConfig.channelId,
            notificationTopics: [this.criticalTopic],
            guardrailPolicies: [
              ManagedPolicy.fromAwsManagedPolicyName('ReadOnlyAccess'),
            ],
          },
        );

        slackChannel.role?.addToPrincipalPolicy(
          new PolicyStatement({
            actions: ['kms:Decrypt', 'kms:GenerateDataKey'],
            resources: [kmsKey.keyArn],
          }),
        );
      }

      if (monitoringConfig.pagerDutyUrl) {
        new sns.Subscription(this, 'PagerDutySubscription', {
          topic: this.criticalTopic,
          protocol: sns.SubscriptionProtocol.HTTPS,
          endpoint: monitoringConfig.pagerDutyUrl,
        });
      }
    }

    this.dashboard = new cloudwatch.Dashboard(this, 'Dashboard', {
      dashboardName: `${resourcePrefix}-dashboard`,
    });

    this.createDynamoDBAlarms(table, resourcePrefix);
    this.addDynamoDBWidgets(table);

    this.createApiGatewayAlarms(api, environment, resourcePrefix);
    this.addApiGatewayWidgets(api, environment);

    lambdas.forEach((fn, index) => {
      this.createLambdaAlarms(fn, resourcePrefix, index);
    });
    this.addLambdaWidgets(lambdas);

    if (consumerReconciler) {
      new cloudwatch.Alarm(this, 'ConsumerReconcilerErrors', {
        alarmName: `${resourcePrefix}-consumer-reconcailer-errors`,
        alarmDescription:
          'Consumer reconciler failed: an external consumer changed in params repo has not been applied',
        metric: consumerReconciler.metricErrors({
          period: Duration.minutes(5),
        }),
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }).addAlarmAction({
        bind: () => ({ alarmActionArn: this.criticalTopic.topicArn }),
      });
    }

    this.performanceDashboard = this.createPerformanceDashboard(
      resourcePrefix,
      table,
      api,
      environment,
      lambdas,
    );
  }

  private createDynamoDBAlarms(table: dynamodb.ITable, resourcePrefix: string) {
    new cloudwatch.Alarm(this, 'DynamoDbReadThrottled', {
      alarmName: `${resourcePrefix}-dynamodb-read-throttled`,
      alarmDescription: 'Dynamodb read requests are being throttled',
      metric: table.metricThrottledRequestsForOperations({
        operations: [dynamodb.Operation.GET_ITEM, dynamodb.Operation.QUERY],
        period: Duration.minutes(1),
        statistic: 'Sum',
      }),
      threshold: 1,
      evaluationPeriods: 2,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction({
      bind: () => ({ alarmActionArn: this.criticalTopic.topicArn }),
    });

    new cloudwatch.Alarm(this, 'DynamoDbWriteThrottled', {
      alarmName: `${resourcePrefix}-dynamodb-write-throttled`,
      alarmDescription: 'Dynamodb write requests are being throttled',
      metric: table.metricThrottledRequestsForOperations({
        operations: [
          dynamodb.Operation.PUT_ITEM,
          dynamodb.Operation.UPDATE_ITEM,
        ],
        period: Duration.minutes(1),
        statistic: 'Sum',
      }),
      threshold: 1,
      evaluationPeriods: 2,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction({
      bind: () => ({ alarmActionArn: this.criticalTopic.topicArn }),
    });

    new cloudwatch.Alarm(this, 'DynamoDbSystemErrors', {
      alarmName: `${resourcePrefix}-dynamodb-system-errors`,
      alarmDescription: 'Dynamodb system errors detected',
      metric: table.metricSystemErrorsForOperations({
        operations: [
          dynamodb.Operation.GET_ITEM,
          dynamodb.Operation.PUT_ITEM,
          dynamodb.Operation.QUERY,
        ],
        period: Duration.minutes(1),
        statistic: 'Sum',
      }),
      threshold: 1,
      evaluationPeriods: 2,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction({
      bind: () => ({ alarmActionArn: this.criticalTopic.topicArn }),
    });
  }

  private addDynamoDBWidgets(table: dynamodb.ITable): void {
    this.dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Dynamo - Read/Write Capacity',
        left: [
          table.metricConsumedReadCapacityUnits({
            period: Duration.minutes(1),
          }),
          table.metricConsumedWriteCapacityUnits({
            period: Duration.minutes(1),
          }),
        ],
        width: 12,
      }),
      new cloudwatch.GraphWidget({
        title: 'Dynamo - Latency',
        left: [
          table.metricSuccessfulRequestLatency({
            dimensionsMap: { TableName: table.tableName, Operation: 'GetItem' },
            period: Duration.minutes(1),
            statistic: 'Average',
          }),
          table.metricSuccessfulRequestLatency({
            dimensionsMap: { TableName: table.tableName, Operation: 'PutItem' },
            period: Duration.minutes(1),
            statistic: 'Average',
          }),
        ],
        width: 12,
      }),
    );
  }

  private createApiMetric(
    api: apigateway.RestApi,
    stage: string,
    metricName: string,
    statistic: string,
  ): cloudwatch.Metric {
    return new cloudwatch.Metric({
      namespace: 'AWS/ApiGateway',
      metricName,
      dimensionsMap: {
        ApiName: api.restApiName,
        Stage: stage,
      },
      period: Duration.minutes(1),
      statistic,
    });
  }

  private createApiGatewayAlarms(
    api: apigateway.RestApi,
    stage: string,
    resourcePrefix: string,
  ): void {
    const errorRateMatric = new cloudwatch.MathExpression({
      expression: '(errors / requests) * 100',
      usingMetrics: {
        errors: this.createApiMetric(api, stage, '5xxError', 'Sum'),
        requests: this.createApiMetric(api, stage, 'Count', 'Sum'),
      },
      period: Duration.minutes(1),
      label: '%xx Error Rate (%)',
    });

    new cloudwatch.Alarm(this, 'ApiGateway5xxErrors', {
      alarmName: `${resourcePrefix}-api-5xx-errors`,
      alarmDescription: `API Gateway 5xx error rate exceeds ${NFR.MAX_ERROR_RATE_PERCENT}%`,
      metric: errorRateMatric,
      threshold: NFR.MAX_ERROR_RATE_PERCENT,
      evaluationPeriods: 2,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction({
      bind: () => ({ alarmActionArn: this.criticalTopic.topicArn }),
    });

    new cloudwatch.Alarm(this, 'ApiGateway4xxErrors', {
      alarmName: `${resourcePrefix}-api-4xx-errors`,
      alarmDescription: 'API Gateway 4xx error rate is high',
      metric: this.createApiMetric(api, stage, '4xxError', 'Sum'),
      threshold: 50,
      evaluationPeriods: 2,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction({
      bind: () => ({ alarmActionArn: this.warningTopic.topicArn }),
    });

    new cloudwatch.Alarm(this, 'ApiGatewayLatency', {
      alarmName: `${resourcePrefix}-api-latency`,
      alarmDescription: `API Gateway p99 latency exceeds ${NFR.P95_LATENCY_MS}`,
      metric: this.createApiMetric(api, stage, 'Latency', 'p95'),
      threshold: NFR.P95_LATENCY_MS,
      evaluationPeriods: 3,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction({
      bind: () => ({ alarmActionArn: this.criticalTopic.topicArn }),
    });
  }

  private addApiGatewayWidgets(api: apigateway.RestApi, stage: string): void {
    this.dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Api Gateway - Requests & Errors',
        left: [
          this.createApiMetric(api, stage, 'Count', 'Sum'),
          this.createApiMetric(api, stage, '4xxError', 'Sum'),
          this.createApiMetric(api, stage, '5xxError', 'Sum'),
        ],
        width: 12,
      }),
      new cloudwatch.GraphWidget({
        title: 'Api Gateway - Latency',
        left: [
          this.createApiMetric(api, stage, 'Latency', 'Average'),
          this.createApiMetric(api, stage, 'Latency', 'p99'),
          this.createApiMetric(api, stage, 'IntegrationLatency', 'Average'),
        ],
        width: 12,
      }),
    );
  }

  private createLambdaAlarms(
    fn: lambda.IFunction,
    resourcePrefix: string,
    index: number,
  ): void {
    const id = `Lambda${index}`;

    new cloudwatch.Alarm(this, `${id}Errors`, {
      alarmName: `${resourcePrefix}-lambda-${index}-errors`,
      alarmDescription: 'Lambda error count excceeds threashold',
      metric: fn.metricErrors({ period: Duration.minutes(1) }),
      threshold: 2,
      evaluationPeriods: 2,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction({
      bind: () => ({ alarmActionArn: this.criticalTopic.topicArn }),
    });

    new cloudwatch.Alarm(this, `${id}Duration`, {
      alarmName: `${resourcePrefix}-lambda-${index}-duration`,
      alarmDescription: `Lambda duration is exceeds ${NFR.LAMBDA_DURATION_P95_MS}`,
      metric: fn.metricDuration({
        period: Duration.minutes(1),
        statistic: 'p95',
      }),
      threshold: NFR.LAMBDA_DURATION_P95_MS,
      evaluationPeriods: 3,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction({
      bind: () => ({ alarmActionArn: this.criticalTopic.topicArn }),
    });

    new cloudwatch.Alarm(this, `${id}Throttles`, {
      alarmName: `${resourcePrefix}-lambda-${index}-throttles`,
      alarmDescription: 'Lambda is being throttled',
      metric: fn.metricThrottles({
        period: Duration.minutes(1),
        statistic: 'Sum',
      }),
      threshold: 1,
      evaluationPeriods: 3,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction({
      bind: () => ({ alarmActionArn: this.criticalTopic.topicArn }),
    });
  }

  private addLambdaWidgets(lambdas: lambda.IFunction[]): void {
    lambdas.forEach((fn, index) => {
      this.dashboard.addWidgets(
        new cloudwatch.GraphWidget({
          title: `Lambda ${index}`,
          left: [
            fn.metricInvocations({ period: Duration.minutes(1) }),
            fn.metricErrors({ period: Duration.minutes(1) }),
            fn.metricThrottles({ period: Duration.minutes(1) }),
          ],
          right: [
            fn.metricDuration({
              period: Duration.minutes(1),
              statistic: 'Average',
            }),
          ],
          width: 12,
        }),
      );
    });
  }

  private createPerformanceDashboard(
    resourcePrefix: string,
    table: dynamodb.ITable,
    api: apigateway.RestApi,
    stage: string,
    lambdas: lambda.IFunction[],
  ): cloudwatch.Dashboard {
    const perfDashboard = new cloudwatch.Dashboard(
      this,
      'PerformanceDashboard',
      {
        dashboardName: `${resourcePrefix}-performance`,
      },
    );

    const nfrLatencyAnnotation: cloudwatch.HorizontalAnnotation = {
      value: NFR.P95_LATENCY_MS,
      label: `NFR P95 (${NFR.P95_LATENCY_MS}ms)`,
      color: '#d62728',
    };

    const nfrErrorRateAnnotation: cloudwatch.HorizontalAnnotation = {
      value: NFR.MAX_ERROR_RATE_PERCENT,
      label: `NFR Error Rate (${NFR.MAX_ERROR_RATE_PERCENT}%)`,
      color: '#d62728',
    };

    const nfrThrottleAnnotation: cloudwatch.HorizontalAnnotation = {
      value: 1,
      label: 'Throttle Threshold (1)',
      color: '#d62728',
    };

    const errorRateExpression = new cloudwatch.MathExpression({
      expression: '(errors / requests) * 100',
      usingMetrics: {
        errors: this.createApiMetric(api, stage, '5xxError', 'Sum'),
        requests: this.createApiMetric(api, stage, 'Count', 'Sum'),
      },
      period: Duration.minutes(1),
      label: '5xx Error Rate (%)',
    });

    // ── Section 1: NFR Summary ──────────────────────────────────────────
    perfDashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# NFR Summary',
        width: 24,
        height: 1,
      }),
    );

    perfDashboard.addWidgets(
      new cloudwatch.SingleValueWidget({
        title: 'P95 Latency (ms)',
        metrics: [this.createApiMetric(api, stage, 'Latency', 'p95')],
        width: 8,
        height: 4,
      }),
      new cloudwatch.SingleValueWidget({
        title: 'Error Rate (%)',
        metrics: [errorRateExpression],
        width: 8,
        height: 4,
      }),
      new cloudwatch.SingleValueWidget({
        title: 'Request Throughput (rpm)',
        metrics: [this.createApiMetric(api, stage, 'Count', 'Sum')],
        width: 8,
        height: 4,
      }),
    );

    // ── Section 2: Latency Breakdown ────────────────────────────────────
    perfDashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# Latency Breakdown',
        width: 24,
        height: 1,
      }),
    );

    perfDashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'API Gateway - End-to-End Latency',
        left: [
          this.createApiMetric(api, stage, 'Latency', 'p50'),
          this.createApiMetric(api, stage, 'Latency', 'p95'),
          this.createApiMetric(api, stage, 'Latency', 'p99'),
        ],
        leftAnnotations: [nfrLatencyAnnotation],
        width: 12,
      }),
      new cloudwatch.GraphWidget({
        title: 'API Gateway - Integration Latency',
        left: [
          this.createApiMetric(api, stage, 'IntegrationLatency', 'p50'),
          this.createApiMetric(api, stage, 'IntegrationLatency', 'p95'),
          this.createApiMetric(api, stage, 'IntegrationLatency', 'p99'),
        ],
        leftAnnotations: [nfrLatencyAnnotation],
        width: 12,
      }),
    );

    perfDashboard.addWidgets(
      ...lambdas.map(
        (fn, index) =>
          new cloudwatch.GraphWidget({
            title: `Lambda ${index} - Duration`,
            left: [
              fn.metricDuration({
                period: Duration.minutes(1),
                statistic: 'p50',
              }),
              fn.metricDuration({
                period: Duration.minutes(1),
                statistic: 'p95',
              }),
              fn.metricDuration({
                period: Duration.minutes(1),
                statistic: 'p99',
              }),
            ],
            leftAnnotations: [
              {
                value: NFR.LAMBDA_DURATION_P95_MS,
                label: `NFR Lambda P95 (${NFR.LAMBDA_DURATION_P95_MS}ms)`,
                color: '#d62728',
              },
            ],
            width: 12,
          }),
      ),
    );

    perfDashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'DynamoDB - Request Latency',
        left: [
          table.metricSuccessfulRequestLatency({
            dimensionsMap: {
              TableName: table.tableName,
              Operation: 'GetItem',
            },
            period: Duration.minutes(1),
            statistic: 'p50',
          }),
          table.metricSuccessfulRequestLatency({
            dimensionsMap: {
              TableName: table.tableName,
              Operation: 'PutItem',
            },
            period: Duration.minutes(1),
            statistic: 'p50',
          }),
          table.metricSuccessfulRequestLatency({
            dimensionsMap: {
              TableName: table.tableName,
              Operation: 'Query',
            },
            period: Duration.minutes(1),
            statistic: 'p50',
          }),
          table.metricSuccessfulRequestLatency({
            dimensionsMap: {
              TableName: table.tableName,
              Operation: 'GetItem',
            },
            period: Duration.minutes(1),
            statistic: 'Average',
          }),
          table.metricSuccessfulRequestLatency({
            dimensionsMap: {
              TableName: table.tableName,
              Operation: 'PutItem',
            },
            period: Duration.minutes(1),
            statistic: 'Average',
          }),
        ],
        width: 12,
      }),
    );

    // ── Section 3: Error Analysis ───────────────────────────────────────
    perfDashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# Error Analysis',
        width: 24,
        height: 1,
      }),
    );

    perfDashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Error Rate Over Time (%)',
        left: [errorRateExpression],
        leftAnnotations: [nfrErrorRateAnnotation],
        width: 12,
      }),
      new cloudwatch.GraphWidget({
        title: 'Error Counts by Type',
        left: [
          this.createApiMetric(api, stage, '4xxError', 'Sum'),
          this.createApiMetric(api, stage, '5xxError', 'Sum'),
        ],
        stacked: true,
        width: 12,
      }),
    );

    perfDashboard.addWidgets(
      ...lambdas.map(
        (fn, index) =>
          new cloudwatch.GraphWidget({
            title: `Lambda ${index} - Errors`,
            left: [fn.metricErrors({ period: Duration.minutes(1) })],
            width: 8,
          }),
      ),
    );

    perfDashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'DynamoDB - System Errors',
        left: [
          table.metricSystemErrorsForOperations({
            operations: [
              dynamodb.Operation.GET_ITEM,
              dynamodb.Operation.PUT_ITEM,
              dynamodb.Operation.QUERY,
            ],
            period: Duration.minutes(1),
            statistic: 'Sum',
          }),
        ],
        width: 12,
      }),
    );

    // ── Section 4: Throttling & Capacity ────────────────────────────────
    perfDashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# Throttling & Capacity',
        width: 24,
        height: 1,
      }),
    );

    perfDashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'DynamoDB - Consumed Capacity',
        left: [
          table.metricConsumedReadCapacityUnits({
            period: Duration.minutes(1),
          }),
          table.metricConsumedWriteCapacityUnits({
            period: Duration.minutes(1),
          }),
        ],
        width: 12,
      }),
      new cloudwatch.GraphWidget({
        title: 'DynamoDB - Throttled Requests',
        left: [
          table.metricThrottledRequestsForOperations({
            operations: [dynamodb.Operation.GET_ITEM, dynamodb.Operation.QUERY],
            period: Duration.minutes(1),
            statistic: 'Sum',
            label: 'Read Throttles',
          }),
          table.metricThrottledRequestsForOperations({
            operations: [
              dynamodb.Operation.PUT_ITEM,
              dynamodb.Operation.UPDATE_ITEM,
            ],
            period: Duration.minutes(1),
            statistic: 'Sum',
            label: 'Write Throttles',
          }),
        ],
        leftAnnotations: [nfrThrottleAnnotation],
        width: 12,
      }),
    );

    perfDashboard.addWidgets(
      ...lambdas.map(
        (fn, index) =>
          new cloudwatch.GraphWidget({
            title: `Lambda ${index} - Throttles`,
            left: [fn.metricThrottles({ period: Duration.minutes(1) })],
            leftAnnotations: [nfrThrottleAnnotation],
            width: 8,
          }),
      ),
    );

    // ── Section 5: Lambda Scaling & Cold Starts ─────────────────────────
    perfDashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# Lambda Scaling & Cold Starts',
        width: 24,
        height: 1,
      }),
    );

    perfDashboard.addWidgets(
      ...lambdas.map(
        (fn, index) =>
          new cloudwatch.GraphWidget({
            title: `Lambda ${index} - Concurrent Executions`,
            left: [
              new cloudwatch.Metric({
                namespace: 'AWS/Lambda',
                metricName: 'ConcurrentExecutions',
                dimensionsMap: { FunctionName: fn.functionName },
                period: Duration.minutes(1),
                statistic: 'Maximum',
              }),
            ],
            width: 12,
          }),
      ),
    );

    perfDashboard.addWidgets(
      ...lambdas.map(
        (fn, index) =>
          new cloudwatch.GraphWidget({
            title: `Lambda ${index} - Init Duration (Cold Start)`,
            left: [
              new cloudwatch.Metric({
                namespace: 'AWS/Lambda',
                metricName: 'InitDuration',
                dimensionsMap: { FunctionName: fn.functionName },
                period: Duration.minutes(1),
                statistic: 'p50',
                label: 'Init Duration p50',
              }),
              new cloudwatch.Metric({
                namespace: 'AWS/Lambda',
                metricName: 'InitDuration',
                dimensionsMap: { FunctionName: fn.functionName },
                period: Duration.minutes(1),
                statistic: 'p95',
                label: 'Init Duration p95',
              }),
            ],
            width: 12,
          }),
      ),
    );

    perfDashboard.addWidgets(
      ...lambdas.map(
        (fn, index) =>
          new cloudwatch.GraphWidget({
            title: `Lambda ${index} - Invocations`,
            left: [fn.metricInvocations({ period: Duration.minutes(1) })],
            width: 8,
          }),
      ),
    );

    return perfDashboard;
  }
}

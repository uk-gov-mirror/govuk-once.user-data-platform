// Consumer reconciler.
//
// Owns every per-consumer resource for external API consumers (IAM role, API
// key, usage plan, config secret, consumer-config KMS key policy and the API
// Gateway resource policy), driven by one SSM parameter per consumer written
// by the external params repo:
//
//   /<env-long>/udp-param/udp/externalConsumers/<consumer>
//
// Invoked by:
//   - EventBridge "Parameter Store Change" events under that path, so a params
//     repo deploy takes effect without redeploying this repo
//   - a CDK Trigger on each deploy of this repo, to re-assert state
//
// MODE=dry-run reads everything and logs the plan without writing. MODE=apply
// converges. Any invalid parameter aborts the run before anything is written,
// so a bad params repo change can never partially apply.

import { APIGatewayClient } from '@aws-sdk/client-api-gateway';
import { IAMClient } from '@aws-sdk/client-iam';
import { KMSClient } from '@aws-sdk/client-kms';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { SSMClient } from '@aws-sdk/client-ssm';
import { getLogger, requireEnvVars } from '@libs/utils';

import { validateConsumers } from './consumers';
import {
  readConsumerParams,
  reconcileConsumers,
  type Clients,
  type ReconcileReport,
  type ReconcilerConfig,
} from './reconcile';

const logger = getLogger({
  serviceName: 'consumerReconciler',
  environment: process.env.ENVIRONMENT,
});

export function loadConfig(): ReconcilerConfig & {
  apply: boolean;
  allowRevokeAll: boolean;
} {
  const env = requireEnvVars(
    'MODE',
    'ENVIRONMENT',
    'RESOURCE_PREFIX',
    'SECRET_PATH_PREFIX',
    'CONSUMER_PARAM_PATH',
    'REST_API_ID',
    'STAGE_NAME',
    'API_URL',
    'OWN_VPCE_ID',
    'ACCOUNT_ID',
    'AWS_REGION',
    'PERMISSIONS_BOUNDARY_ARN',
  );

  if (env.MODE !== 'apply' && env.MODE !== 'dry-run') {
    throw new Error(`MODE must be "apply" or "dry-run", got "${env.MODE}"`);
  }

  return {
    apply: env.MODE === 'apply',
    allowRevokeAll: process.env.ALLOW_REVOKE_ALL === 'true',
    environment: env.ENVIRONMENT,
    resourcePrefix: env.RESOURCE_PREFIX,
    secretPathPrefix: env.SECRET_PATH_PREFIX,
    consumerParamPath: env.CONSUMER_PARAM_PATH,
    restApiId: env.REST_API_ID,
    stageName: env.STAGE_NAME,
    apiUrl: env.API_URL,
    ownVpcEndpointId: env.OWN_VPCE_ID,
    accountId: env.ACCOUNT_ID,
    region: env.AWS_REGION,
    permissionsBoundaryArn: env.PERMISSIONS_BOUNDARY_ARN,
    crossAccountPrincipals: JSON.parse(
      process.env.CROSS_ACCOUNT_PRINCIPALS || '[]',
    ),
    tags: JSON.parse(process.env.RESOURCE_TAGS || '{}'),
  };
}

let clients: Clients | undefined;
const getClients = (): Clients =>
  (clients ??= {
    iam: new IAMClient({}),
    apigw: new APIGatewayClient({}),
    kms: new KMSClient({}),
    secrets: new SecretsManagerClient({}),
    ssm: new SSMClient({}),
  });

interface InvocationEvent {
  source?: string;
}

export const handler = async (
  event: InvocationEvent = {},
  injectedClients?: Clients,
): Promise<ReconcileReport> => {
  const config = loadConfig();
  const aws = injectedClients ?? getClients();

  const params = await readConsumerParams(aws, config);
  const { consumers, errors } = validateConsumers(params);

  let report: ReconcileReport;
  if (errors.length > 0) {
    report = {
      mode: config.apply ? 'apply' : 'dry-run',
      consumers: [],
      revoked: [],
      changes: [],
      warnings: [],
      details: {},
      errors,
    };
  } else {
    try {
      report = await reconcileConsumers(aws, config, consumers, config);
    } catch (err) {
      // A dry-run only observes, so it must never fail a deploy of this repo.
      if (config.apply || event.source === 'aws.ssm') throw err;
      report = {
        mode: 'dry-run',
        consumers: consumers.map((c) => c.name),
        revoked: [],
        changes: [],
        warnings: [],
        details: {},
        errors: [`Dry-run failed: ${(err as Error).message}`],
      };
    }
  }

  const accessChanges = report.changes.filter((c) => c.impact === 'access');
  logger.info('Consumer reconcile complete', {
    mode: report.mode,
    consumers: report.consumers,
    revoked: report.revoked,
    accessChangeCount: accessChanges.length,
    changes: report.changes,
    warnings: report.warnings,
    // What each consumer needs in order to connect; stable, and no secrets.
    details: report.details,
  });

  if (report.errors.length > 0) {
    logger.error('Consumer reconcile aborted; nothing was written', {
      errors: report.errors,
    });
    // For SSM change events, fail the invocation so the Lambda error alarm
    // fires. For deploy-time invocations, don't: an invalid consumer declared
    // in the params repo must not block deploying this repo.
    if (event.source === 'aws.ssm') {
      throw new Error(
        `Consumer reconcile aborted: ${report.errors.join('; ')}`,
      );
    }
  }

  return report;
};

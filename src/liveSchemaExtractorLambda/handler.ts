import middy from '@middy/core';
import type {
  AttributeValue as StreamAttributeValue,
  DynamoDBBatchResponse,
  DynamoDBRecord,
  DynamoDBStreamEvent,
} from 'aws-lambda';
import { DynamoDBClient, type AttributeValue } from '@aws-sdk/client-dynamodb';
import { KMSClient } from '@aws-sdk/client-kms';
import { DynamoDBDocumentClient, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import {
  getTracer,
  captureLambdaHandler,
  getLogger,
  injectLambdaContext,
  requireEnvVars,
} from '@libs/utils';
import {
  DsqlConnection,
  JsonSchema,
  LiveSchemaRepository,
  LiveUserSchemaRepository,
  SCHEMA_EXTRACTOR_DB_ROLE,
  UserIdHasher,
  UserSchema,
  inferSchema,
  mergeSchemas,
  toUserShape,
} from '@libs/live-schema';
import { EncryptionService } from '@libs/data-access';

const { DSQL_ENDPOINT, AWS_REGION, DATA_TABLE_NAME, USER_ID_HMAC_KEY_ID } =
  requireEnvVars(
    'DSQL_ENDPOINT',
    'AWS_REGION',
    'DATA_TABLE_NAME',
    'USER_ID_HMAC_KEY_ID',
  );

const {
  STACK: stack,
  SERVICE_NAME: serviceName = 'udpLiveSchemaExtractor',
  KMS_KEY_ID: kmsKeyId,
  DYNAMO_ENDPOINT: dynamoDbEndpoint,
} = process.env;

const tracer = getTracer({ serviceName });
const logger = getLogger({
  serviceName,
  environment: stack,
});

const dsql = new DsqlConnection({
  endpoint: DSQL_ENDPOINT,
  region: AWS_REGION,
  user: SCHEMA_EXTRACTOR_DB_ROLE,
});
const repository = new LiveSchemaRepository(dsql);
const userRepository = new LiveUserSchemaRepository(dsql);

const hasher = new UserIdHasher(
  USER_ID_HMAC_KEY_ID,
  tracer.captureAWSv3Client(new KMSClient({})),
);

const encryption = kmsKeyId
  ? new EncryptionService({ kmsKeyId, tracer })
  : undefined;

const dynamo = DynamoDBDocumentClient.from(
  tracer.captureAWSv3Client(
    new DynamoDBClient(dynamoDbEndpoint ? { endpoint: dynamoDbEndpoint } : {}),
  ),
);

interface StreamItem {
  sequenceNumber: string;
  pk: string;
  sk: string;
  udpKey: string;
  /** The stored `data` attribute exactly as written (ciphertext when encrypted). */
  storedData: unknown;
  data: unknown;
}

/** The resource path is the UDP topic; normalise to a single leading slash. */
const toUdpKey = (resourcePath: string) =>
  `/${resourcePath.replace(/^\/+/, '')}`;

const readRecord = async (record: DynamoDBRecord): Promise<StreamItem> => {
  const image = unmarshall(
    record.dynamodb!.NewImage as Record<string, StreamAttributeValue> as Record<
      string,
      AttributeValue
    >,
  );
  const { pk, sk, data, __dataKey } = image as {
    pk: string;
    sk: string;
    data?: unknown;
    __dataKey?: string;
  };

  const decrypted =
    encryption && __dataKey
      ? (await encryption.decryptFields({ data, __dataKey }, ['data'])).data
      : data;

  return {
    sequenceNumber: record.dynamodb!.SequenceNumber!,
    pk,
    sk,
    udpKey: toUdpKey(sk),
    storedData: data,
    data: decrypted ?? {},
  };
};

/**
 * Stamps the evaluated version onto the record and clears the evaluation flag,
 * so the resulting MODIFY is dropped by the stream filter. The write is
 * conditional on `data` being unchanged since this event: if the record was
 * rewritten (or deleted) meanwhile, that newer write carries its own flag and
 * will be evaluated by its own event.
 */
const stamp = async (item: StreamItem, version: string) => {
  try {
    await dynamo.send(
      new UpdateCommand({
        TableName: DATA_TABLE_NAME,
        Key: { pk: item.pk, sk: item.sk },
        UpdateExpression: 'SET #schemaVersion = :version, #flag = :evaluated',
        ConditionExpression:
          item.storedData === undefined
            ? 'attribute_exists(pk) AND attribute_not_exists(#data)'
            : 'attribute_exists(pk) AND #data = :data',
        ExpressionAttributeNames: {
          '#schemaVersion': 'schemaVersion',
          '#flag': 'schemaEvaluationRequired',
          '#data': 'data',
        },
        ExpressionAttributeValues: {
          ':version': version,
          ':evaluated': false,
          ...(item.storedData === undefined
            ? {}
            : { ':data': item.storedData }),
        },
      }),
    );
  } catch (error) {
    if ((error as Error).name !== 'ConditionalCheckFailedException') {
      throw error;
    }
    logger.info('Record changed since event; skipping stamp', {
      udpKey: item.udpKey,
      sequenceNumber: item.sequenceNumber,
    });
  }
};

/**
 * Evolves the live schema for one udpKey from every record in the batch that
 * targets it, then stamps those records. One DSQL write per key per batch.
 */
const processKey = async (udpKey: string, items: StreamItem[]) => {
  const observed = items
    .map((item) => inferSchema(item.data))
    .reduce<JsonSchema>((acc, schema) => mergeSchemas(acc, schema), {});

  const { version, created } = await repository.evolve(udpKey, observed);
  if (created) {
    logger.info('Saved new live schema version', { udpKey, version });
  }

  for (const item of items) {
    await stamp(item, version);
  }
};

/**
 * Replaces the shape of each topic in the user's live user schema with the
 * fields populated in its latest record. Records arrive in stream order, so a
 * later record for the same topic wins.
 */
const processUser = async (udpUserId: string, items: StreamItem[]) => {
  const topics: UserSchema = {};
  for (const item of items) {
    topics[item.udpKey] = toUserShape(inferSchema(item.data));
  }
  await userRepository.mergeTopics(await hasher.hash(udpUserId), topics);
};

const groupBy = (items: StreamItem[], keyOf: (item: StreamItem) => string) => {
  const groups = new Map<string, StreamItem[]>();
  for (const item of items) {
    groups.set(keyOf(item), [...(groups.get(keyOf(item)) ?? []), item]);
  }
  return groups;
};

export const lambdaHandler = async (
  event: DynamoDBStreamEvent,
): Promise<DynamoDBBatchResponse> => {
  const failed = new Set<string>();
  const items: StreamItem[] = [];

  for (const record of event.Records) {
    if (!record.dynamodb?.NewImage) continue;
    try {
      items.push(await readRecord(record));
    } catch (error) {
      logger.error('Failed to read stream record', {
        sequenceNumber: record.dynamodb.SequenceNumber,
        error,
      });
      failed.add(record.dynamodb.SequenceNumber!);
    }
  }

  for (const [udpKey, keyItems] of groupBy(items, (i) => i.udpKey)) {
    try {
      await processKey(udpKey, keyItems);
    } catch (error) {
      logger.error('Failed to evolve live schema', { udpKey, error });
      for (const item of keyItems) failed.add(item.sequenceNumber);
    }
  }

  // User footprints follow the global schema: only records it accepted.
  const evolved = items.filter((i) => !failed.has(i.sequenceNumber));
  for (const [udpUserId, userItems] of groupBy(evolved, (i) => i.pk)) {
    try {
      await processUser(udpUserId, userItems);
    } catch (error) {
      // Never log the udpUserId; sequence numbers identify the records.
      logger.error('Failed to update live user schema', {
        sequenceNumbers: userItems.map((i) => i.sequenceNumber),
        error,
      });
      for (const item of userItems) failed.add(item.sequenceNumber);
    }
  }

  return {
    batchItemFailures: [...failed].map((itemIdentifier) => ({
      itemIdentifier,
    })),
  };
};

export const handler = middy()
  .use(injectLambdaContext(logger))
  .use(captureLambdaHandler(tracer, { captureResponse: false }))
  .use({
    before: async () => {
      tracer.putAnnotation('stack', stack);
    },
  })
  .handler(lambdaHandler);

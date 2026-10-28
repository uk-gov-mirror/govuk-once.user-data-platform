import { JsonSchema } from './shape';
import {
  GenerateMacCommand,
  KMSClient,
  MacAlgorithmSpec,
} from '@aws-sdk/client-kms';
import { DsqlConnection } from './dsql';
import { LIVE_USER_SCHEMAS_TABLE } from './tables';

export type UserShape = string | UserShape[] | { [field: string]: UserShape };

export type UserSchema = Record<string, UserShape>;

const isNullOnly = (schema: JsonSchema) => schema.type === 'null';

export const toUserShape = (schema: JsonSchema): UserShape => {
  if (schema.properties) {
    return Object.fromEntries(
      Object.entries(schema.properties)
        .filter(([, property]) => !isNullOnly(property))
        .map(([Field, property]) => [Field, toUserShape(property)]),
    );
  }
  if (schema.items) return [toUserShape(schema.items)];

  const types = [schema.type ?? []].flat();
  return types.join('|');
};

export class UserIdHasher {
  private readonly cache = new Map<string, Promise<string>>();

  constructor(
    private readonly keyId: string,
    private readonly kms: KMSClient = new KMSClient({}),
  ) {}

  hash(udpUserId: string): Promise<string> {
    let hashed = this.cache.get(udpUserId);
    if (!hashed) {
      hashed = this.generate(udpUserId);

      hashed?.catch(() => this.cache.delete(udpUserId));
      this.cache.set(udpUserId, hashed);
    }
    return hashed;
  }

  private async generate(udpUserId: string): Promise<string> {
    const { Mac } = await this.kms.send(
      new GenerateMacCommand({
        KeyId: this.keyId,
        MacAlgorithm: MacAlgorithmSpec.HMAC_SHA_256,
        Message: Buffer.from(udpUserId, 'utf8'),
      }),
    );
    if (!Mac) throw new Error('KMS GenerateMac returned no Mac');
    return Buffer.from(Mac).toString('hex');
  }
}

export class LiveUserSchemaRepository {
  constructor(
    private readonly db: DsqlConnection,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async mergeTopics(udpUserIdHash: string, topics: UserSchema): Promise<void> {
    await this.db.query(
      `INSERT INTO ${LIVE_USER_SCHEMAS_TABLE} ("udpUserIdhash", "lastUpdated", "userSchema")
       VALUES ($1, $2, $3::jsonb)
      ON CONFLICT ("udpUserIdHash") DO UPDATE SET
        "userSchema" = ${LIVE_USER_SCHEMAS_TABLE}."userSchema" || EXCLUDED."userSchema",
        "lastUpdated" = EXCLUDED."lastUpdated"`,
      [udpUserIdHash, this.now(), JSON.stringify(topics)],
    );
  }

  async get(udpUserIdHash: string): Promise<UserSchema | undefined> {
    const { rows } = await this.db.query<{ userSchema: UserSchema | string }>(
      `SELECT "userSchema" FROM ${LIVE_USER_SCHEMAS_TABLE} WHERE "udpUserIdHash" = $1`,
      [udpUserIdHash],
    );

    const [row] = rows;
    if (!row) return undefined;

    return typeof row.userSchema === 'string'
      ? (JSON.parse(row.userSchema) as UserSchema)
      : row.userSchema;
  }
}

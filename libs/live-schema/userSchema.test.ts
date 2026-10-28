import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import { GenerateMacCommand, KMSClient } from '@aws-sdk/client-kms';
import type { DsqlConnection } from './dsql';
import { inferSchema } from './shape';
import {
  LiveUserSchemaRepository,
  UserIdHasher,
  toUserShape,
} from './userSchema';
import { LIVE_USER_SCHEMAS_TABLE } from './tables';

describe('toUserShape', () => {
  it('maps populated fields to their types', () => {
    expect(
      toUserShape(
        inferSchema({
          vehicleRegistration: 'AB12 CDE',
          mileage: 12000,
          taxed: true,
        }),
      ),
    ).toEqual({
      vehicleRegistration: 'string',
      mileage: 'integer',
      taxed: 'boolean',
    });
  });

  it('leaves out null fields as not provided', () => {
    expect(
      toUserShape(
        inferSchema({ vehicleRegistration: 'AB12', motExpiry: null }),
      ),
    ).toEqual({ vehicleRegistration: 'string' });
  });

  it('nests objects and describes arrays by their items', () => {
    expect(
      toUserShape(
        inferSchema({
          vehicle: { make: 'Ford' },
          tags: ['a', 'b'],
          mixed: [1, 'x'],
          empty: [],
        }),
      ),
    ).toEqual({
      vehicle: { make: 'string' },
      tags: ['string'],
      mixed: ['integer|string'],
      empty: 'array',
    });
  });

  it('never includes values', () => {
    const shape = toUserShape(inferSchema({ name: 'Jane Doe' }));
    expect(JSON.stringify(shape)).not.toContain('Jane Doe');
  });
});

describe('UserIdHasher', () => {
  const kmsMock = mockClient(KMSClient);

  beforeEach(() => {
    kmsMock.reset();
    kmsMock.on(GenerateMacCommand).callsFake(({ Message }) => ({
      Mac: Buffer.from(`mac:${Buffer.from(Message).toString()}`),
    }));
  });

  it('returns the hex HMAC from KMS using the configured key', async () => {
    const hasher = new UserIdHasher('hmac-key', new KMSClient({}));

    const hash = await hasher.hash('udp-id-1');

    expect(hash).toBe(Buffer.from('mac:udp-id-1').toString('hex'));
    expect(hash).not.toContain('udp-id-1');
    expect(kmsMock.commandCalls(GenerateMacCommand)[0].args[0].input).toEqual(
      expect.objectContaining({
        KeyId: 'hmac-key',
        MacAlgorithm: 'HMAC_SHA_256',
      }),
    );
  });

  it('calls KMS once per udpUserId', async () => {
    const hasher = new UserIdHasher('hmac-key', new KMSClient({}));

    await hasher.hash('udp-id-1');
    await hasher.hash('udp-id-1');
    await hasher.hash('udp-id-2');

    expect(kmsMock.commandCalls(GenerateMacCommand)).toHaveLength(2);
  });

  it('retries KMS after a failure instead of caching it', async () => {
    kmsMock
      .on(GenerateMacCommand)
      .rejectsOnce(new Error('throttled'))
      .resolves({ Mac: Buffer.from('mac') });
    const hasher = new UserIdHasher('hmac-key', new KMSClient({}));

    await expect(hasher.hash('udp-id-1')).rejects.toThrow('throttled');
    await expect(hasher.hash('udp-id-1')).resolves.toBe(
      Buffer.from('mac').toString('hex'),
    );
  });
});

describe('LiveUserSchemaRepository', () => {
  const query = vi.fn();
  const db = { query } as unknown as DsqlConnection;
  const now = new Date('2026-10-27T10:00:00Z');

  beforeEach(() => {
    query.mockReset().mockResolvedValue({ rowCount: 1, rows: [] });
  });

  it('upserts topics, replacing only the topics given', async () => {
    const repository = new LiveUserSchemaRepository(db, () => now);

    await repository.mergeTopics('hash-1', {
      '/dvla/state': { vehicleRegistration: 'string' },
    });

    const [sql, values] = query.mock.calls[0];
    expect(sql).toContain(`INSERT INTO ${LIVE_USER_SCHEMAS_TABLE}`);
    expect(sql).toContain('ON CONFLICT ("udpUserIdHash") DO UPDATE');
    expect(sql).toContain(
      `"userSchema" = ${LIVE_USER_SCHEMAS_TABLE}."userSchema" || EXCLUDED."userSchema"`,
    );
    expect(values).toEqual([
      'hash-1',
      now,
      JSON.stringify({ '/dvla/state': { vehicleRegistration: 'string' } }),
    ]);
  });

  it('reads a stored schema, parsed or as text', async () => {
    const repository = new LiveUserSchemaRepository(db);
    const schema = { '/dvla/state': { taxStatus: 'string' } };

    query.mockResolvedValueOnce({ rows: [{ userSchema: schema }] });
    await expect(repository.get('hash-1')).resolves.toEqual(schema);

    query.mockResolvedValueOnce({
      rows: [{ userSchema: JSON.stringify(schema) }],
    });
    await expect(repository.get('hash-1')).resolves.toEqual(schema);

    query.mockResolvedValueOnce({ rows: [] });
    await expect(repository.get('hash-1')).resolves.toBeUndefined();
  });
});

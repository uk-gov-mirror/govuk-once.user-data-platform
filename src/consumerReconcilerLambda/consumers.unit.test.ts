import { validateConsumers } from './consumers';

const flex = {
  accountId: '308036881389',
  permissions: ['read', 'write', 'delete'],
  description: 'Flex integration',
  vpcEndpointId: 'vpce-0fda65abeaa732a68',
};

const param = (name: string, value: unknown) => ({
  name,
  value: typeof value === 'string' ? value : JSON.stringify(value),
});

describe('validateConsumers', () => {
  it('accepts a well-formed consumer and applies throttle defaults', () => {
    const { consumers, errors } = validateConsumers([param('flex', flex)]);

    expect(errors).toEqual([]);
    expect(consumers).toEqual([
      { name: 'flex', ...flex, rateLimit: 20, burstLimit: 10 },
    ]);
  });

  it('keeps explicit throttle limits and optional fields', () => {
    const { consumers } = validateConsumers([
      param('gdsuns', {
        ...flex,
        externalId: 'ext-123',
        rateLimit: 100,
        burstLimit: 200,
      }),
    ]);

    expect(consumers[0]).toMatchObject({
      externalId: 'ext-123',
      rateLimit: 100,
      burstLimit: 200,
    });
  });

  it.each([
    ['invalid JSON', 'flex', '{nope'],
    ['short account id', 'flex', { ...flex, accountId: '123' }],
    ['unknown permission', 'flex', { ...flex, permissions: ['admin'] }],
    ['empty permissions', 'flex', { ...flex, permissions: [] }],
    ['bad vpce id', 'flex', { ...flex, vpcEndpointId: 'not-a-vpce' }],
    ['unknown field (typo)', 'flex', { ...flex, ratelimit: 5 }],
    ['bad consumer name', 'flex-api', flex],
    ['bad externalId', 'flex', { ...flex, externalId: 'has spaces' }],
    ['reserved name', 'test', flex],
  ])('rejects %s', (_label, name, value) => {
    const { consumers, errors } = validateConsumers([param(name, value)]);

    expect(consumers).toEqual([]);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toMatch(new RegExp(`^${name}:`));
  });

  it('rejects the same VPC endpoint claimed by two accounts', () => {
    const { errors } = validateConsumers([
      param('flex', flex),
      param('other', { ...flex, accountId: '111111111111' }),
    ]);

    expect(errors).toEqual([
      expect.stringMatching(/^other: vpcEndpointId .* already claimed by flex/),
    ]);
  });

  it('allows one account to reuse its own VPC endpoint across consumers', () => {
    const { errors } = validateConsumers([
      param('flex', flex),
      param('flexbeta', flex),
    ]);

    expect(errors).toEqual([]);
  });

  it('rejects consumer names that differ only by case', () => {
    const { errors } = validateConsumers([
      param('flex', flex),
      param('FLEX', flex),
    ]);

    expect(errors).toEqual([
      expect.stringMatching(/^FLEX: collides with consumer flex/),
    ]);
  });
});

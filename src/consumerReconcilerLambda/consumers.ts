// Validation of per-consumer SSM parameters written by the external params
// repo. This is the trust boundary: nothing read from SSM reaches IAM, KMS,
// Secrets Manager or API Gateway without passing through here.

import { z } from 'zod';

export const CONSUMER_NAME_RE = /^[a-zA-Z0-9]{1,32}$/;

// Consumers still managed by CloudFormation in the main stack.
export const RESERVED_CONSUMER_NAMES = ['test'];

export const DEFAULT_RATE_LIMIT = 20;
export const DEFAULT_BURST_LIMIT = 10;

const consumerParamSchema = z.strictObject({
  accountId: z.string().regex(/^\d{12}$/, 'must be a 12 digit AWS account id'),
  permissions: z
    .array(z.enum(['read', 'write', 'delete']))
    .min(1)
    .refine((p) => new Set(p).size === p.length, 'must not contain duplicates'),
  externalId: z
    .string()
    .regex(/^[\w+=,.@:/-]{2,1224}$/, 'must be a valid sts:ExternalId')
    .optional(),
  description: z
    .string()
    .max(1000)
    .regex(
      /^[\t\n\r\x20-\x7E\xA1-\xFF]*$/,
      'contains characters not allowed in an IAM role description',
    )
    .optional(),
  rateLimit: z.number().positive().optional(),
  burstLimit: z.number().int().positive().optional(),
  vpcEndpointId: z
    .string()
    .regex(/^vpce-[0-9a-f]{8,17}$/, 'must be a vpce- id')
    .optional(),
});

export type Permission = 'read' | 'write' | 'delete';

export interface Consumer {
  name: string;
  accountId: string;
  permissions: Permission[];
  externalId?: string;
  description?: string;
  rateLimit: number;
  burstLimit: number;
  vpcEndpointId?: string;
}

export interface RawConsumerParam {
  name: string;
  value: string;
}

export interface ValidationResult {
  consumers: Consumer[];
  errors: string[];
}

export function validateConsumers(
  params: RawConsumerParam[],
): ValidationResult {
  const consumers: Consumer[] = [];
  const errors: string[] = [];

  for (const { name, value } of params) {
    if (!CONSUMER_NAME_RE.test(name)) {
      errors.push(`${name}: consumer name must match ${CONSUMER_NAME_RE}`);
      continue;
    }
    if (RESERVED_CONSUMER_NAMES.includes(name.toLowerCase())) {
      errors.push(`${name}: consumer name is reserved`);
      continue;
    }

    let json: unknown;
    try {
      json = JSON.parse(value);
    } catch {
      errors.push(`${name}: value is not valid JSON`);
      continue;
    }

    const parsed = consumerParamSchema.safeParse(json);
    if (!parsed.success) {
      for (const issue of parsed.error.issues) {
        errors.push(
          `${name}: ${issue.path.join('.') || '<root>'} ${issue.message}`,
        );
      }
      continue;
    }

    consumers.push({
      name,
      ...parsed.data,
      rateLimit: parsed.data.rateLimit ?? DEFAULT_RATE_LIMIT,
      burstLimit: parsed.data.burstLimit ?? DEFAULT_BURST_LIMIT,
    });
  }

  // IAM role names are case-insensitive, so flex and FLEX would collide.
  const seenNames = new Map<string, string>();
  for (const { name } of consumers) {
    const existing = seenNames.get(name.toLowerCase());
    if (existing) {
      errors.push(
        `${name}: collides with consumer ${existing} (names are case-insensitive)`,
      );
    }
    seenNames.set(name.toLowerCase(), name);
  }

  // A VPC endpoint belongs to exactly one account; letting two accounts claim
  // the same endpoint would let one ride the other's network admission.
  const vpceOwners = new Map<string, Consumer>();
  for (const consumer of consumers) {
    if (!consumer.vpcEndpointId) continue;
    const owner = vpceOwners.get(consumer.vpcEndpointId);
    if (owner && owner.accountId !== consumer.accountId) {
      errors.push(
        `${consumer.name}: vpcEndpointId ${consumer.vpcEndpointId} is already claimed by ${owner.name} (account ${owner.accountId})`,
      );
    }
    vpceOwners.set(consumer.vpcEndpointId, owner ?? consumer);
  }

  return { consumers, errors };
}

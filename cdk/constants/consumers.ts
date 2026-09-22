import { GovUkOnceEnvironments } from './environment';

export type ConsumerProvisioning = 'cloudformation' | 'reconciler';

export const ConsumerProvisioningByEnvironment: Record<
  string,
  ConsumerProvisioning
> = {
  [GovUkOnceEnvironments.Dev]: 'cloudformation',
  [GovUkOnceEnvironments.Stag]: 'cloudformation',
  [GovUkOnceEnvironments.Prod]: 'cloudformation',
};

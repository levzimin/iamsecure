import { IAMClient } from '@aws-sdk/client-iam';
import { MissingMfaChecker } from './MissingMfaChecker.js';
import { StaleAccessKeysChecker } from './StaleAccessKeysChecker.js';
import { MultiSecurityChecker } from './MultiSecurityChecker.js';

const SUPPORTED = ['MFA', 'StaleAccessKeys'];

/**
 * Note: At this point, a hardcoded list of supported checks should suffice. If we decide to revisit this and make this dynamic, we could load jsons dynamically that would include
 * the name, implementation reference and a custom config object to be passed down to each checker.
 * At this time, I wouldn't do more than a simple switch case.
 */
function createRequestedSecurityChecks(securityCheckNames = []) {
  const securityCheckInstances = [];
  const unsupported = [];
  
  const region = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1';
  const iam = new IAMClient({ region });

  for (const name of securityCheckNames) {
    switch (name) {
      case 'MFA':
        securityCheckInstances.push({ name: 'MFA', securityCheck: new MissingMfaChecker(iam) });
        break;
      case 'StaleAccessKeys':
        {
          securityCheckInstances.push({ name: 'StaleAccessKeys', securityCheck: new StaleAccessKeysChecker(iam, { unusedDaysLimit: Number(process.env.STALE_ACCESS_KEYS_UNUSED_DAYS_LIMIT) }) });
          break;
        }
      default:
        unsupported.push(name);
    }
  }

  if (unsupported.length > 0) {
    throw new Error(`Unsupported checks: ${unsupported.join(', ')}`);
  }

  return securityCheckInstances;
}

export function supportedChecks() {
  return SUPPORTED.slice();
}

export function createInstance(requiredSecurityCheckNames = []) {
  const checks = createRequestedSecurityChecks(requiredSecurityCheckNames);
  return new MultiSecurityChecker(checks);
}


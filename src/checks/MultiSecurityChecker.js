import { IamSecurityChecker } from '../core/IamSecurityChecker.js';
import { IamSecurityCheckerResultStatus } from '../core/resultStatus.js';

/**
 * A unified checker that allows running multiple security checks in parallel.
 */
export class MultiSecurityChecker extends IamSecurityChecker {
  /**
   * @param {*} namedSecurityChecks Array of named security checks. Each check is an object with a name and a security check instance.
   */
  constructor(namedSecurityChecks, numberOfConcurrentChecks = 2) {
    super();

    if (!Array.isArray(namedSecurityChecks) || namedSecurityChecks.length === 0) {
      throw new Error('namedSecurityChecks must be a non-empty array');
    }

    for (const entry of namedSecurityChecks) {
      if (!entry || typeof entry.name !== 'string' || !entry.securityCheck) {
        throw new Error('Each entry must have a name and a securityCheck');
      }
      if (!(entry.securityCheck instanceof IamSecurityChecker)) {
        throw new Error(`securityCheck for '${entry.name}' must extend IamSecurityCheck`);
      }
    }

    if (typeof numberOfConcurrentChecks !== 'number' || numberOfConcurrentChecks < 1) {
      throw new Error('numberOfConcurrentChecks must be a number greater than 0');
    }

    this.__namedChecks = namedSecurityChecks;
    this.__numberOfConcurrentChecks = numberOfConcurrentChecks;
  }

  /**
   * Runs all the checks in parallel (concurrency depends on the configured limit).
   * @returns A unified report of the results of all the checks, as well as an overall result status.
   */
  async runCheck() {
    const results = [];
    let hasActionRequired = false;
    const actionRequiredCheckNames = [];

    const batchSize = this.__numberOfConcurrentChecks;

    for (let i = 0; i < this.__namedChecks.length; i += batchSize) {
      const batch = this.__namedChecks.slice(i, i + batchSize);

      const batchTasks = batch.map(async ({ name, securityCheck }) => {
        try {
          const checkResult = await securityCheck.runCheck();

          if (checkResult && checkResult.resultStatus === IamSecurityCheckerResultStatus.ActionRequired) {
            hasActionRequired = true;
            actionRequiredCheckNames.push(name);
          }

          results.push({ name, report: checkResult });
        } catch (error) {
          console.error(`Error running check ${name}.`, error);
          
          hasActionRequired = true;
          actionRequiredCheckNames.push(name);
          results.push({ name, report: { resultStatus: IamSecurityCheckerResultStatus.ActionRequired, message: `Could not complete security check.`, data: { } } });
        }
      });

      await Promise.all(batchTasks);
    }

    return {
      resultStatus: hasActionRequired ? IamSecurityCheckerResultStatus.ActionRequired : IamSecurityCheckerResultStatus.Passed,
      message: hasActionRequired 
        ? `The following security checks require action: ${actionRequiredCheckNames.join(', ')}` : undefined,
      detectedTime: new Date().toISOString(),
      data: results,
    };
  }
}



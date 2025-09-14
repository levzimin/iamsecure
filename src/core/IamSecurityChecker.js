/**
 * Describes the base class for IAM security check runners.
 */
export class IamSecurityChecker {
  /**
   * Run the security check.
   * @returns {Promise<{resultStatus:'Passed'|'ActionRequired', message?:string, data:any}>}
   */
  async runCheck() {
    throw new Error('Not implemented');
  }
}



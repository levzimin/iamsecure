import { IamSecurityChecker } from '../core/IamSecurityChecker.js';
import { IamSecurityCheckerResultStatus } from '../core/resultStatus.js';
import { ListUsersCommand, ListMFADevicesCommand, GetLoginProfileCommand } from '@aws-sdk/client-iam';

/**
 * An IAM Security Checker that detects IAM users without MFA enabled.
 */
export class MissingMfaChecker extends IamSecurityChecker {
  constructor(iamClient) {
    super();

    if (!iamClient) {
      throw new Error('iamClient is required.');
    }

    this.__iamClient = iamClient;
    this.__maxUsersBatchSize = 10;
  }

  /**
   * Checks for users without MFA enabled. 
   * IMPORTANT: Only considers users with a console login profile.
   */
  async runCheck() {
    const usersWithoutMfa = [];

    let Marker;

    do {
      const { Users = [], IsTruncated, Marker: NextMarker } = await this.__iamClient.send(new ListUsersCommand({ Marker }));

      // Limit concurrency manually with simple batching to avoid throttling.
      const batchSize = this.__maxUsersBatchSize;

      for (let i = 0; i < Users.length; i += batchSize) {
        const batch = Users.slice(i, i + batchSize);

        await Promise.all(batch.map(async user => {
          // Only look at users with a console login profile.
          let hasConsoleLogin = false;

          try {
            await this.__iamClient.send(new GetLoginProfileCommand({ UserName: user.UserName }));
            hasConsoleLogin = true;
          } catch (e) {
            if (e && e.name === 'NoSuchEntityException') {
              // If the profile is not found, ignore this user for MFA purposes
              // IAM throws NoSuchEntityException when no login profile exists
              hasConsoleLogin = false;
            } else {
              // If the error we got is somethign we didn't expect, log it and rethrow.
              console.error(`Error getting login profile for user ${user.UserName}:`, e);
              throw e;
            }
          }

          if (!hasConsoleLogin) {
            return;
          }

          const { MFADevices = [] } = await this.__iamClient.send(new ListMFADevicesCommand({ UserName: user.UserName }));

          // If the user has not MFA devices enabled, the user is missing the MFA setup.
          if (!MFADevices || MFADevices.length === 0) {
            usersWithoutMfa.push({
              identityName: user.UserName,
              arn: user.Arn,
            });
          }
        }));
      }

      Marker = IsTruncated ? NextMarker : undefined;
    } while (Marker);

    if (usersWithoutMfa.length > 0) {
      return {
        resultStatus: IamSecurityCheckerResultStatus.ActionRequired,
        message: 'Some IAM users do not have MFA enabled.',
        detectedTime: new Date().toISOString(),
        data: { count: usersWithoutMfa.length, noMfaUsers: usersWithoutMfa },
      };
    }

    return { 
      resultStatus: IamSecurityCheckerResultStatus.Passed,
      detectedTime: new Date().toISOString(),
      data: { count: 0, noMfaUsers: [] },
    };
  }
}



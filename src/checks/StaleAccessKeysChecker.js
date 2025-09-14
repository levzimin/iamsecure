import { IamSecurityChecker } from '../core/IamSecurityChecker.js';
import { IamSecurityCheckerResultStatus } from '../core/resultStatus.js';
import { ListUsersCommand, ListAccessKeysCommand, GetAccessKeyLastUsedCommand } from '@aws-sdk/client-iam';

/**
 * An IAM Security Checker that detects IAM users with access keys that have not been used in a while.
 */
export class StaleAccessKeysChecker extends IamSecurityChecker {
  constructor(iamClient, options = {}) {
    super();
    
    if (!iamClient) {
        throw new Error('iamClient is required.');
    }

    const { unusedDaysLimit = 90 } = options;
    
    this.__iamClient = iamClient;
    this.__unusedDaysLimit = unusedDaysLimit;
    this.__maxUsersBatchSize = 10;
  }

  async runCheck() {
    const findings = [];
    const now = new Date();

    let Marker;

    do {
      const { Users = [], IsTruncated, Marker: NextMarker } = await this.__iamClient.send(new ListUsersCommand({ Marker }));

      // Simple batching to avoid throttling
      const batchSize = this.__maxUsersBatchSize;

      for (let i = 0; i < Users.length; i += batchSize) {
        const batchOfUsersToProcess = Users.slice(i, i + batchSize);

        await Promise.all(batchOfUsersToProcess.map(async user => {
          const listAccessKeysResponse = await this.__iamClient.send(new ListAccessKeysCommand({ UserName: user.UserName }));
          const keys = listAccessKeysResponse.AccessKeyMetadata || [];

          for (const key of keys) {
            if (key.Status !== 'Active') continue;

            let lastUsedAt = null;
            let daysSinceLastUsed = null;

            try {
              const lastUsedResp = await this.__iamClient.send(new GetAccessKeyLastUsedCommand({ AccessKeyId: key.AccessKeyId }));
              lastUsedAt = lastUsedResp.AccessKeyLastUsed?.LastUsedDate || null;

              if (lastUsedAt) {
                daysSinceLastUsed = this.__daysBetween(now, new Date(lastUsedAt));
              } else {
                daysSinceLastUsed = this.__daysBetween(now, new Date(key.CreateDate));
              }
              
            } catch (error) {
              console.error(`Error getting last used date for access key.`, error);
              // On error retrieving last used: treat as never used and fallback to creation date.
              daysSinceLastUsed = this.__daysBetween(now, new Date(key.CreateDate));
            }

            const isStale = daysSinceLastUsed !== null && daysSinceLastUsed >= this.__unusedDaysLimit;

            if (isStale) {
              findings.push({
                identityName: user.UserName,
                arn: user.Arn,
                maskedKeyId: this.__maskKeyId(key.AccessKeyId),
                daysSinceLastUse: daysSinceLastUsed,
                neverUsed: !lastUsedAt
              });
            }
          }
        }));
      }

      Marker = IsTruncated ? NextMarker : undefined;
    } while (Marker);

    if (findings.length > 0) {
      return {
        resultStatus: IamSecurityCheckerResultStatus.ActionRequired,
        message: 'Some users have stale access keys.',
        detectedTime: new Date().toISOString(),
        data: { count: findings.length, findings },
      };
    }

    return { resultStatus: IamSecurityCheckerResultStatus.Passed, detectedTime: new Date().toISOString(), data: { count: 0, findings: [] } };
  }

  __daysBetween(a, b) {
    const msForAFullDay = 24 * 60 * 60 * 1000;
    return Math.floor((a.getTime() - b.getTime()) / msForAFullDay);
  }

  __maskKeyId(keyId) {
    if (!keyId || typeof keyId !== 'string') return '';
    const visible = keyId.slice(-4);
    const hiddenLength = Math.max(0, keyId.length - 4);
    return '*'.repeat(hiddenLength) + visible;
  }
}



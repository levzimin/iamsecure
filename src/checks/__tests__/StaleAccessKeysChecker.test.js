import { describe, it, expect, jest } from '@jest/globals';
import { StaleAccessKeysChecker } from '../StaleAccessKeysChecker.js';

class MockIamClient {
  constructor(responders) { this.responders = responders; }
  async send(cmd) { return this.responders(cmd); }
}

function daysAgo(n) {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - n);
  return d;
}

function makeUsers(names) {
  return { Users: names.map(name => ({ UserName: name, Arn: `arn:aws:iam::123456789012:user/${name}` })) };
}

describe('StaleAccessKeysChecker basic functionality coverage', () => {
  it('Marks the user as action required in the report, when limit is 90d and keys were last used 120d ago', async () => {
    // Set up mock IAM client to return the correct responses for the commands.
    const accessKeyId = 'AKIAABCDEFGHIJKLMNOP';
    const responders = jest.fn(async cmd => {
      const n = cmd.constructor.name;
      if (n === 'ListUsersCommand') return makeUsers(['dev']);
      if (n === 'ListAccessKeysCommand') return {
        AccessKeyMetadata: [{ AccessKeyId: accessKeyId, Status: 'Active', CreateDate: daysAgo(200) }]
      };
      if (n === 'GetAccessKeyLastUsedCommand') return {
        AccessKeyLastUsed: { LastUsedDate: daysAgo(120) }
      };
      throw new Error('Unexpected command: ' + n);
    });

    const iam = new MockIamClient(responders);
    const checker = new StaleAccessKeysChecker(iam, { unusedDaysLimit: 90 });
    const res = await checker.runCheck();
    
    expect(res.resultStatus).toBe('ActionRequired');
    expect(res.data.count).toBe(1);
    const finding = res.data.findings[0];
    expect(finding.identityName).toBe('dev');
    expect(finding.maskedKeyId).toBe('*'.repeat(accessKeyId.length - 4) + accessKeyId.slice(-4));
  });

  it('Marks the user as action required in the report when limit is 90d, the keys were never used, and they were created 200d ago', async () => {
    // Set up mock IAM client to return the correct responses for the commands.
    const responders = jest.fn(async cmd => {
      const n = cmd.constructor.name;
      if (n === 'ListUsersCommand') return makeUsers(['svc']);
      if (n === 'ListAccessKeysCommand') return {
        AccessKeyMetadata: [{ AccessKeyId: 'AKIAXXXXXXXNEVERUSED', Status: 'Active', CreateDate: daysAgo(200) }]
      };
      if (n === 'GetAccessKeyLastUsedCommand') return { AccessKeyLastUsed: {} }; // no LastUsedDate
      throw new Error('Unexpected command: ' + n);
    });
    
    const iam = new MockIamClient(responders);
    const checker = new StaleAccessKeysChecker(iam, { unusedDaysLimit: 90 });
    const res = await checker.runCheck();
    
    expect(res.resultStatus).toBe('ActionRequired');
    expect(res.data.count).toBe(1);
  });

  it('passes with no action required when active keys are recently used, and while inactive keys are ignored', async () => {
    // Set up mock IAM client to return the correct responses for the commands.
    const responders = jest.fn(async cmd => {
      const n = cmd.constructor.name;
      if (n === 'ListUsersCommand') return makeUsers(['dev2']);
      if (n === 'ListAccessKeysCommand') return {
        AccessKeyMetadata: [
          { AccessKeyId: 'AKIARECENT', Status: 'Active', CreateDate: daysAgo(5) },
          { AccessKeyId: 'AKIAINACTIVE', Status: 'Inactive', CreateDate: daysAgo(400) },
        ]
      };
      if (n === 'GetAccessKeyLastUsedCommand') return { AccessKeyLastUsed: { LastUsedDate: daysAgo(5) } };
      throw new Error('Unexpected command: ' + n);
    });

    const iam = new MockIamClient(responders);
    const checker = new StaleAccessKeysChecker(iam, { unusedDaysLimit: 90 });
    const res = await checker.runCheck();
    
    expect(res.resultStatus).toBe('Passed');
    expect(res.data.count).toBe(0);
  });
});



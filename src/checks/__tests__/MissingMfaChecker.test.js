import { describe, it, expect, jest } from '@jest/globals';
import { MissingMfaChecker } from '../MissingMfaChecker.js';

class MockIamClient {
  constructor(responders) { this.responders = responders; }
  async send(cmd) { return this.responders(cmd); }
}

function makeListUsersResponse(usernames) {
  return { Users: usernames.map(name => ({ UserName: name, Arn: `arn:aws:iam::123456789012:user/${name}` })) };
}

describe('MissingMfaChecker basic functionality coverage', () => {
  it('Marks the user as action required in the report, when console login is available but no MFA is setup', async () => {
    // Set up mock IAM client to return the correct responses for the commands.
    const responders = jest.fn(async cmd => {
      const cmdName = cmd.constructor.name;
      if (cmdName === 'ListUsersCommand') return makeListUsersResponse(['alice']);
      if (cmdName === 'GetLoginProfileCommand') return {}; // exists
      if (cmdName === 'ListMFADevicesCommand') return { MFADevices: [] };
      throw new Error('Unexpected command');
    });

    const iam = new MockIamClient(responders);
    const checker = new MissingMfaChecker(iam);
    const res = await checker.runCheck();
    
    expect(res.resultStatus).toBe('ActionRequired');
    expect(res.data.noMfaUsers[0].identityName).toBe('alice');
  });

  it('ignores users without console login (NoSuchEntity on GetLoginProfile)', async () => {
    // Set up mock IAM client to return the correct responses for the commands.
    const responders = jest.fn(async cmd => {
      const cmdName = cmd.constructor.name;
      if (cmdName === 'ListUsersCommand') return makeListUsersResponse(['svc']);
      if (cmdName === 'GetLoginProfileCommand') { const e = new Error('no profile'); e.name = 'NoSuchEntityException'; throw e; }
      throw new Error('Unexpected command');
    });

    const iam = new MockIamClient(responders);
    const checker = new MissingMfaChecker(iam);
    const res = await checker.runCheck();
    
    expect(res.resultStatus).toBe('Passed');
    expect(res.data.count).toBe(0);
  });

  it('does not mark as action required users who have MFA devices setup', async () => {
    // Set up mock IAM client to return the correct responses for the commands.
    const responders = jest.fn(async cmd => {
      const cmdName = cmd.constructor.name;
      if (cmdName === 'ListUsersCommand') return makeListUsersResponse(['bob']);
      if (cmdName === 'GetLoginProfileCommand') return {}; // exists
      if (cmdName === 'ListMFADevicesCommand') return { MFADevices: [{}] };
      throw new Error('Unexpected command');
    });

    const iam = new MockIamClient(responders);
    const checker = new MissingMfaChecker(iam);
    const res = await checker.runCheck();
    
    expect(res.resultStatus).toBe('Passed');
    expect(res.data.count).toBe(0);
  });
});



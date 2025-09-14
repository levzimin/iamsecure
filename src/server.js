import express from 'express';
import { createInstance, supportedChecks } from './checks/multiSecurityCheckerFactory.js';

function createApp() {
  const app = express();
  app.use(express.json());

  // Returns the list of supported security checks
  app.get('/report/supported-checks', (req, res) => {
    res.json({ supportedChecks: supportedChecks() });
  });

  /**
   * Runs a report that includes the results of the security checks specified by the user.
   */
  app.post('/report', async (req, res) => {
    const { checks } = req.body || {};

    // Validate that checks is an array and is not empty.
    if (!Array.isArray(checks) || checks.length === 0) {
      return res.status(400).json({ error: "'checks' must be a non-empty array" });
    }

    try {
      // Pre-validate using registry
      const supported = new Set(supportedChecks());
      const requestedChecksThatWeDontSupport = checks.filter(checkToFilter => !supported.has(checkToFilter));
      
      if (requestedChecksThatWeDontSupport.length > 0) {
        return res.status(400).json({ error: 'Unsupported checks', unsupported: requestedChecksThatWeDontSupport });
      }

      const multiSecurityChecker = createInstance(checks);
      const report = await multiSecurityChecker.runCheck();
      res.json({ report });
    } catch (err) {
      res.status(500).json({ error: 'Could not run checks. please try again later.' });
    }
  });


  app.use((req, res) => {
    res.status(404).json({ error: 'Not Found' });
  });

  return app;
}

export function startServer(port = Number(process.env.PORT) || 8000) {
  const app = createApp();
  return app.listen(port, () => {
    console.log(`IAMSecure server listening on http://localhost:${port}`);
  });
}



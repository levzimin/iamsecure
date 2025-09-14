#!/usr/bin/env node
import express from 'express';
import { IAMClient } from '@aws-sdk/client-iam';
import { MissingMfaCheck } from './checks/MissingMfaCheck.js';

const app = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 8000;

app.use(express.json());

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/report', async (req, res) => {
  const { checks } = req.body || {};

  if (!Array.isArray(checks) || checks.length === 0) {
    return res.status(400).json({ error: "'checks' must be a non-empty array" });
  }

  // Validate supported checks
  const unsupported = checks.filter(c => c !== 'MFA');
  if (unsupported.length > 0) {
    return res.status(400).json({ error: 'Unsupported checks', unsupported });
  }

  try {
    const results = [];

    if (checks.includes('MFA')) {
      const region = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1';
      const iam = new IAMClient({ region });
      const check = new MissingMfaCheck({ iam, concurrency: 8 });
      const report = await check.runCheck();
      results.push({ id: 'MFA', report });
    }

    res.json({ time: new Date().toISOString(), results });
  } catch (err) {
    res.status(500).json({ error: err.message || String(err) });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

app.listen(PORT, () => {
  console.log(`IAMSecure server listening on http://localhost:${PORT}`);
});



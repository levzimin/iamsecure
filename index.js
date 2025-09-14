#!/usr/bin/env node
import 'dotenv/config';
import { startServer } from './src/server.js';

function validateRequiredEnv() {
  const hasProfile = !!process.env.AWS_PROFILE;
  const hasKeys = !!process.env.AWS_ACCESS_KEY_ID && !!process.env.AWS_SECRET_ACCESS_KEY;

  if (!hasProfile && !hasKeys) {
    throw new Error('AWS credentials not found. Set AWS_PROFILE or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.');
  }
}

validateRequiredEnv();
startServer();

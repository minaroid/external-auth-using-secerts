#!/usr/bin/env node
'use strict';
/**
 * Convenience runner for local development: starts the auth service, waits for
 * it, then starts service B and service A. Ctrl-C stops all three.
 */
const {spawn} = require('child_process');
const path = require('path');
const env = require('./env-file');

const ROOT = path.join(__dirname, '..');
const AUTH = env.authBaseUrl();

const children = [];

function start(name, workspace) {
  const child = spawn('npm', ['start', '--workspace', workspace], {
    cwd: ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const tag = `[${name}]`;
  child.stdout.on('data', data => process.stdout.write(prefix(tag, data)));
  child.stderr.on('data', data => process.stderr.write(prefix(tag, data)));
  child.on('exit', code => {
    console.log(`${tag} exited with code ${code}`);
    shutdown(code ?? 0);
  });
  children.push(child);
  return child;
}

function prefix(tag, data) {
  return data
    .toString()
    .split('\n')
    .filter(line => line.length)
    .map(line => `${tag} ${line}\n`)
    .join('');
}

async function waitForHealth(url, attempts = 40) {
  for (let i = 0; i < attempts; i++) {
    try {
      const response = await fetch(`${url}/health`);
      if (response.ok) return true;
    } catch {
      /* still starting */
    }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  return false;
}

let shuttingDown = false;
function shutdown(code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  for (const child of children) child.kill('SIGTERM');
  setTimeout(() => process.exit(code), 500);
}

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));

async function main() {
  const missing = ['a', 'b'].filter(service => !env.read(service).CLIENT_SECRET);
  if (missing.length) {
    console.error(
      `CLIENT_SECRET is missing from: ${missing
        .map(service => env.envPath(service))
        .join(', ')}\n` +
        'Run: npm run bootstrap, then start the auth service and run npm run seed.',
    );
    process.exit(1);
  }

  start('auth', '@tra/auth-service');
  if (!(await waitForHealth(AUTH))) {
    console.error('auth service did not become healthy');
    return shutdown(1);
  }

  start('svc-b', '@tra/service-b');
  start('svc-a', '@tra/service-a');
}

main();

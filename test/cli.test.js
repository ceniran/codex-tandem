'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const cliPath = path.resolve(__dirname, '../src/cli.js');
const fakeCodexPath = path.resolve(__dirname, 'fixtures/fake-codex');

function authDocument(label) {
  return JSON.stringify({
    auth_mode: 'chatgpt',
    tokens: {
      access_token: `access-${label}-abcdefghijklmnopqrstuvwxyz`,
      refresh_token: `refresh-${label}-abcdefghijklmnopqrstuvwxyz`,
      id_token: `id-${label}-abcdefghijklmnopqrstuvwxyz`,
      account_id: `account-${label}`
    }
  });
}

test('CLI initializes, logs in a second account, and switches without moving sessions', t => {
  if (process.platform === 'win32') return t.skip('executable fixture is Unix-oriented');
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'codex-tandem-cli-'));
  const codexHome = path.join(base, 'codex-home');
  const tandemHome = path.join(base, 'tandem-home');
  fs.mkdirSync(codexHome, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(codexHome, 'auth.json'), authDocument('A'), { mode: 0o600 });
  fs.mkdirSync(path.join(codexHome, 'sessions'), { mode: 0o700 });
  fs.writeFileSync(path.join(codexHome, 'sessions', 'continuity-marker'), 'same-session');
  fs.chmodSync(fakeCodexPath, 0o755);
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));

  const env = {
    ...process.env,
    CODEX_HOME: codexHome,
    CODEX_TANDEM_HOME: tandemHome,
    CODEX_BIN: fakeCodexPath,
    FAKE_ACCOUNT_LABEL: 'B'
  };
  const run = (...args) => spawnSync(process.execPath, [cliPath, ...args], {
    env,
    encoding: 'utf8'
  });

  assert.equal(run('init', 'A').status, 0);
  assert.equal(run('login', 'B').status, 0);
  const switched = run('switch', 'B');
  assert.equal(switched.status, 0, switched.stderr);
  assert.match(switched.stdout, /Switched A -> B/);
  assert.equal(JSON.parse(fs.readFileSync(path.join(codexHome, 'auth.json'))).tokens.account_id, 'account-B');
  assert.equal(fs.readFileSync(path.join(codexHome, 'sessions', 'continuity-marker'), 'utf8'), 'same-session');
  const status = run('status');
  assert.equal(status.status, 0, status.stderr);
  assert.match(status.stdout, /Current: B/);
  assert.match(status.stdout, /A: ready/);
  assert.match(status.stdout, /B: ready \(active\)/);
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  CodexAccountProfiles,
  isAccountFailoverError,
  runWithAccountFailover,
  validateAuthDocument,
  writeAtomic
} = require('../src/account-profiles');

function authDocument(label, suffix = '') {
  return Buffer.from(JSON.stringify({
    auth_mode: 'chatgpt',
    tokens: {
      access_token: `access-${label}-${suffix}-abcdefghijklmnopqrstuvwxyz`,
      refresh_token: `refresh-${label}-${suffix}-abcdefghijklmnopqrstuvwxyz`,
      id_token: `id-${label}-${suffix}-abcdefghijklmnopqrstuvwxyz`,
      account_id: `account-${label}`
    }
  }));
}

function createHarness(validateLogin = async () => {}) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'codex-tandem-'));
  const rootDir = path.join(base, 'profiles');
  const codexHome = path.join(base, 'codex-home');
  fs.mkdirSync(codexHome, { recursive: true, mode: 0o700 });
  writeAtomic(path.join(codexHome, 'auth.json'), authDocument('A', 'refreshed'));
  const profiles = new CodexAccountProfiles({ rootDir, codexHome, validateLogin });
  profiles.importLiveAs('A');
  writeAtomic(profiles.profileAuthPath('B'), authDocument('B'));
  return { base, rootDir, codexHome, profiles };
}

test('validates credentials without exposing token values', () => {
  assert.equal(validateAuthDocument(authDocument('A')).auth_mode, 'chatgpt');
  assert.throws(() => validateAuthDocument(Buffer.from('{broken')), /valid JSON/);
  assert.throws(() => validateAuthDocument(Buffer.from('{}')), /no usable/);
});

test('imports the live login as the initial profile', t => {
  const harness = createHarness();
  t.after(() => fs.rmSync(harness.base, { recursive: true, force: true }));
  assert.equal(harness.profiles.readCurrent(), 'A');
  assert.equal(harness.profiles.status().automaticFailoverReady, true);
});

test('switch persists refreshed credentials and activates the target atomically', async t => {
  const harness = createHarness();
  t.after(() => fs.rmSync(harness.base, { recursive: true, force: true }));

  const result = await harness.profiles.switchTo('B');

  assert.equal(result.changed, true);
  assert.equal(harness.profiles.readCurrent(), 'B');
  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(harness.codexHome, 'auth.json'))),
    JSON.parse(authDocument('B'))
  );
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(path.join(harness.codexHome, 'auth.json')).mode & 0o777, 0o600);
  }
});

test('failed validation restores the original login and marker', async t => {
  const harness = createHarness(async () => { throw new Error('rejected'); });
  t.after(() => fs.rmSync(harness.base, { recursive: true, force: true }));

  await assert.rejects(harness.profiles.switchTo('B'), error => error.code === 'validation_failed');
  assert.equal(harness.profiles.readCurrent(), 'A');
  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(harness.codexHome, 'auth.json'))),
    JSON.parse(authDocument('A', 'refreshed'))
  );
});

test('startup recovers an interrupted switch from its journal', t => {
  const harness = createHarness();
  t.after(() => fs.rmSync(harness.base, { recursive: true, force: true }));
  writeAtomic(path.join(harness.codexHome, 'auth.json'), authDocument('B'));
  writeAtomic(
    path.join(harness.rootDir, 'switching.json'),
    Buffer.from(JSON.stringify({ from: 'A', to: 'B' }))
  );

  const recovered = new CodexAccountProfiles({
    rootDir: harness.rootDir,
    codexHome: harness.codexHome
  });
  assert.equal(recovered.readCurrent(), 'A');
  assert.equal(fs.existsSync(path.join(harness.rootDir, 'switching.json')), false);
});

test('automatic failover is conservative and retries once', async () => {
  assert.equal(isAccountFailoverError({ message: "You've hit your usage limit" }), true);
  assert.equal(isAccountFailoverError({ message: 'temporary HTTP 429' }), false);

  let attempts = 0;
  const result = await runWithAccountFailover({
    profiles: {
      status: () => ({ current: 'A', automaticFailoverReady: true }),
      otherProfile: () => 'B',
      switchTo: async () => ({ rollback: async () => assert.fail('unexpected rollback') })
    },
    runAttempt: async () => {
      attempts += 1;
      if (attempts === 1) throw new Error('usage_limit_reached');
      return 'same session resumed';
    }
  });

  assert.deepEqual(result, {
    value: 'same session resumed',
    failover: { from: 'A', to: 'B' }
  });
});

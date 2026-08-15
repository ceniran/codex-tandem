'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

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

async function createHarness(validateLogin = async () => {}, faultInjector) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'codex-tandem-'));
  const rootDir = path.join(base, 'profiles');
  const codexHome = path.join(base, 'codex-home');
  fs.mkdirSync(codexHome, { recursive: true, mode: 0o700 });
  writeAtomic(path.join(codexHome, 'auth.json'), authDocument('A', 'refreshed'));
  const profiles = new CodexAccountProfiles({ rootDir, codexHome, validateLogin, faultInjector });
  await profiles.importLiveAs('A');
  writeAtomic(profiles.profileAuthPath('B'), authDocument('B'));
  return { base, rootDir, codexHome, profiles };
}

test('validates credentials without exposing token values', () => {
  assert.equal(validateAuthDocument(authDocument('A')).auth_mode, 'chatgpt');
  assert.throws(() => validateAuthDocument(Buffer.from('{broken')), /valid JSON/);
  assert.throws(() => validateAuthDocument(Buffer.from('{}')), /no usable/);
});

test('imports the live login as the initial profile', async t => {
  const harness = await createHarness();
  t.after(() => fs.rmSync(harness.base, { recursive: true, force: true }));
  assert.equal(harness.profiles.readCurrent(), 'A');
  assert.equal(harness.profiles.status().automaticFailoverReady, true);
});

test('switch persists refreshed credentials and activates the target atomically', async t => {
  const harness = await createHarness();
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
  const harness = await createHarness(async () => { throw new Error('rejected'); });
  t.after(() => fs.rmSync(harness.base, { recursive: true, force: true }));

  await assert.rejects(harness.profiles.switchTo('B'), error => error.code === 'validation_failed');
  assert.equal(harness.profiles.readCurrent(), 'A');
  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(harness.codexHome, 'auth.json'))),
    JSON.parse(authDocument('A', 'refreshed'))
  );
});

test('startup recovers an interrupted switch from its journal', async t => {
  const harness = await createHarness();
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
  await recovered.recover();
  assert.equal(recovered.readCurrent(), 'A');
  assert.equal(fs.existsSync(path.join(harness.rootDir, 'switching.json')), false);
});

test('credential symlinks are rejected instead of followed', async t => {
  const harness = await createHarness();
  t.after(() => fs.rmSync(harness.base, { recursive: true, force: true }));
  const target = harness.profiles.profileAuthPath('B');
  const realCredential = path.join(harness.base, 'outside-auth.json');
  writeAtomic(realCredential, authDocument('B', 'outside'));
  fs.rmSync(target);
  fs.symlinkSync(realCredential, target);

  await assert.rejects(
    harness.profiles.switchTo('B'),
    error => error.code === 'path_unsafe'
  );
  assert.equal(harness.profiles.readCurrent(), 'A');
});

test('credential files with group or world permissions are rejected', async t => {
  const harness = await createHarness();
  t.after(() => fs.rmSync(harness.base, { recursive: true, force: true }));
  const target = harness.profiles.profileAuthPath('B');
  fs.chmodSync(target, 0o640);

  await assert.rejects(
    harness.profiles.switchTo('B'),
    error => error.code === 'auth_permissions'
  );
  assert.equal(harness.profiles.readCurrent(), 'A');
});

test('the operation lock excludes a second process for the whole validation window', async t => {
  let releaseValidation;
  const validationStarted = new Promise(resolve => {
    releaseValidation = resolve;
  });
  let notifyStarted;
  const started = new Promise(resolve => { notifyStarted = resolve; });
  const harness = await createHarness(async () => {
    notifyStarted();
    await validationStarted;
  });
  t.after(() => fs.rmSync(harness.base, { recursive: true, force: true }));
  const contender = new CodexAccountProfiles({
    rootDir: harness.rootDir,
    codexHome: harness.codexHome
  });

  const firstSwitch = harness.profiles.switchTo('B');
  await started;
  await assert.rejects(contender.switchTo('B'), error => error.code === 'operation_locked');
  releaseValidation();
  await firstSwitch;
  assert.equal(harness.profiles.readCurrent(), 'B');
});

test('a stale lock left by SIGKILL is reaped and an interrupted switch rolls back', async t => {
  if (process.platform === 'win32') return t.skip('SIGKILL and O_NOFOLLOW are Unix-specific');
  const harness = await createHarness();
  t.after(() => fs.rmSync(harness.base, { recursive: true, force: true }));
  const modulePath = path.resolve(__dirname, '../src/account-profiles.js');
  const childScript = `
    const { CodexAccountProfiles } = require(${JSON.stringify(modulePath)});
    const profiles = new CodexAccountProfiles({
      rootDir: process.env.TEST_ROOT,
      codexHome: process.env.TEST_CODEX_HOME,
      faultInjector(point) {
        if (point === 'after_live_replace') process.kill(process.pid, 'SIGKILL');
      }
    });
    profiles.switchTo('B');
  `;
  const child = spawnSync(process.execPath, ['-e', childScript], {
    env: {
      ...process.env,
      TEST_ROOT: harness.rootDir,
      TEST_CODEX_HOME: harness.codexHome
    }
  });
  assert.equal(child.signal, 'SIGKILL');

  const recovered = new CodexAccountProfiles({
    rootDir: harness.rootDir,
    codexHome: harness.codexHome
  });
  assert.equal(await recovered.recover(), true);
  assert.equal(recovered.readCurrent(), 'A');
  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(harness.codexHome, 'auth.json'))),
    JSON.parse(authDocument('A', 'refreshed'))
  );
  assert.equal(fs.existsSync(path.join(harness.rootDir, 'operation.lock')), false);
});

test('SIGKILL after journaling but before replacement also restores the original profile', async t => {
  if (process.platform === 'win32') return t.skip('SIGKILL is Unix-specific');
  const harness = await createHarness();
  t.after(() => fs.rmSync(harness.base, { recursive: true, force: true }));
  const modulePath = path.resolve(__dirname, '../src/account-profiles.js');
  const childScript = `
    const { CodexAccountProfiles } = require(${JSON.stringify(modulePath)});
    const profiles = new CodexAccountProfiles({
      rootDir: process.env.TEST_ROOT,
      codexHome: process.env.TEST_CODEX_HOME,
      faultInjector(point) {
        if (point === 'after_journal') process.kill(process.pid, 'SIGKILL');
      }
    });
    profiles.switchTo('B');
  `;
  const child = spawnSync(process.execPath, ['-e', childScript], {
    env: {
      ...process.env,
      TEST_ROOT: harness.rootDir,
      TEST_CODEX_HOME: harness.codexHome
    }
  });
  assert.equal(child.signal, 'SIGKILL');

  const recovered = new CodexAccountProfiles({
    rootDir: harness.rootDir,
    codexHome: harness.codexHome
  });
  assert.equal(await recovered.recover(), true);
  assert.equal(recovered.readCurrent(), 'A');
  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(harness.codexHome, 'auth.json'))),
    JSON.parse(authDocument('A', 'refreshed'))
  );
});

test('SIGKILL after journal cleanup leaves a fully committed target profile', async t => {
  if (process.platform === 'win32') return t.skip('SIGKILL is Unix-specific');
  const harness = await createHarness();
  t.after(() => fs.rmSync(harness.base, { recursive: true, force: true }));
  const modulePath = path.resolve(__dirname, '../src/account-profiles.js');
  const childScript = `
    const { CodexAccountProfiles } = require(${JSON.stringify(modulePath)});
    const profiles = new CodexAccountProfiles({
      rootDir: process.env.TEST_ROOT,
      codexHome: process.env.TEST_CODEX_HOME,
      faultInjector(point) {
        if (point === 'after_journal_clear') process.kill(process.pid, 'SIGKILL');
      }
    });
    profiles.switchTo('B');
  `;
  const child = spawnSync(process.execPath, ['-e', childScript], {
    env: {
      ...process.env,
      TEST_ROOT: harness.rootDir,
      TEST_CODEX_HOME: harness.codexHome
    }
  });
  assert.equal(child.signal, 'SIGKILL');

  const recovered = new CodexAccountProfiles({
    rootDir: harness.rootDir,
    codexHome: harness.codexHome
  });
  assert.equal(await recovered.recover(), false);
  assert.equal(recovered.readCurrent(), 'B');
  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(harness.codexHome, 'auth.json'))),
    JSON.parse(authDocument('B'))
  );
});

test('an ENOSPC-style failure before replacement leaves the original account intact', async t => {
  const noSpace = Object.assign(new Error('disk full'), { code: 'ENOSPC' });
  const harness = await createHarness(async () => {}, point => {
    if (point === 'before_live_replace') throw noSpace;
  });
  t.after(() => fs.rmSync(harness.base, { recursive: true, force: true }));

  await assert.rejects(
    harness.profiles.switchTo('B'),
    error => error.code === 'switch_failed' && error.cause?.code === 'ENOSPC'
  );
  assert.equal(harness.profiles.readCurrent(), 'A');
  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(harness.codexHome, 'auth.json'))),
    JSON.parse(authDocument('A', 'refreshed'))
  );
});

test('an old rollback cannot overwrite a later successful switch', async t => {
  const harness = await createHarness();
  t.after(() => fs.rmSync(harness.base, { recursive: true, force: true }));

  const firstTransaction = await harness.profiles.switchTo('B');
  await harness.profiles.switchTo('A');
  await assert.rejects(firstTransaction.rollback(), error => error.code === 'rollback_conflict');
  assert.equal(harness.profiles.readCurrent(), 'A');
  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(harness.codexHome, 'auth.json'))),
    JSON.parse(authDocument('A', 'refreshed'))
  );
});

test('a read-only Codex home cannot produce a partial switch', async t => {
  if (process.platform === 'win32' || process.getuid?.() === 0) {
    return t.skip('permission failure requires a non-root Unix user');
  }
  const harness = await createHarness();
  t.after(() => {
    try { fs.chmodSync(harness.codexHome, 0o700); } catch (_) {}
    fs.rmSync(harness.base, { recursive: true, force: true });
  });
  fs.chmodSync(harness.codexHome, 0o500);

  await assert.rejects(harness.profiles.switchTo('B'));
  assert.equal(harness.profiles.readCurrent(), 'A');
  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(harness.codexHome, 'auth.json'))),
    JSON.parse(authDocument('A', 'refreshed'))
  );
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

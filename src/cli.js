#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const {
  CodexAccountProfiles,
  TandemError,
  normalizeProfileName,
  readSecureAuth
} = require('./account-profiles');

const codexHome = path.resolve(process.env.CODEX_HOME || path.join(os.homedir(), '.codex'));
const tandemHome = path.resolve(process.env.CODEX_TANDEM_HOME || path.join(os.homedir(), '.codex-tandem'));
const codexBin = process.env.CODEX_BIN || 'codex';

function usage() {
  return `Codex Tandem — two accounts, one Codex home\n\nUsage:\n  codex-tandem init A|B     Save the current Codex login as the first profile\n  codex-tandem login A|B    Log into a profile without replacing the active one\n  codex-tandem switch A|B   Switch auth.json and validate the target login\n  codex-tandem status       Show profile readiness (never token values)\n\nEnvironment:\n  CODEX_HOME          Shared Codex home (default: ~/.codex)\n  CODEX_TANDEM_HOME   Private profile store (default: ~/.codex-tandem)\n  CODEX_BIN           Codex executable (default: codex)`;
}

function codexLoginStatus(home = codexHome) {
  const result = spawnSync(codexBin, ['login', 'status'], {
    env: { ...process.env, CODEX_HOME: home },
    stdio: 'ignore',
    timeout: 20_000
  });
  if (result.error || result.status !== 0) {
    throw new TandemError('validation_failed', `Codex login validation failed for ${home}.`);
  }
}

async function loginProfile(profile, profiles) {
  const target = normalizeProfileName(profile);
  const loginHome = fs.mkdtempSync(path.join(tandemHome, `.login-${target.toLowerCase()}-`));
  fs.chmodSync(loginHome, 0o700);
  try {
    const result = spawnSync(codexBin, ['login'], {
      env: { ...process.env, CODEX_HOME: loginHome },
      stdio: 'inherit'
    });
    if (result.error || result.status !== 0) {
      throw new TandemError('login_failed', `Codex login failed for profile ${target}.`);
    }
    const auth = readSecureAuth(path.join(loginHome, 'auth.json'));
    await profiles.storeProfile(target, auth);
    return target;
  } finally {
    fs.rmSync(loginHome, { recursive: true, force: true });
  }
}

async function main(argv) {
  const [command, profileArgument] = argv;
  if (!command || command === '--help' || command === '-h') {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  const profiles = new CodexAccountProfiles({
    rootDir: tandemHome,
    codexHome,
    validateLogin: () => codexLoginStatus()
  });

  if (command === 'status') {
    await profiles.recover();
    const status = profiles.status();
    process.stdout.write(`Current: ${status.current || 'not initialized'}\n`);
    for (const profile of ['A', 'B']) {
      const item = status.profiles[profile];
      process.stdout.write(`${profile}: ${item.configured ? 'ready' : 'not configured'}${item.current ? ' (active)' : ''}\n`);
    }
    return;
  }

  if (command === 'init') {
    const profile = await profiles.importLiveAs(profileArgument);
    codexLoginStatus();
    process.stdout.write(`Initialized profile ${profile}. Sessions and config remain in ${codexHome}.\n`);
    return;
  }

  if (command === 'login') {
    const profile = await loginProfile(profileArgument, profiles);
    process.stdout.write(`Profile ${profile} is ready. The active account was not changed.\n`);
    return;
  }

  if (command === 'switch') {
    const result = await profiles.switchTo(profileArgument);
    process.stdout.write(result.changed
      ? `Switched ${result.from} -> ${result.to}. Sessions and config were not moved.\n`
      : `Profile ${result.to} is already active and its login is valid.\n`);
    return;
  }

  throw new TandemError('command_unknown', `Unknown command: ${command}\n\n${usage()}`);
}

main(process.argv.slice(2)).catch(error => {
  const message = error instanceof TandemError ? error.message : 'Unexpected failure.';
  process.stderr.write(`codex-tandem: ${message}\n`);
  process.exitCode = 1;
});

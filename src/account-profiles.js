'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PROFILE_NAMES = Object.freeze(['A', 'B']);
const MAX_AUTH_BYTES = 5 * 1024 * 1024;

class TandemError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = 'TandemError';
    this.code = code;
  }
}

function normalizeProfileName(value) {
  const profile = String(value || '').trim().toUpperCase();
  if (!PROFILE_NAMES.includes(profile)) {
    throw new TandemError('profile_unknown', 'Profile must be A or B.');
  }
  return profile;
}

function profileDirectoryName(profile) {
  return `account-${normalizeProfileName(profile).toLowerCase()}`;
}

function validateAuthDocument(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0 || buffer.length > MAX_AUTH_BYTES) {
    throw new TandemError('auth_invalid', 'Credential file has an invalid size.');
  }

  let document;
  try {
    document = JSON.parse(buffer.toString('utf8'));
  } catch (_) {
    throw new TandemError('auth_invalid', 'Credential file is not valid JSON.');
  }

  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new TandemError('auth_invalid', 'Credential document has an invalid shape.');
  }

  const tokens = document.tokens;
  const hasChatGptTokens = tokens && typeof tokens === 'object'
    && typeof tokens.access_token === 'string' && tokens.access_token.length > 20
    && typeof tokens.refresh_token === 'string' && tokens.refresh_token.length > 20;
  const hasApiKey = typeof document.OPENAI_API_KEY === 'string'
    && document.OPENAI_API_KEY.length > 20;
  if (!hasChatGptTokens && !hasApiKey) {
    throw new TandemError('auth_invalid', 'Credential document has no usable login fields.');
  }
  return document;
}

function ensurePrivateDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(directory, 0o700); } catch (_) {}
}

function fsyncDirectory(directory) {
  let descriptor;
  try {
    descriptor = fs.openSync(directory, 'r');
    fs.fsyncSync(descriptor);
  } catch (_) {
    // Some filesystems and Windows do not support directory fsync.
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch (_) {}
    }
  }
}

function writeAtomic(filePath, buffer, mode = 0o600) {
  const directory = path.dirname(filePath);
  ensurePrivateDirectory(directory);
  const temporary = path.join(
    directory,
    `.${path.basename(filePath)}.${process.pid}.${crypto.randomUUID()}.tmp`
  );
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, 'wx', mode);
    fs.writeFileSync(descriptor, buffer);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.chmodSync(temporary, mode);
    fs.renameSync(temporary, filePath);
    try { fs.chmodSync(filePath, mode); } catch (_) {}
    fsyncDirectory(directory);
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch (_) {}
    }
    try { fs.rmSync(temporary, { force: true }); } catch (_) {}
  }
}

function readSecureAuth(filePath) {
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (_) {
    throw new TandemError('auth_missing', `No credential found at ${filePath}.`);
  }
  if (!stat.isFile()) {
    throw new TandemError('auth_invalid', 'Credential path is not a regular file.');
  }
  if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
    throw new TandemError('auth_permissions', `Credential permissions must be 0600: ${filePath}`);
  }
  const buffer = fs.readFileSync(filePath);
  validateAuthDocument(buffer);
  return buffer;
}

function isAccountFailoverError(error) {
  const diagnostic = String(error?.codexDiagnostic || error?.message || '').toLowerCase();
  const explicitSignals = [
    'usage_limit_reached',
    'usage limit reached',
    "you've hit your usage limit",
    'you have hit your usage limit',
    'insufficient_quota',
    'quota exceeded',
    'authentication failed',
    'authentication error',
    'invalid authentication',
    'invalid_grant',
    'refresh token has been revoked',
    'refresh token revoked',
    'token has been revoked',
    'invalid access token'
  ];
  return explicitSignals.some(signal => diagnostic.includes(signal));
}

async function runWithAccountFailover({ runAttempt, profiles }) {
  try {
    return { value: await runAttempt(), failover: null };
  } catch (originalError) {
    const status = profiles.status();
    if (!status.automaticFailoverReady || !isAccountFailoverError(originalError)) {
      throw originalError;
    }

    const originalProfile = status.current;
    const targetProfile = profiles.otherProfile(originalProfile);
    const transaction = await profiles.switchTo(targetProfile);
    try {
      return {
        value: await runAttempt(),
        failover: { from: originalProfile, to: targetProfile }
      };
    } catch (retryError) {
      await transaction.rollback();
      const error = new TandemError('failover_failed', 'Retry failed; the original profile was restored.');
      error.originalProfile = originalProfile;
      error.targetProfile = targetProfile;
      error.cause = retryError;
      throw error;
    }
  }
}

class CodexAccountProfiles {
  constructor({ rootDir, codexHome, validateLogin }) {
    this.rootDir = path.resolve(rootDir);
    this.codexHome = path.resolve(codexHome);
    this.liveAuthPath = path.join(this.codexHome, 'auth.json');
    this.currentPath = path.join(this.rootDir, 'current.json');
    this.journalPath = path.join(this.rootDir, 'switching.json');
    this.validateLogin = typeof validateLogin === 'function' ? validateLogin : async () => {};
    ensurePrivateDirectory(this.rootDir);
    ensurePrivateDirectory(this.codexHome);
    this.recoverInterruptedSwitch();
  }

  profileAuthPath(profile) {
    return path.join(this.rootDir, profileDirectoryName(profile), 'auth.json');
  }

  readCurrent() {
    try {
      return normalizeProfileName(JSON.parse(fs.readFileSync(this.currentPath, 'utf8'))?.current);
    } catch (_) {
      return null;
    }
  }

  writeCurrent(profile) {
    const current = normalizeProfileName(profile);
    writeAtomic(this.currentPath, Buffer.from(`${JSON.stringify({
      current,
      updated_at: new Date().toISOString()
    }, null, 2)}\n`));
  }

  importLiveAs(profile) {
    const target = normalizeProfileName(profile);
    const liveAuth = readSecureAuth(this.liveAuthPath);
    writeAtomic(this.profileAuthPath(target), liveAuth);
    this.writeCurrent(target);
    return target;
  }

  writeSwitchJournal(from, to) {
    writeAtomic(this.journalPath, Buffer.from(`${JSON.stringify({
      from: normalizeProfileName(from),
      to: normalizeProfileName(to),
      started_at: new Date().toISOString()
    }, null, 2)}\n`));
  }

  clearSwitchJournal() {
    fs.rmSync(this.journalPath, { force: true });
    fsyncDirectory(this.rootDir);
  }

  recoverInterruptedSwitch() {
    if (!fs.existsSync(this.journalPath)) return false;
    let journal;
    try {
      journal = JSON.parse(fs.readFileSync(this.journalPath, 'utf8'));
      journal.from = normalizeProfileName(journal.from);
      journal.to = normalizeProfileName(journal.to);
    } catch (_) {
      throw new TandemError('journal_invalid', 'The interrupted switch journal is invalid.');
    }
    writeAtomic(this.liveAuthPath, readSecureAuth(this.profileAuthPath(journal.from)));
    this.writeCurrent(journal.from);
    this.clearSwitchJournal();
    return true;
  }

  isConfigured(profile) {
    try {
      readSecureAuth(this.profileAuthPath(profile));
      return true;
    } catch (_) {
      return false;
    }
  }

  status() {
    const current = this.readCurrent();
    const profiles = Object.fromEntries(PROFILE_NAMES.map(profile => [profile, {
      configured: this.isConfigured(profile),
      current: current === profile
    }]));
    return {
      current,
      profiles,
      automaticFailoverReady: Boolean(current && PROFILE_NAMES.every(profile => profiles[profile].configured))
    };
  }

  otherProfile(profile) {
    return normalizeProfileName(profile) === 'A' ? 'B' : 'A';
  }

  async switchTo(targetProfile) {
    const target = normalizeProfileName(targetProfile);
    const previousProfile = this.readCurrent();
    if (!previousProfile) {
      throw new TandemError('not_initialized', 'Run `codex-tandem init A` first.');
    }
    if (target === previousProfile) {
      await this.validateLogin();
      return { changed: false, from: previousProfile, to: target, rollback: async () => {} };
    }

    const previousAuth = readSecureAuth(this.liveAuthPath);
    const targetAuth = readSecureAuth(this.profileAuthPath(target));
    const previousMarker = fs.readFileSync(this.currentPath);

    // Keep refresh-token changes made by Codex while this profile was active.
    writeAtomic(this.profileAuthPath(previousProfile), previousAuth);
    this.writeSwitchJournal(previousProfile, target);

    let liveWasReplaced = false;
    try {
      writeAtomic(this.liveAuthPath, targetAuth);
      liveWasReplaced = true;
      await this.validateLogin();
      this.writeCurrent(target);
      this.clearSwitchJournal();
    } catch (error) {
      if (liveWasReplaced) {
        writeAtomic(this.liveAuthPath, previousAuth);
        writeAtomic(this.currentPath, previousMarker);
      }
      try { this.clearSwitchJournal(); } catch (_) {}
      if (error instanceof TandemError) throw error;
      throw new TandemError('validation_failed', 'Target login failed; the original profile was restored.');
    }

    let rolledBack = false;
    const rollback = async () => {
      if (rolledBack) return;
      rolledBack = true;
      try {
        writeAtomic(this.profileAuthPath(target), readSecureAuth(this.liveAuthPath));
      } catch (_) {}
      writeAtomic(this.liveAuthPath, previousAuth);
      writeAtomic(this.currentPath, previousMarker);
    };
    return { changed: true, from: previousProfile, to: target, rollback };
  }
}

module.exports = {
  CodexAccountProfiles,
  PROFILE_NAMES,
  TandemError,
  isAccountFailoverError,
  normalizeProfileName,
  readSecureAuth,
  runWithAccountFailover,
  validateAuthDocument,
  writeAtomic
};

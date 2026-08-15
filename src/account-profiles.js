'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const PROFILE_NAMES = Object.freeze(['A', 'B']);
const MAX_AUTH_BYTES = 5 * 1024 * 1024;
const MAX_METADATA_BYTES = 64 * 1024;
const INCOMPLETE_LOCK_GRACE_MS = 30_000;

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
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new TandemError('path_unsafe', `Directory must not be a symbolic link: ${directory}`);
  }
  validateOwnerAndMode(stat, directory, true);
}

function validateOwnerAndMode(stat, filePath, directory = false) {
  if (process.platform === 'win32') return;
  const expectedUid = typeof process.geteuid === 'function' ? process.geteuid() : process.getuid?.();
  const expectedGid = typeof process.getegid === 'function' ? process.getegid() : process.getgid?.();
  if (expectedUid !== undefined && stat.uid !== expectedUid) {
    throw new TandemError('path_owner', `Path must be owned by the current user: ${filePath}`);
  }
  if (expectedGid !== undefined && stat.gid !== expectedGid) {
    throw new TandemError('path_group', `Path must use the current user's group: ${filePath}`);
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new TandemError(
      directory ? 'directory_permissions' : 'file_permissions',
      `${directory ? 'Directory' : 'File'} permissions must not grant group or world access: ${filePath}`
    );
  }
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

function readSecureFile(filePath, { missingCode = 'file_missing', maxBytes = MAX_METADATA_BYTES } = {}) {
  let linkStat;
  try {
    linkStat = fs.lstatSync(filePath);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw new TandemError(missingCode, `No file found at ${filePath}.`);
    }
    throw error;
  }
  if (linkStat.isSymbolicLink() || !linkStat.isFile()) {
    throw new TandemError('path_unsafe', `Path must be a regular file, not a link: ${filePath}`);
  }
  validateOwnerAndMode(linkStat, filePath);
  if (linkStat.size <= 0 || linkStat.size > maxBytes) {
    throw new TandemError('file_size', `File has an invalid size: ${filePath}`);
  }

  let descriptor;
  try {
    const noFollow = typeof fs.constants.O_NOFOLLOW === 'number' ? fs.constants.O_NOFOLLOW : 0;
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
    const openedStat = fs.fstatSync(descriptor);
    if (!openedStat.isFile()
      || openedStat.dev !== linkStat.dev
      || openedStat.ino !== linkStat.ino) {
      throw new TandemError('path_changed', `File changed while it was being opened: ${filePath}`);
    }
    validateOwnerAndMode(openedStat, filePath);
    if (openedStat.size <= 0 || openedStat.size > maxBytes) {
      throw new TandemError('file_size', `File has an invalid size: ${filePath}`);
    }
    const buffer = fs.readFileSync(descriptor);
    if (buffer.length === 0 || buffer.length > maxBytes) {
      throw new TandemError('file_size', `File changed to an invalid size while being read: ${filePath}`);
    }
    return buffer;
  } catch (error) {
    if (error?.code === 'ELOOP') {
      throw new TandemError('path_unsafe', `Refusing to follow a symbolic link: ${filePath}`);
    }
    throw error;
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch (_) {}
    }
  }
}

function readSecureJson(filePath, options) {
  const buffer = readSecureFile(filePath, options);
  try {
    const document = JSON.parse(buffer.toString('utf8'));
    if (!document || typeof document !== 'object' || Array.isArray(document)) throw new Error('shape');
    return { buffer, document };
  } catch (_) {
    throw new TandemError('metadata_invalid', `Metadata is not valid JSON: ${filePath}`);
  }
}

function readSecureAuth(filePath) {
  let buffer;
  try {
    buffer = readSecureFile(filePath, { missingCode: 'auth_missing', maxBytes: MAX_AUTH_BYTES });
  } catch (error) {
    if (error?.code === 'file_permissions') {
      throw new TandemError('auth_permissions', `Credential permissions must be 0600: ${filePath}`);
    }
    throw error;
  }
  validateAuthDocument(buffer);
  return buffer;
}

function processIsAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === 'EPERM';
  }
}

class OperationLock {
  constructor(rootDir) {
    this.rootDir = rootDir;
    this.lockPath = path.join(rootDir, 'operation.lock');
    this.ownerPath = path.join(this.lockPath, 'owner.json');
  }

  reapStaleLock() {
    let lockStat;
    try {
      lockStat = fs.lstatSync(this.lockPath);
    } catch (error) {
      return error?.code === 'ENOENT';
    }
    if (!lockStat.isDirectory() || lockStat.isSymbolicLink()) {
      throw new TandemError('lock_unsafe', `Operation lock path is unsafe: ${this.lockPath}`);
    }
    validateOwnerAndMode(lockStat, this.lockPath, true);

    let owner;
    try {
      owner = readSecureJson(this.ownerPath).document;
    } catch (error) {
      if (Date.now() - lockStat.mtimeMs < INCOMPLETE_LOCK_GRACE_MS) return false;
      owner = null;
    }
    if (owner?.hostname && owner.hostname !== os.hostname()) return false;
    if (owner && processIsAlive(Number(owner.pid))) return false;

    const tombstone = `${this.lockPath}.stale.${process.pid}.${crypto.randomUUID()}`;
    try {
      fs.renameSync(this.lockPath, tombstone);
    } catch (error) {
      return error?.code === 'ENOENT' ? true : false;
    }
    fs.rmSync(tombstone, { recursive: true, force: true });
    fsyncDirectory(this.rootDir);
    return true;
  }

  acquire() {
    ensurePrivateDirectory(this.rootDir);
    const token = crypto.randomUUID();
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        fs.mkdirSync(this.lockPath, { mode: 0o700 });
        writeAtomic(this.ownerPath, Buffer.from(`${JSON.stringify({
          pid: process.pid,
          hostname: os.hostname(),
          token,
          created_at: new Date().toISOString()
        }, null, 2)}\n`));
        fsyncDirectory(this.rootDir);
        return () => this.release(token);
      } catch (error) {
        if (error?.code !== 'EEXIST') {
          try { fs.rmSync(this.lockPath, { recursive: true, force: true }); } catch (_) {}
          throw error;
        }
        if (!this.reapStaleLock()) {
          throw new TandemError('operation_locked', 'Another Codex Tandem operation is already running.');
        }
      }
    }
    throw new TandemError('operation_locked', 'Another Codex Tandem operation is already running.');
  }

  release(token) {
    let owner;
    try {
      owner = readSecureJson(this.ownerPath).document;
    } catch (_) {
      throw new TandemError('lock_lost', 'Operation lock ownership could not be verified.');
    }
    if (owner.token !== token || Number(owner.pid) !== process.pid) {
      throw new TandemError('lock_lost', 'Operation lock is no longer owned by this process.');
    }
    fs.rmSync(this.lockPath, { recursive: true, force: false });
    fsyncDirectory(this.rootDir);
  }
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
    if (typeof profiles.recover === 'function') await profiles.recover();
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
  constructor({ rootDir, codexHome, validateLogin, faultInjector }) {
    this.rootDir = path.resolve(rootDir);
    this.codexHome = path.resolve(codexHome);
    this.liveAuthPath = path.join(this.codexHome, 'auth.json');
    this.currentPath = path.join(this.rootDir, 'current.json');
    this.journalPath = path.join(this.rootDir, 'switching.json');
    this.validateLogin = typeof validateLogin === 'function' ? validateLogin : async () => {};
    this.faultInjector = typeof faultInjector === 'function' ? faultInjector : () => {};
    ensurePrivateDirectory(this.rootDir);
    ensurePrivateDirectory(this.codexHome);
    this.operationLock = new OperationLock(this.rootDir);
  }

  profileAuthPath(profile) {
    return path.join(this.rootDir, profileDirectoryName(profile), 'auth.json');
  }

  readCurrentState() {
    try {
      const document = readSecureJson(this.currentPath, { missingCode: 'current_missing' }).document;
      return {
        current: normalizeProfileName(document.current),
        transactionId: typeof document.transaction_id === 'string' ? document.transaction_id : null
      };
    } catch (error) {
      if (error?.code === 'current_missing') return null;
      throw error;
    }
  }

  readCurrent() {
    return this.readCurrentState()?.current || null;
  }

  writeCurrent(profile, transactionId = crypto.randomUUID()) {
    const current = normalizeProfileName(profile);
    writeAtomic(this.currentPath, Buffer.from(`${JSON.stringify({
      current,
      transaction_id: transactionId,
      updated_at: new Date().toISOString()
    }, null, 2)}\n`));
    return transactionId;
  }

  async withOperationLock(callback) {
    const release = this.operationLock.acquire();
    let callbackError;
    try {
      return await callback();
    } catch (error) {
      callbackError = error;
      throw error;
    } finally {
      try {
        release();
      } catch (releaseError) {
        if (!callbackError) throw releaseError;
      }
    }
  }

  async recover() {
    return this.withOperationLock(() => this.recoverInterruptedSwitchUnlocked());
  }

  async importLiveAs(profile) {
    return this.withOperationLock(() => {
      this.recoverInterruptedSwitchUnlocked();
      const target = normalizeProfileName(profile);
      const liveAuth = readSecureAuth(this.liveAuthPath);
      writeAtomic(this.profileAuthPath(target), liveAuth);
      this.writeCurrent(target);
      return target;
    });
  }

  async storeProfile(profile, authBuffer) {
    return this.withOperationLock(() => {
      this.recoverInterruptedSwitchUnlocked();
      const target = normalizeProfileName(profile);
      validateAuthDocument(authBuffer);
      writeAtomic(this.profileAuthPath(target), authBuffer);
      return target;
    });
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

  recoverInterruptedSwitchUnlocked() {
    let journal;
    try {
      journal = readSecureJson(this.journalPath, { missingCode: 'journal_missing' }).document;
      journal.from = normalizeProfileName(journal.from);
      journal.to = normalizeProfileName(journal.to);
    } catch (error) {
      if (error?.code === 'journal_missing') return false;
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
    } catch (error) {
      if (error?.code === 'auth_missing') return false;
      throw error;
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
    return this.withOperationLock(async () => {
      this.recoverInterruptedSwitchUnlocked();
      const target = normalizeProfileName(targetProfile);
      const previousState = this.readCurrentState();
      const previousProfile = previousState?.current;
      if (!previousProfile) {
        throw new TandemError('not_initialized', 'Run `codex-tandem init A` first.');
      }
      if (target === previousProfile) {
        await this.validateLogin();
        return { changed: false, from: previousProfile, to: target, rollback: async () => {} };
      }

      const previousAuth = readSecureAuth(this.liveAuthPath);
      const targetAuth = readSecureAuth(this.profileAuthPath(target));
      const previousMarker = readSecureFile(this.currentPath);
      const switchTransactionId = crypto.randomUUID();

      // Keep refresh-token changes made by Codex while this profile was active.
      writeAtomic(this.profileAuthPath(previousProfile), previousAuth);
      this.faultInjector('after_previous_profile_saved');
      this.writeSwitchJournal(previousProfile, target);
      this.faultInjector('after_journal');

      let liveWasReplaced = false;
      try {
        this.faultInjector('before_live_replace');
        writeAtomic(this.liveAuthPath, targetAuth);
        liveWasReplaced = true;
        this.faultInjector('after_live_replace');
        try {
          await this.validateLogin();
        } catch (validationError) {
          const failure = new TandemError('validation_failed', 'Target login validation failed.');
          failure.cause = validationError;
          throw failure;
        }
        this.faultInjector('after_validation');
        this.writeCurrent(target, switchTransactionId);
        this.faultInjector('after_current');
        this.clearSwitchJournal();
        this.faultInjector('after_journal_clear');
      } catch (error) {
        try {
          if (liveWasReplaced) writeAtomic(this.liveAuthPath, previousAuth);
          writeAtomic(this.currentPath, previousMarker);
          this.clearSwitchJournal();
        } catch (rollbackError) {
          const failure = new TandemError('rollback_failed', 'Switch failed and the original login could not be restored.');
          failure.cause = rollbackError;
          throw failure;
        }
        if (error instanceof TandemError) throw error;
        const failure = new TandemError('switch_failed', 'Switch failed; the original profile was restored.');
        failure.cause = error;
        throw failure;
      }

      let rolledBack = false;
      const rollback = async () => {
        if (rolledBack) return;
        await this.withOperationLock(() => {
          const activeState = this.readCurrentState();
          if (activeState?.current !== target || activeState.transactionId !== switchTransactionId) {
            throw new TandemError('rollback_conflict', 'A later switch occurred; refusing to overwrite it.');
          }
          try {
            writeAtomic(this.profileAuthPath(target), readSecureAuth(this.liveAuthPath));
          } catch (_) {}
          writeAtomic(this.liveAuthPath, previousAuth);
          writeAtomic(this.currentPath, previousMarker);
          rolledBack = true;
        });
      };
      return { changed: true, from: previousProfile, to: target, rollback };
    });
  }
}

module.exports = {
  CodexAccountProfiles,
  PROFILE_NAMES,
  OperationLock,
  TandemError,
  isAccountFailoverError,
  normalizeProfileName,
  readSecureAuth,
  runWithAccountFailover,
  validateAuthDocument,
  writeAtomic
};

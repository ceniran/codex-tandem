# Codex Tandem

**Two accounts. One Codex home. The same sessions continue.**

Codex Tandem switches only the active Codex CLI credential file. Your shared
`CODEX_HOME` stays in place, so sessions, history, configuration, MCP servers,
skills, and project context are not copied or reset.

It is intentionally small: exactly two profiles, A and B.

> This is an independent community project. It is not affiliated with or
> endorsed by OpenAI.

## Why

Some people have two legitimate Codex subscriptions and want to use either one
on the same Linux host. Moving the whole `.codex` directory splits history and
breaks continuity. Codex Tandem keeps one home and changes only `auth.json`
between turns.

## Requirements

- Linux or macOS
- Node.js 20+
- Codex CLI already installed
- Two accounts you are authorized to use

## Install

```bash
git clone https://github.com/ceniran/codex-tandem.git
cd codex-tandem
npm link
```

## Set up two accounts

First, log into Codex normally with the account you want to call **A**. Then:

```bash
codex-tandem init A
codex-tandem login B
codex-tandem status
```

`login B` uses an isolated temporary Codex home. It stores only the resulting
credential in `~/.codex-tandem`; it does not replace the active account.

Switch only when no Codex command is running:

```bash
codex-tandem switch B
codex-tandem switch A
```

Custom locations are supported:

```bash
CODEX_HOME=/srv/codex-home \
CODEX_TANDEM_HOME=/srv/codex-tandem \
codex-tandem status
```

## What “same session” means

Codex session files live under the shared `CODEX_HOME`. Tandem never moves
them, so after switching accounts you can use the same normal Codex resume
flow. Tandem does not fabricate, merge, or rewrite session IDs.

For a bot or service, queue the switch **between** Codex runs. The exported
`CodexAccountProfiles` class and `runWithAccountFailover` helper can be embedded
in a host process. Automatic failover is deliberately conservative: it reacts
only to explicit quota or authentication failures, switches once, and restores
the previous account if the retry fails.

## Safety model

- Credentials remain local and are never printed by `status`.
- Credential files and profile directories are forced to `0600` and `0700`.
- Replacement uses write + fsync + atomic rename.
- An interrupted switch is recovered from a small transaction journal.
- A target login is validated with `codex login status`; failure restores the
  original credential and active-profile marker.
- Refresh-token changes made by Codex are saved back before switching away.

Like Codex CLI itself, Tandem stores credentials as local files rather than
encrypting them. Protect the host account and never commit `auth.json`.

## 中文说明

Codex Tandem 是一个只支持 A/B 两个账号的轻量切换器。它只切换
`auth.json`，不会移动 `.codex` 中的 sessions、历史、配置、MCP 或 skills，
所以切换后仍可沿用原来的 Codex 会话。

第一次使用时，先用账号 A 正常登录 Codex，再运行：

```bash
codex-tandem init A
codex-tandem login B
codex-tandem switch B
```

请只使用你有权使用的账号，并在没有 Codex 任务运行时切换。

## Development

```bash
npm test
npm run check
```

## License

MIT

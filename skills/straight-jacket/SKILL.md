---
name: straight-jacket
description: Use when a repository contains Straight Jacket metadata (.straight-jacket/manifest.json) or the user mentions protected files. Straight Jacket marks files whose changes require human authorization; this skill covers required verification checks, the protected-file editing policy, and forbidden bypass actions.
---

# Straight Jacket

## Purpose

Use this skill when a repository contains Straight Jacket metadata or when the user mentions protected files. Straight Jacket marks files whose changes require human authorization.

## When To Use

- A repository contains `.straight-jacket/manifest.json`.
- A task may edit broad areas of a repository.
- A Straight Jacket verification command reports violations.

## Required First Checks

Run these before broad edits:

```sh
straight-jacket list --json
straight-jacket verify --json
```

If the CLI is unavailable, inspect `.straight-jacket/manifest.json` and tell the user verification could not be run.

## Protected-File Editing Policy

Avoid editing protected paths. If a protected file must change, make the content change only when the user explicitly asks for it, then ask the human to run the appropriate command locally:

```sh
straight-jacket update <path>
straight-jacket remove <path>
straight-jacket rename <old-path> <new-path>
```

## Verification Policy

Run `straight-jacket verify --json` before final response when Straight Jacket metadata exists and the CLI is available. Treat violations as blocking until the human authorizes or resolves them.

## Human Update Flow

Explain what changed and which human command is needed. Do not request secrets or signing authority in chat.

## Forbidden Actions

- edit .straight-jacket/manifest.json
- edit .straight-jacket/manifest.sig
- edit .straight-jacket/public-key.json
- ask user for password in chat
- commit with --no-verify to bypass checks
- delete hooks to bypass checks
- call or invent MCP mutation tools without host-mediated human confirmation

## Plugin Packaging Notes

Package the CLI, read-only MCP helpers, this skill, and hook/CI templates. The plugin must not include a daemon, secret forwarding, password capture, or private-key export path.

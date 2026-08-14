# Straight Jacket

A repo-native cli + gh action + pre-commit hook to lock files and make it impposible for AI agents to commit changes to them.

## How it works

Straight Jacket separates two kinds of authority. The master password encrypts the repository’s registration key, which is used to register trusted local signers. From that master password, Straight Jacket also derives a STRAIGHT_JACKET_CI_KEY value that you store as a GitHub Actions secret so CI can detect unauthorized metadata replacement.
Each checkout also has a local password. That local password encrypts the local signer private key in .straight-jacket/local/, and that signer is used when a human intentionally adds, updates, removes, or renames protected files.
Protected files are tracked in a signed JSON manifest. When you run straight-jacket add <file>, Straight Jacket records the file path, size, timestamp, and SHA-256 checksum of the file’s current contents. Later, straight-jacket verify hashes the current file contents and compares them to the signed checksum; if the file changed without being re-authorized, verification fails.
The metadata is also signed. The manifest must be signed by a registered local signer, and the signer registry must be signed by the registration key. In CI, straight-jacket verify --ci-key "$STRAIGHT_JACKET_CI_KEY" checks the committed CI proof, which ties the registration metadata back to the original master-derived CI key and catches replacement with metadata initialized under a different master password.

See [`PRODUCT_VISION.md`](./PRODUCT_VISION.md) for the full rationale.

## Install via npm

```sh
npm i --save-dev straight-jacket
```
optionally install globally with -g

## CLI quick guide
```
straight-jacket --help
straight-jacket setup --help

straight-jacket add <path | pattern>
straight-jacket add <path> <second path> ...
straight-jacket add <path> --reason "<optional description - can be helpful for AI agents"

straight-jacket update <path | pattern>
straight-jacket update <path> <second path> ...

straight-jacket remove <path | pattern>
```

## Setup

```
straight-jacket setup
```

It will prompt you for a master password (and to confirm)
- If this repo has multiple contributors, that will need to approve changes to protected files, make sure the master password is something you are okay with sharing.
- The master password allows this to be setup for a team / multiple devs, while still remaining repo based with no outside dependencies / servers (except github).

Next it will prompt you for a local password (and to confirm).
- This is your personal password.

### NOTE: Do not copy and paste either password into an AI chat and do not store either password anywhere an AI agent can read it.

Next it will generate a key that the github action will need.  
- This needs to be copied and saved for use in the next step.

### ! To ensure 100% locking that an agent can not get around you must do this next step.
## Setup branch protection and github action (Optional but reccomended)
locally run ```straight-jacket install-ci```

```
git add .straight-jacket
git add .github/workflows/straight-jacket.yml
```

commit and push to the branch you want to protect / or to temp / develop branch -> open pr to main (depending on your setup)
```
git commit -m"Adding github action for straight-jacket"
git push
```
This registers the action so you can add branch protection.

on github.com 

go to repo -> repo settings -> secrets and variables -> actions
  -   add the key you copied earlier with name "STRAIGHT_JACKET_CI_KEY"

go to repo -> repo settings -> branches -> add classic branch rule
  -  in the "Branch name pattern" box type the branch name / pattern you want to protect (main for example). 
  -  check: Require a pull request before merging (this prevents the agent using --no-verify to commit and push direct to protected branch)
  -  check: Require status checks to pass before merging
  -  in the "Search for status checks" box search for "verify" (the action registered earlier)
  -  Save

For more info see [`docs/features/github-protection.md`](./docs/features/github-protection.md).

## Install pre-commit hook (Optional but helpful for AI agents and humans to see a file is blocked before opening a PR)
```
straight-jacket install-hook
```

## Start protecting files.

Add a file to the protected list
```straight-jacket add <relative path to file>```

You can also add multiple at one time
``` straight-jacket add <file1> <file2> ```

Or you can use a pattern
``` straight-jacket add guardrails/*.ts```

## When a protected file is changed.

When you or your code AI changes a file, if the pre-commit hook is installed committing will be blocked with a message like
'CHECKSUM error...
 If you want to approve this change run
 straight-jacket update <file>
 '

 If the github action is installed and setup with branch protection it will run on and PR to the protected branch and fail if a protected file ws changed without being updated.

 ## Remove a protected file
 
 ``` straight-jacket remove <file>```

## Try it out

After setup is complete and pre-commit hook + github action (optional) is installed and configured.

Create a file in the project root.
``` touch test-straight-jacket.md```

Lock it.
```straight-jacket add test-straight-jacket.md --reason"Just a test file"```

Now open the file and change it.  Just add "Test" to it and save.

Now try committing
```
git add test-straight-jacket.md
git commit -m"just a test"
```

This should fail the pre-commit hook with an error telling you to update the lock if you approve the change.

If you setup the github action as well you can test that works
```
git commit -m"just a test" --no-verify
git push
```

That will bypass the pre-commit hoooks.
Next go to github.comn and open a PR from this branch to your protected branch.

Merge should be blocked by a failed status check.  Error message in the check will say what file was changed without approval



## Teams / Multiple developers / Multiple workstations 

Once the initial setup is done and pushed, you can let additional developers register a local password by sharing the master password with them.
- ensure they have pulled the branch / a branch that has the straight-jacket configured in
- if it was installed with --save-dev: ```npm i```
- or if installing globally: ```npm i -g straight-jacket```

then run
```
straight-jacket setup
```

If straight-jacket was already setup for this repo (which it should be if they are on the right branch and it is up to date)
This will 
- prompt them for the master password
- then to create their own local password.

That is all they need to do, then commit and push so their user is registered on the remote / for later.

## Install Claude Code plugin so claude has a better idea of what is blocking it.

The plugin ships:

- a read-only MCP server (`bin/straight-jacket-mcp.mjs`) exposing
  `list_protected_files`, `verify`, and `explain_violation`;
- the `straight-jacket` skill (protected-file editing policy + forbidden bypass actions);
- the `straight-jacket` CLI.

Plugin manifest: [`.claude-plugin/plugin.json`](./.claude-plugin/plugin.json).
Marketplace manifest: [`.claude-plugin/marketplace.json`](./.claude-plugin/marketplace.json).
Add this repo as a marketplace or a local plugin, e.g.:

```sh
/plugin marketplace add dcassil/straight-jacket
/plugin install straight-jacket@straight-jacket
```

Or reference it directly as a local plugin during development.

## Use with Codex

Codex reads MCP servers from `~/.codex/config.toml`. Merge the snippet in
[`codex/config.toml`](./codex/config.toml) after installing the CLI.

## Use with any MCP client

[`.mcp.json`](./.mcp.json) declares the server for generic MCP hosts:

```sh
straight-jacket-mcp
```

## To remove - uninstall

delete ./straight-jacket
delete straight-jacket entries in ./githooks/pre-commit
delete .github/workflows/straight-jacket.yml

remove github branch settings added during setup
remove github secret

## Development

```sh
npm test        # unit + contract + security + guardrails
npm run guardrails
```

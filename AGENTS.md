# Repository Agent Rules

- When an agent opens or updates a pull request in this repository, and the required GitHub CI checks pass, try to merge the PR to `main` before finishing the task.
- Every PR intended for `main` must bump the package/plugin version and changelog to the next publishable version. The required `verify` workflow blocks PRs whose package version is already published.
- Publishing is automatic on every push to `main`: the `Release` workflow validates, publishes the npm package, pushes the matching `vX.Y.Z` tag, and creates the GitHub release.
- Do not merge if the PR is a draft, has failing or pending required checks, has merge conflicts, contains unauthorized Straight Jacket violations, has unresolved requested changes, or the user explicitly asks not to merge it.
- Use the normal protected-branch merge path. Do not use admin bypasses, `--no-verify`, force pushes, hook deletion, or Straight Jacket metadata edits to make a PR mergeable.
- After merging, verify the local or remote `main` state when feasible and report the merged PR number and commit.

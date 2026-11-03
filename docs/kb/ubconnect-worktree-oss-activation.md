# UbConnect OSS activation fails: "Git config file not found" (suspected worktree leftover)

**Status:** Unconfirmed. Observed once on 2026-11-03, not reproduced. Verify if it recurs.

## Symptom

UbConnect could not verify that the project is open source, so its license did not
activate. It worked the day before, when the solution was started, and failed
"out of the box" the next day. The ubCode log showed:

```
2026-11-03 20:40:28.761 [info] [Info  - 8:40:28 PM] ubCode: OSS activation results for WS folder 'sbom-validation':
OssResult { success: false, error: None,
  repo_errors: {".claude\\worktrees\\sbom-validation": "Git config file not found"},
  repo_ok: [""] }
```

## What we found

- ubCode discovered two repositories under the workspace folder: the main repo
  (`repo_ok: [""]`, healthy) and a worktree at `.claude/worktrees/sbom-validation`
  (`repo_errors`, no git config found).
- By the time we looked, `.claude/worktrees/` no longer existed (`.claude/` was
  last modified 20:45, the log line is 20:40). `git worktree list` showed only the
  main checkout, `.git/worktrees` did not exist, and `git worktree prune -n` found
  nothing stale. `.git/config` was intact with `remote.origin.url` set.
- We changed nothing. The cause was never observed directly.

## Hypothesis (inferred, not verified)

A worktree's `.git` is a file pointing back to the main repo, not a real git
directory. Claude Code creates worktrees under `.claude/worktrees/` for isolated
sessions. When such a worktree was stale or half-removed inside the workspace
folder, ubCode's repo scan still picked it up and looked for a git config there.
ubCode appears to return `success: false` if any discovered repo errors, even when
another repo is in `repo_ok`. That last part is also unverified.

## How to verify if it recurs

1. Copy the `OSS activation results` log line, in particular `repo_errors`.
2. Check whether the path in `repo_errors` is a worktree: look for
   `.claude/worktrees/` and run `git worktree list`.
3. Check whether it appeared after a worktree was created plus an IDE restart or
   reinitialization.
4. If the path no longer exists, ubCode may be caching repo discovery. Reload the
   VS Code window or restart the language server first; clearing `.ub_cache/` is
   the next step (not yet tried).

## Possible solutions (decide when it recurs)

- If the issue only appears after a worktree is created plus an IDE restart, avoid
  worktrees in this project.
- Or create worktrees outside the repo, e.g.
  `C:\Users\Sucea\source\repos\sbom-validation-wt\`, so ubCode never scans them.
- Remove finished worktrees with `git worktree remove`.

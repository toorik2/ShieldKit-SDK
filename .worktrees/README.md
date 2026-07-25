# Local git worktrees (project-contained)

All worktrees for this repository **must** live under this directory:

```text
/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/.worktrees/<label>
```

Create:

```sh
git worktree add .worktrees/<label> <ref>
```

Forbidden locations (non-exhaustive):

- parent `ZK-Proofs/` (including `.codex-worktrees/`, sibling clone dirs)
- `~/.grok/worktrees/`
- `/tmp`, home root, or any path outside this repo

Remove:

```sh
git worktree remove .worktrees/<label>
```

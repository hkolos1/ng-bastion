---
title: Git and report comparison
description: Relate findings to changed code and compare the findings and coverage of two local scans.
---

## Git diff analysis

```sh
ngbastion scan apps/shop --diff origin/main --format html --output changes.html
```

The revision must already exist in the local repository. NgBastion scans the selected workspace with its normal cross-file context, then compares the working tree with that revision. The comparison includes staged changes, unstaged changes and untracked non-ignored files. Monorepo paths are relative to the scanned directory. A missing repository or revision produces exit 2.

| Association | Evidence |
|---|---|
| changed-line | The finding or a recorded trace location intersects added or modified current-side lines |
| changed-file | At least one recorded location belongs to a changed file outside those hunks |
| outside-diff | The recorded locations have no matching current-side change |

An unchanged sink may be associated with a changed source in another file. Deleted files have no current-side ranges. A rename without edited lines can therefore be a changed-file match. An unstaged move may appear as a deletion and an untracked addition. Submodule contents are excluded. Association depends on the path the engine recorded, and cannot establish when an issue was introduced. Use baseline comparison to classify findings across scans.

## Compare completed reports

```sh
ngbastion report compare previous.json current.json
ngbastion report compare previous.json current.json --format json --output comparison.json
```

Both inputs must be CLI-generated JSON reports containing compatible comparison snapshots. The command reads local files and runs no project builds. The result includes current statuses, comparable and uncertain disappearances, severity or confidence changes on matches, and changes to file or rule coverage. A successful comparison returns 0 even when it finds differences. Use the scan gate for a CI pass or fail decision.

Older reports without comparison snapshots cannot reconstruct the required identity or coverage. Generate fresh reports with the reporting CLI. Historical changes require at least two actual scans.

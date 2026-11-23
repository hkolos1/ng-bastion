# ngbastion

## 0.3.0

### Minor Changes

- 84ff6b2: Expose the reusable HTML document renderer and TypeScript literal check used by the website’s local snippet analysis.

### Patch Changes

- Updated dependencies [84ff6b2]
  - @ngbastion/rules@0.3.0
  - @ngbastion/config@0.3.0
  - @ngbastion/core@0.3.0
  - @ngbastion/plugin-api@0.3.0

## 0.2.0

### Minor Changes

- c4ccb57: Add versioned semantic finding fingerprints, local baseline comparison and status-aware security gates.
- 3eff32d: Add a self-contained offline HTML security report, observed rule evaluation counts, shareable source redaction and an interactive findings explorer.
- ee8728c: Classify finding and trace locations against a local Git revision and compare two saved JSON reports.

### Patch Changes

- Updated dependencies [c4ccb57]
- Updated dependencies [3eff32d]
- Updated dependencies [a5ecd42]
- Updated dependencies [2a03f59]
- Updated dependencies [7cb7329]
- Updated dependencies [0e2924a]
- Updated dependencies [ef02c2c]
- Updated dependencies [a59dcd4]
- Updated dependencies [cc13645]
- Updated dependencies [ce16391]
  - @ngbastion/core@0.2.0
  - @ngbastion/rules@0.2.0
  - @ngbastion/config@0.2.0
  - @ngbastion/plugin-api@0.2.0

## 0.1.2

### Patch Changes

- 9715e74: `ngbastion --version`, `--help` and the `tool.version` in terminal, JSON and SARIF reports now show the
  installed package version (also `ENGINE_VERSION` in `@ngbastion/core`). 0.1.1 still reported 0.1.0.
- Updated dependencies [9715e74]
  - @ngbastion/core@0.1.2
  - @ngbastion/config@0.1.2
  - @ngbastion/plugin-api@0.1.2
  - @ngbastion/rules@0.1.2

## 0.1.1

### Patch Changes

- b8ffb6f: Rule documentation, `--help` and SARIF/JSON report links now point to https://ngbastion.web.app
  (ngbastion.dev was never live).
- Updated dependencies [b8ffb6f]
  - @ngbastion/rules@0.1.1
  - @ngbastion/config@0.1.1
  - @ngbastion/core@0.1.1
  - @ngbastion/plugin-api@0.1.1

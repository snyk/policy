# AGENTS.md

Single source of truth for AI coding agents working on this project. Read this before making any changes.

`CLAUDE.md` intentionally delegates here — update this file, not the pointer.

`snyk-policy` is Snyk's policy parser and matching logic. It loads `.snyk` policy files, parses them
into a structured policy object, and filters vulnerability reports by `vuln.id` and path
(`vuln.from`) matching. Published to npm and consumed by the Snyk CLI and registry.

## Scope

These rules cover TypeScript under `lib/`, the ambient shims in `types/`, and the Vitest suite in
`test/`.

## Architecture

One exported operation per file. `lib/policy.ts` loads and saves policies and calls `attachMethods()`
to bind `filter`, `save`, `add`, `demunge` and friends onto the loaded policy object — the single
place the public policy API is wired. `lib/parser/index.ts` dispatches import and export through a
`parsers` lookup table keyed on the semver major, with `v1.ts` the only implementation.
`lib/filter/index.ts` orchestrates `ignore` → `patch` → `notes`. Every exported type lives in
`lib/types.ts`.

### Hard rules

Every item is a blocking gate — a PR that violates any of these must not merge.

- **Never commit `test.only`.** `npm test` runs `check-tests` first
  (`! grep 'test.only' test/**/*.test.ts -n`) and fails the build if one is present.
- **When fixing a bug, commit the failing test first as its own commit, then the fix in a following
  commit** — so the failure is demonstrable before and after. Never combine them.
- **Never open a PR for review while tests are failing.** PRs are not code reviewed until the suite
  is green.
- **Always add tests for new code**, mirroring the source directory and file structure.
- **Coverage must stay at or above 85%** for branches, functions, lines and statements — the
  thresholds are configured in `vite.config.js` and enforced by CI.
- **`loose: true` must never throw** when the policy cannot be read from disk.
- **Secondary policy `ignore` rules are suggestions, not rules.** When loading an array of policies,
  add a `note` property to the vulnerability rather than applying the ignore — unless
  `trust-policies: true` is set.
- **Patch rules must be verified against the on-disk Snyk patch file**, except when the policy sets
  `skipVerifyPatch: true` for filesystems where the packages are not accessible.
- **The module must stay forward-compatible across policy format versions** — callers never need to
  know which version they hold, and `save` writes the latest format, upgrading older ones.
- **`getByVuln` requires the vuln object to carry both `id` and `from`** to match correctly.
- **The `code` string on a thrown error is the consumer-facing contract.** Use `PolicyError(message,
  'CODE')` for policy-content failures, or attach `error.code` to a `NodeJS.ErrnoException`; callers
  switch on these.
  Reference: [`lib/types.ts`](lib/types.ts)
- **Adding a public export means touching two files** — the surface is re-exported from both
  `lib/index.ts` and `lib/policy.ts`.
- **Mark every mutating parameter `(*mutates!*)` in its JSDoc `@param`.** This is the repo-wide
  signal for in-place mutation and appears across `add.ts`, `add-exclude.ts`, `policy.ts` and all
  three filter modules.
  Reference: [`lib/add.ts`](lib/add.ts)
- **Commit messages must be Angular-style Conventional Commits without a scope**, with a header ≤ 72
  characters and a blank line before the body. Prefix the body with `BREAKING CHANGE: ` to release a
  major version.

### Conventions

- `export default fn;` is placed at the very top of the file, above the imports — an unusual
  convention that 7 of 9 `lib` files follow.
- Every subdirectory has an `index.ts` that both re-exports its siblings and holds the orchestrating
  function.
- Filter functions share a fixed signature shape: `(ruleSet, vulns, ...opts, filtered: T[] = [])`,
  where `filtered` is a documented mutating out-parameter.
- All interfaces, type aliases and unions live in `lib/types.ts`, documented with `@example` blocks
  showing the raw YAML or JSON shape. Only single-use local shapes stay local.
- Boolean helpers are `is*` / `has*` and typed as predicates rather than using casts.
- Files are lowercase kebab-case (16/16 in `lib`); functional tests are named after their Jira
  ticket (`BST-264.test.ts`).
- String concatenation with `+` is used in preference to template literals.

### Danger zone

**Several docs in this repo are stale and will mislead you.** `.github/CONTRIBUTING.md` tells you to
follow `.jshintrc` and `.jscsrc`, neither of which exists — the repo uses `.eslintrc` and
`.prettierrc.json` — and its commit-type list (which adds `style` and `perf`) contradicts
`.commitlintrc.json`, which enforces exactly `feat|fix|docs|chore|refactor|test|revert`. The README
still shows a Travis CI badge although CI is CircleCI, and documents `require('snyk-policy')`
although the package is `"type": "module"` with dual ESM/CJS exports. `.github/CODEOWNERS` references
`lib/add-exclude.js`, but the file is `.ts`, so that ownership rule never matches. ESLint runs only
over `lib/` — `test/` is not linted.

Treat these areas as high-risk: prefer the smallest possible change,
add tests before modifying, and ask a human reviewer before landing.

## Code conventions

### Style and formatting

ESLint 8 with `eslint:recommended`, `@typescript-eslint/recommended` and `eslint-config-prettier`;
only `no-console` and `no-empty` are enabled beyond the presets, both as warnings. Prettier 3 with
single quotes and always-parenthesised arrow params. `tsc --noEmit` runs as a third lint gate.
Formatting and linting are enforced by tooling — run `npm run format` / `npm run lint`
instead of reasoning about style; they are authoritative.

### Best practices for new code

Apply these principles when writing **new** code. Do not refactor existing code to comply unless explicitly asked.

When you touch a file that has existing violations:
1. Write your new code correctly.
2. Leave the surrounding violation untouched.
3. Emit: "⚠️ Legacy debt: [file:line] — [which principle], left alone to avoid scope creep."

- **Single Responsibility Principle (SRP)**
- **Avoid Hasty Abstractions (AHA)**

## Generated code

Never hand-edit these — they are auto-generated:

| Path | Generator | Regenerate with |
|------|-----------|-----------------|
| `dist` | Vite library build (ES + CJS) with `vite-plugin-dts` | `npm run build` |
| `coverage` | `@vitest/coverage-v8` | `npm test` |

## Testing

Vitest 1.6 with the v8 coverage provider. Tests are split into `test/unit/` and `test/functional/`,
with 59 fixture files under `test/fixtures/`; `vite.config.js` sets `dir: 'test'`, so a single
`vitest run` executes both suites. Coverage thresholds are 85% across the board and are enforced.

| Command | What it runs |
|---------|--------------|
| `npm test` | `check-tests` (the `test.only` guard) then `vitest run --coverage` |
| `npm run lint` | ESLint over `lib`, commitlint from `HEAD~20`, and `tsc --noEmit` |
| `npm run build` | Vite library build |

### AI agent testing protocol

**1. Test-first: fail before pass.**

Before writing implementation, write a test that exercises the new behavior. Run it — it **must
fail** first. A test that passes before the change is testing the wrong thing; discard it and write
another. Implement, then run again. This cycle counts as one attempt; you have **3 attempts** total.
If fail-then-pass cannot be achieved, stop and warn: "Warning: could not achieve
fail-before/pass-after for [test name] — [reason]."

If writing a test before implementation is genuinely not feasible (e.g., the change is in test
scaffolding itself), document the reason explicitly.

**2. Do not add tests for pre-existing untested code you touch.**

When modifying existing code that has no tests, report it: "Warning: [file/function] has no
existing test coverage. This change is unverified." Do **not** add tests for it — that is out of
scope and may introduce incorrect assumptions about existing behavior. Do write tests for any
**new** behavior you add, even if it lives in an existing file.

## Commits and PRs

**Commit format:** Angular-style Conventional Commits without a scope — `<type>: <subject>`
Allowed types: feat, fix, docs, chore, refactor, test, revert.
Subject line ≤ 72 characters.
Example: `fix: minified scripts being removed`
**PR description sections:** the readiness checklist (Ready for review / Follows CONTRIBUTING rules
/ Reviewed by Snyk internal team), What does this PR do?, Where should the reviewer start?, How
should this be manually tested?, Any background context you want to provide?, What are the relevant
tickets?, Screenshots, Additional questions.

Remember this library runs across multiple platforms and Node versions — a local pass on your
machine does not guarantee a pass elsewhere.

## Before you finish

Before presenting any change, verify each item below. Do not report work as complete until every applicable item passes.

- [ ] `npm test` passes, including the 85% coverage thresholds
- [ ] `npm run lint` passes (ESLint, commitlint, `tsc --noEmit`)
- [ ] `npm run build` succeeds
- [ ] No `test.only` committed
- [ ] A bug fix is split into a failing-test commit followed by a fix commit
- [ ] New public exports added to both `lib/index.ts` and `lib/policy.ts`
- [ ] Commit message is Angular-style with a header ≤ 72 characters

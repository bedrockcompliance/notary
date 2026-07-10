# Releasing @bedrockgovernance/notary

## Pre-flight

- [ ] CI green on `main` for `notary-ts.yml`.
- [ ] Fixtures up to date (`pnpm --filter @bedrockgovernance/notary gen:fixtures` produces no diff).
- [ ] `CHANGELOG.md` updated.
- [ ] If the canonical-form bytes changed, the version bump is **major**.

## One-time setup

1. Create the npm scope `@bedrockgovernance` (via `npm org create bedrockgovernance` or the web UI).
2. Add a repository secret `NPM_TOKEN` — an automation token scoped to `@bedrockgovernance`, 2FA auth-only.

## Cutting a release

1. Bump `version` in `packages/notary/package.json`.
2. Move `## [Unreleased]` notes in `CHANGELOG.md` to a dated heading.
3. Commit and merge to `main`.
4. Trigger the **Notary (Publish)** workflow from the Actions tab.
5. Verify on <https://www.npmjs.com/package/@bedrockgovernance/notary>.

## Yanking

```sh
npm deprecate @bedrockgovernance/notary@<version> "see SECURITY-ADVISORY-..."
```

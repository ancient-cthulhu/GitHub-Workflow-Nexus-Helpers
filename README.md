# Bulk Nexus credential injection Workflow App

Adds private-registry (Sonatype Nexus) authentication to the Veracode GitHub
Workflow Integration across many GitHub organizations, so that Veracode static
packaging and SCA scans can resolve dependencies from Nexus instead of failing
on 401s or falling back to public registries.

There are two layers:

1. **Per-runner credential helper** (`nexus-auth.sh` / `nexus-auth.ps1`)
   
   Runs inside the integration's build and SCA jobs, just before dependencies
   are resolved. It detects which package managers a repo uses and writes the
   right auth config for each (Maven, Gradle, npm/Yarn, pip, Go, Composer,
   Ruby), sourcing credentials from three GitHub secrets.

2. **Per-repo wiring + fleet rollout** (`veracode-nexus-rollout.py`)
   
   Edits each org's `veracode` integration repo through the GitHub Contents
   API, drops the two helper scripts in, inserts the steps that invoke them,
   and plumbs the three `VERACODE_NEXUS_*` secrets through the reusable-workflow
   chain. Optionally sets those org secrets. Built for hundreds of orgs: shared
   rate limiter, retries, parallel workers, checkpoint/resume, dry-run by
   default, and CSV reporting.

---

## Files

| File | Purpose |
|------|---------|
| `veracode-nexus-rollout.py` | Standalone fleet runner (discovery, injection, optional secrets, reporting). |
| `nexus-auth.sh` | Linux credential helper, run inside the packager container and the SCA runner. |
| `nexus-auth.ps1` | Windows credential helper (pwsh 7). |

Put all three in one folder. The helpers may sit flat beside the script or in a
`./helper/` subfolder; the script finds them either way.

---

## What gets changed in each `veracode` repo

Exactly 7 files, all idempotent:

- `helper/nexus-auth.sh`, `helper/nexus-auth.ps1` (added)
- `.github/workflows/veracode-default-build.yml` (credential step before
  packaging on Linux and Windows; declares the three secrets)
- `.github/workflows/veracode-sca-scan.yml` (credential step before dependency
  resolution, Linux and Windows)
- `.github/workflows/veracode-build-artifact-for-scanning.yml` (declares and
  passes the secrets to the build)
- `.github/workflows/veracode-code-analysis.yml`,
  `veracode-sandbox-scan.yml` (pass the secrets into the build chain)

The secrets are wired explicitly (`on.workflow_call.secrets` with
`required: false`, plus a `secrets:` mapping at each `uses:` hop), not with
`secrets: inherit`, so only the three Nexus secrets cross each boundary.
Because they are `required: false`, the workflows are safe to deploy to orgs
that do not use Nexus.

---

## Prerequisites

- Python 3.10+ with `requests` and `pyyaml`. `pynacl` only for
  `--set-nexus-secrets`.
- A GitHub token (`GITHUB_TOKEN` by default) with:
  - contents write on every target org's `veracode` repo,
  - `admin:org` if you will set secrets,
  - `read:enterprise` for `--enterprise` discovery, or `read:org` for
    `/user/orgs` discovery.
- The three Nexus secret values (only if setting secrets): a Nexus base URL, a
  username, and a password or, preferably, a **read-only** Nexus token.

---

## Quick start

```bash
# 1. Audit the whole fleet. Writes nothing. Produces out/orgs.txt and reports.
GITHUB_TOKEN=*** python3 veracode-nexus-rollout.py --enterprise ACME --workers 5

# 2. Canary: apply to a small subset first (prompts for confirmation).
GITHUB_TOKEN=*** python3 veracode-nexus-rollout.py --orgs-file canary.txt --apply --workers 3

# 3. Full rollout, optionally setting the secrets in the same pass.
NEXUS_BASE_URL=https://nexus.acme.com NEXUS_USER=ci NEXUS_PASS=*** \
GITHUB_TOKEN=*** python3 veracode-nexus-rollout.py \
    --orgs-file out/orgs.txt --apply --set-nexus-secrets --workers 5

# Resume after an interruption (completed orgs are skipped).
GITHUB_TOKEN=*** python3 veracode-nexus-rollout.py --orgs-file out/orgs.txt --apply --continue
```

Before the first apply, tune the repo-group names at the top of `nexus-auth.sh`
to match your Nexus (see Knobs below). That single step is what makes the first
live scan resolve cleanly.

---

## Command reference (`veracode-nexus-rollout.py`)

| Flag | Description |
|------|-------------|
| `--dry-run` | Audit only, no writes (default). |
| `--apply` | Apply changes. Prompts for confirmation. |
| `--set-nexus-secrets` | Also set the three org secrets from env values. Requires `pynacl`. |
| `--enterprise SLUG` | Discover orgs via the enterprise GraphQL API. |
| `--orgs-file FILE` | One org login per line (`#` comments and blanks ignored). |
| `--repo-name NAME` | Integration repo name (default `veracode`). |
| `--branch NAME` | Branch to edit (default `main`). |
| `--workers N` | Parallel worker threads (default 1; 3-5 recommended). |
| `--skip-to ORG` | Skip all orgs before this one. |
| `--continue` | Resume from `out/checkpoint.json`. |
| `--out DIR` | Output directory (default `out`). |
| `--api-base URL` | GitHub API base (default `https://api.github.com`; set for GHES). |
| `--token-env NAME` | Env var holding the token (default `GITHUB_TOKEN`). |

Secret values for `--set-nexus-secrets` are read from `NEXUS_BASE_URL`,
`NEXUS_USER`, `NEXUS_PASS` (or `VERACODE_NEXUS_*` as a fallback) and stored as
org secrets `VERACODE_NEXUS_BASE_URL`, `VERACODE_NEXUS_USER`,
`VERACODE_NEXUS_PASS` with visibility `all`.

---

## Outputs (in `--out`, default `out/`)

- `orgs.txt` — the resolved org list (reusable with `--orgs-file`).
- `nexus_report_<timestamp>.json` — full per-org detail for the run.
- `nexus_needs_attention.csv` — orgs with status `off_template`,
  `protected_branch`, `partial`, or `error`.
- `missing_veracode_repo.csv` — orgs without a usable `veracode` repo.
- `nexus_secrets.csv` — per-org secret-set results (only with
  `--set-nexus-secrets`).
- `checkpoint.json` — resume state.

### Per-org status values

| Status | Meaning |
|--------|---------|
| `injected` | Files written this run. |
| `already_current` | Nothing to do (idempotent). |
| `would_inject` | Dry-run: changes are pending. |
| `off_template` | A workflow or anchor was missing. **Nothing was written.** |
| `protected_branch` | A PR-required/protected `main` rejected a write. Stopped cleanly. |
| `partial` / `error` | A write failed mid-run; stopped before any unsafe state. |
| `skip_no_repo` | No `veracode` repo, or it is empty. |

---

## Safety and idempotency

- **Dry-run by default.** `--apply` is required to write, and prompts once.
- **Pre-flight.** All five workflows are transformed in memory first; if the
  repo is off-template the run writes nothing and leaves it byte-for-byte
  unchanged.
- **Idempotent.** Re-running is a no-op once applied. Safe to re-run anytime.
- **Validated.** Every workflow is parsed as YAML before it is written.
- **Safe write order.** Helpers first, then workflows in
  default-build to build-artifact to code-analysis to sandbox to sca order, so a
  callee always declares a secret before any caller passes it. A stop-on-failure
  never leaves a `secrets:` mapping pointing at an undeclared secret.
- **Per-org isolation.** One org failing never aborts the run.

---

## The credential helper (`nexus-auth.sh` / `nexus-auth.ps1`)

Invoked by the injected workflow steps as
`bash veracode-helper/helper/nexus-auth.sh <project-dir>` (and the pwsh
equivalent on Windows). It detects manifests and writes auth config only for
the ecosystems present, so single-language repos are unaffected.

### Required env (supplied by the workflow step from secrets)

`NEXUS_BASE_URL`, `NEXUS_USER`, `NEXUS_PASS`. If any is empty the helper exits
cleanly and does nothing, so the Workflow App keeps working even before the
secrets exist.

### Knobs (optional, with safe defaults)

| Variable | Default | Effect |
|----------|---------|--------|
| `NEXUS_MAVEN_REPO` | `<base>/repository/maven-public/` | Maven group URL. |
| `NEXUS_NPM_REPO` | `<base>/repository/npm-group/` | npm group URL. |
| `NEXUS_PYPI_REPO` | `<base>/repository/pypi-group/simple` | PyPI index. |
| `NEXUS_GO_REPO` | `<base>/repository/go-group/` | Go proxy. |
| `NEXUS_MAVEN_MIRROR_OF` | `*` | Maven mirror scope. Narrow it if Nexus does not proxy Central. |
| `NEXUS_MAVEN_INJECT_REPO` | `true` | Add an active profile repo so a pom listing no repos still hits Nexus. |
| `NEXUS_NPM_SCOPES` | (unset) | Comma list of scopes, e.g. `@acme,@corp`, mapped to Nexus. |
| `NEXUS_COMPOSER_REPO` | (unset) | If set, adds a global Composer repository. |
| `NEXUS_COMPOSER_DISABLE_PACKAGIST` | `false` | Route Composer entirely through Nexus. |
| `NEXUS_GO_PRIVATE` | (unset) | Sets `GOPRIVATE` if you need it. |
| `NEXUS_MAXDEPTH` | `4` | Manifest search depth (monorepo subprojects). |
| `NEXUS_DEBUG` | `false` | Verbose logging. |

Set these either by editing the defaults in `nexus-auth.sh` or by adding them to
the `env:` block of the injected steps.

### Per-ecosystem coverage

| Ecosystem | What is written |
|-----------|-----------------|
| Maven | `~/.m2/settings.xml` (server + mirror + optional active profile repo). |
| Gradle | `~/.gradle/init.d/nexus.init.gradle` (pluginManagement + dependencyResolutionManagement + allprojects + buildscript), honoring `GRADLE_USER_HOME`. |
| npm / Yarn / pnpm | project and user `.npmrc`; Yarn Berry via `YARN_NPM_*` env. |
| pip / pipenv / poetry | `pip.conf` + `PIP_*` / `PIPENV_PYPI_MIRROR` / `POETRY_HTTP_BASIC_*`, creds via `.netrc`. |
| Go | `GOPROXY` / `GOSUMDB`, creds via `.netrc`. |
| Composer | `COMPOSER_AUTH` env; optional global repo. |
| Ruby / Bundler | `BUNDLE_<host>` for every source host found in the Gemfile. |

Credentials are escaped for XML, JSON, and YAML. Secret-bearing values are
written to `$GITHUB_ENV` using the heredoc-delimiter form, which prevents a
secret from injecting additional environment variables. Each ecosystem runs in
isolation, so one failure does not block the others.

---

## Troubleshooting

- **`off_template`**: the repo drifted from the upstream template (renamed
  steps, moved call sites, or missing workflows). It was left untouched. Bring
  it back to template, then re-run.
- **`protected_branch`**: `main` requires PRs or status checks. Open a PR or add
  a policy exception, then re-run.
- **401s during a scan even after injection**: check the repo-group names match
  your Nexus (Knobs), confirm the three secrets exist, and run a scan with
  `debug: true` to read the helper's `+ <file>` lines.
- **Ruby auth not taking**: confirm the `BUNDLE_<host>` key the helper prints
  matches your Gemfile `source` host.
- **Secondary rate limits at high concurrency**: lower `--workers`; the limiter
  already paces writes and retries with backoff.

---

## Known limitations

- Injection plants files and plumbing only. Until the three `VERACODE_NEXUS_*`
  secrets exist, the helper no-ops. The Workflow App keeps working; Nexus auth
  is simply not live yet.
- The per-ecosystem auth covers most cases, not all. Site-specific Nexus layouts
  and unusual project configs may need a knob change. The knobs at the top of
  `nexus-auth.sh` are where you close that gap.
- `secrets: inherit` is deliberately not used; only the three Nexus secrets are
  passed.


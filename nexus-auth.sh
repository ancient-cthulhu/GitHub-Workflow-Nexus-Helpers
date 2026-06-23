#!/usr/bin/env bash
# inject Sonatype Nexus credentials for the ecosystems the
# Veracode autopackager / SCA agent resolves dependencies for, BEFORE the
# package / scan step runs.  Hardened for broad compatibility.
#
# Usage:  bash nexus-auth.sh <project_dir>      (default ".")
#
# Required env (from GitHub secrets in the calling step):
#   NEXUS_BASE_URL  e.g. https://nexus.example.com    NEXUS_USER    NEXUS_PASS
#
# Optional knobs (all have safe defaults):
#   NEXUS_MAVEN_REPO  NEXUS_NPM_REPO  NEXUS_PYPI_REPO  NEXUS_GO_REPO
#   NEXUS_MAVEN_MIRROR_OF      (default '*')       Maven mirror scope
#   NEXUS_MAVEN_INJECT_REPO    (default 'true')    add an active profile repo so a pom
#                                                  that lists no repos still hits Nexus
#   NEXUS_NPM_SCOPES           (comma list, e.g. '@acme,@corp')  scope->Nexus mappings
#   NEXUS_COMPOSER_REPO        (composer-type URL) add a global composer repo
#   NEXUS_COMPOSER_DISABLE_PACKAGIST (default 'false')
#   NEXUS_GO_PRIVATE           (GOPRIVATE glob; default unset = route all via proxy)
#   NEXUS_SBT_REPO             (default: NEXUS_MAVEN_REPO)  SBT/Coursier resolver URL;
#                                                  defaults to the Maven proxy since Nexus
#                                                  proxies Central through it
#   NEXUS_MAXDEPTH             (default 4)         manifest search depth
#   NEXUS_DEBUG               (default 'false')

set -uo pipefail   # NOT -e: each ecosystem runs in a guarded subshell so one
                   # failure cannot block the others.

PROJECT_DIR="${1:-.}"

NEXUS_REQUIRE="${NEXUS_REQUIRE:-false}"
if [[ -z "${NEXUS_USER:-}" || -z "${NEXUS_PASS:-}" || -z "${NEXUS_BASE_URL:-}" ]]; then
  if [[ "$NEXUS_REQUIRE" == "true" ]]; then
    echo "::error::nexus-auth: NEXUS_BASE_URL/USER/PASS expected but empty. If this step was injected, the reusable-workflow secret pass-through is misconfigured (secrets not declared or not passed). Failing closed."
    exit 1
  fi
  echo "Nexus credentials not set, skipping Nexus credential injection"; exit 0
fi
if [[ -z "${HOME:-}" || ! -d "$HOME" ]]; then
  echo "::error::\$HOME is not set or not a directory ('$HOME')"; exit 1
fi
case "$NEXUS_USER$NEXUS_PASS" in
  *$'\n'*) echo "::warning::nexus-auth: NEXUS_USER/NEXUS_PASS contains a newline; .netrc-based auth (pip/Go) may not work. Use a single-line token." ;;
esac

# ---- knobs / defaults ----
NEXUS_MAVEN_REPO="${NEXUS_MAVEN_REPO:-${NEXUS_BASE_URL}/repository/maven-public/}"
NEXUS_NPM_REPO="${NEXUS_NPM_REPO:-${NEXUS_BASE_URL}/repository/npm-group/}"
NEXUS_PYPI_REPO="${NEXUS_PYPI_REPO:-${NEXUS_BASE_URL}/repository/pypi-group/simple}"
NEXUS_GO_REPO="${NEXUS_GO_REPO:-${NEXUS_BASE_URL}/repository/go-group/}"
NEXUS_MAVEN_MIRROR_OF="${NEXUS_MAVEN_MIRROR_OF:-*}"
NEXUS_MAVEN_INJECT_REPO="${NEXUS_MAVEN_INJECT_REPO:-true}"
NEXUS_COMPOSER_DISABLE_PACKAGIST="${NEXUS_COMPOSER_DISABLE_PACKAGIST:-false}"
NEXUS_SBT_REPO="${NEXUS_SBT_REPO:-${NEXUS_MAVEN_REPO}}"
NEXUS_PIP_TRUSTED_HOST="${NEXUS_PIP_TRUSTED_HOST:-false}"   # opt-in; off keeps TLS verification on
NEXUS_GO_SUMDB_OFF="${NEXUS_GO_SUMDB_OFF:-false}"           # opt-in; off keeps checksum-db verification
NEXUS_MAXDEPTH="${NEXUS_MAXDEPTH:-4}"
NEXUS_DEBUG="${NEXUS_DEBUG:-false}"
GH_ENV="${GITHUB_ENV:-/dev/null}"

# ---- derived ----
HOST="$(printf '%s' "$NEXUS_BASE_URL" | sed -E 's#^https?://##; s#/.*$##')"
HOST_NOPORT="${HOST%%:*}"
NPM_NOSCHEME="$(printf '%s' "$NEXUS_NPM_REPO" | sed -E 's#^https?://##')"

b64() { # portable base64, no wrapping
  if base64 --help 2>&1 | grep -q -- '-w'; then base64 -w0; else base64 | tr -d '\n'; fi
}
NPM_AUTH="$(printf '%s:%s' "$NEXUS_USER" "$NEXUS_PASS" | b64)"
# base64(user:pass) is a transformed secret; GitHub masks only the raw values, so
# register the derived blob explicitly to keep it out of logs.
echo "::add-mask::$NPM_AUTH"

xml_esc() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&apos;/g"; }
json_esc() { printf '%s' "$1" | awk 'BEGIN{ORS=""} {gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); gsub(/\t/,"\\t"); gsub(/\r/,"\\r"); if(NR>1) printf "\\n"; printf "%s",$0}'; }
USER_X="$(xml_esc "$NEXUS_USER")"; PASS_X="$(xml_esc "$NEXUS_PASS")"
USER_J="$(json_esc "$NEXUS_USER")"; PASS_J="$(json_esc "$NEXUS_PASS")"

dbg() { [[ "$NEXUS_DEBUG" == "true" ]] && echo "  [debug] $*" || true; }

# Safe GITHUB_ENV writer: heredoc-delimiter form so a secret value (even with
# newlines or '=') cannot inject additional environment variables.
EOF_DELIM="NEXUSENV_$(date +%s)_${$}_EOF"
set_env() {
  local n="$1" v="$2"
  { printf '%s<<%s\n' "$n" "$EOF_DELIM"; printf '%s\n' "$v"; printf '%s\n' "$EOF_DELIM"; } >> "$GH_ENV"
}

# prune-aware detection (covers monorepo subprojects without descending into deps)
PRUNES=( -name node_modules -o -name vendor -o -name .git -o -name .gradle -o -name build -o -name dist -o -name target )
found() { # $@ = -name patterns (OR-ed)
  find "$PROJECT_DIR" -maxdepth "$NEXUS_MAXDEPTH" \( "${PRUNES[@]}" \) -prune -o -type f \( "$@" \) -print 2>/dev/null | head -n1
}
have() { [[ -n "$(found "$@")" ]]; }

have_maven()    { have -name pom.xml; }
have_gradle()   { have -name build.gradle -o -name build.gradle.kts -o -name settings.gradle -o -name settings.gradle.kts; }
have_sbt()      { have -name build.sbt; }
have_python()   { have -name 'requirements*.txt' -o -name pyproject.toml -o -name setup.py -o -name setup.cfg -o -name Pipfile; }
have_npm()      { have -name package.json; }
have_go()       { have -name go.mod; }
have_composer() { have -name composer.json; }
have_ruby()     { have -name Gemfile; }

run() { # run an ecosystem fn in a subshell; warn (don't abort) on failure
  local name="$1"; shift
  if ( set -e; "$@" ); then :; else echo "::warning::nexus-auth: '$name' configuration failed (continuing)"; fi
}

echo "::group::Nexus credential injection (host: $HOST, project: $PROJECT_DIR)"

# ---------------- .netrc (pip + Go host auth) ----------------
cfg_netrc() {
  umask 077
  # de-dupe: drop any prior block for this host, then append
  [[ -f "$HOME/.netrc" ]] && sed -i.bak "/^machine ${HOST_NOPORT}\$/,+2d" "$HOME/.netrc" 2>/dev/null || true
  printf 'machine %s\n  login %s\n  password %s\n' "$HOST_NOPORT" "$NEXUS_USER" "$NEXUS_PASS" >> "$HOME/.netrc"
  rm -f "$HOME/.netrc.bak" 2>/dev/null || true
  echo "  + ~/.netrc"
}

# ---------------- Maven ----------------
cfg_maven() {
  mkdir -p "$HOME/.m2"
  local profile=""
  if [[ "$NEXUS_MAVEN_INJECT_REPO" == "true" ]]; then
    profile="$(cat <<EOF
  <profiles>
    <profile>
      <id>nexus</id>
      <activation><activeByDefault>true</activeByDefault></activation>
      <repositories>
        <repository>
          <id>nexus</id><url>${NEXUS_MAVEN_REPO}</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </repository>
      </repositories>
      <pluginRepositories>
        <pluginRepository>
          <id>nexus</id><url>${NEXUS_MAVEN_REPO}</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </pluginRepository>
      </pluginRepositories>
    </profile>
  </profiles>
EOF
)"
  fi
  cat > "$HOME/.m2/settings.xml" <<EOF
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <servers>
    <server><id>nexus</id><username>${USER_X}</username><password>${PASS_X}</password></server>
  </servers>
  <mirrors>
    <mirror><id>nexus</id><name>Nexus</name><url>${NEXUS_MAVEN_REPO}</url><mirrorOf>${NEXUS_MAVEN_MIRROR_OF}</mirrorOf></mirror>
  </mirrors>
${profile}
</settings>
EOF
  echo "  + ~/.m2/settings.xml (mirrorOf=${NEXUS_MAVEN_MIRROR_OF}, inject_repo=${NEXUS_MAVEN_INJECT_REPO})"
}

# ---------------- Gradle ----------------
cfg_gradle() {
  # creds come from env at build time (exported to GITHUB_ENV); not written to disk here
  local script
  script="$(cat <<'EOF'
def nexusUrl  = System.getenv("NEXUS_MAVEN_REPO_RESOLVED")
def nexusUser = System.getenv("NEXUS_USER")
def nexusPass = System.getenv("NEXUS_PASS")
def addRepo = { repos -> repos.maven { url nexusUrl; credentials { username nexusUser; password nexusPass } } }
gradle.settingsEvaluated { settings ->
  try { settings.pluginManagement { addRepo(repositories); repositories.gradlePluginPortal() } } catch (ignored) {}
  try { settings.dependencyResolutionManagement { addRepo(repositories) } } catch (ignored) {}
}
allprojects {
  try { addRepo(repositories) } catch (ignored) {}
  try { buildscript { addRepo(repositories) } } catch (ignored) {}
}
EOF
)"
  local dirs=( "${GRADLE_USER_HOME:-$HOME/.gradle}" )
  [[ "${GRADLE_USER_HOME:-}" && "$GRADLE_USER_HOME" != "$HOME/.gradle" ]] && dirs+=( "$HOME/.gradle" )
  local d
  for d in "${dirs[@]}"; do
    mkdir -p "$d/init.d"
    printf '%s\n' "$script" > "$d/init.d/nexus.init.gradle"
    echo "  + $d/init.d/nexus.init.gradle"
  done
  set_env NEXUS_MAVEN_REPO_RESOLVED "$NEXUS_MAVEN_REPO"
  set_env NEXUS_USER "$NEXUS_USER"
  set_env NEXUS_PASS "$NEXUS_PASS"
}

# ---------------- npm / Yarn / pnpm ----------------
cfg_npm() {
  # Registry routing (no secret) may live in the workspace; the credential must NOT,
  # or it leaks via build artifacts / an accidental commit.
  local reg="registry=${NEXUS_NPM_REPO}
always-auth=true
"
  if [[ -n "${NEXUS_NPM_SCOPES:-}" ]]; then
    local s
    IFS=',' read -ra _scopes <<< "$NEXUS_NPM_SCOPES"
    for s in "${_scopes[@]}"; do
      s="${s// /}"; [[ -z "$s" ]] && continue
      reg+="${s}:registry=${NEXUS_NPM_REPO}
"
    done
  fi
  local auth="//${NPM_NOSCHEME}:_auth=${NPM_AUTH}
//${NPM_NOSCHEME}:always-auth=true
"
  printf '%s%s' "$reg" "$auth" >> "$HOME/.npmrc"   # creds: user-level only
  printf '%s' "$reg" >> "$PROJECT_DIR/.npmrc"       # workspace: routing only, no creds
  echo "  + ~/.npmrc (with auth) and $PROJECT_DIR/.npmrc (routing only)"
  # Yarn Berry (>=2): env-driven. npmAuthIdent encoding differs by major version:
  #   yarn 2 expects base64(user:pass); yarn 3+ expects raw user:pass.
  if [[ -f "$PROJECT_DIR/.yarnrc.yml" ]] || [[ -d "$PROJECT_DIR/.yarn/releases" ]] || grep -qsE '"packageManager"\s*:\s*"yarn@[2-9]' "$PROJECT_DIR/package.json"; then
    local ymajor=""
    if [[ -f "$PROJECT_DIR/package.json" ]]; then
      ymajor="$(grep -oE '"yarn@[0-9]+' "$PROJECT_DIR/package.json" 2>/dev/null | grep -oE '[0-9]+' | head -n1)"
    fi
    if [[ -z "$ymajor" ]]; then
      local _rel; _rel="$(ls "$PROJECT_DIR"/.yarn/releases/yarn-*.cjs 2>/dev/null | head -n1)"
      [[ -n "$_rel" ]] && ymajor="$(basename "$_rel" | grep -oE 'yarn-[0-9]+' | grep -oE '[0-9]+')"
    fi
    local ident; if [[ "$ymajor" == "2" ]]; then ident="$NPM_AUTH"; else ident="${NEXUS_USER}:${NEXUS_PASS}"; fi
    echo "::add-mask::$ident"
    set_env YARN_NPM_REGISTRY_SERVER "$NEXUS_NPM_REPO"
    set_env YARN_NPM_ALWAYS_AUTH "true"
    set_env YARN_NPM_AUTH_IDENT "$ident"
    echo "  + Yarn Berry env (YARN_NPM_*, ident for yarn ${ymajor:-3+})"
  fi
}

# ---------------- pip / pipenv / poetry ----------------
cfg_pip() {
  local conf="[global]
index-url = ${NEXUS_PYPI_REPO}
"
  if [[ "$NEXUS_PIP_TRUSTED_HOST" == "true" ]]; then
    conf+="trusted-host = ${HOST}
"
  fi
  mkdir -p "$HOME/.config/pip" "$HOME/.pip"
  printf '%s' "$conf" > "$HOME/.config/pip/pip.conf"
  printf '%s' "$conf" > "$HOME/.pip/pip.conf"
  set_env PIP_INDEX_URL "$NEXUS_PYPI_REPO"
  [[ "$NEXUS_PIP_TRUSTED_HOST" == "true" ]] && set_env PIP_TRUSTED_HOST "$HOST"
  set_env PIPENV_PYPI_MIRROR "$NEXUS_PYPI_REPO"
  # poetry best-effort: assumes a source named 'nexus' in pyproject if poetry is used
  set_env POETRY_HTTP_BASIC_NEXUS_USERNAME "$NEXUS_USER"
  set_env POETRY_HTTP_BASIC_NEXUS_PASSWORD "$NEXUS_PASS"
  echo "  + pip.conf (x2) + PIP_/PIPENV_/POETRY_ env (creds via ~/.netrc; trusted-host=${NEXUS_PIP_TRUSTED_HOST})"
}

# ---------------- Go ----------------
cfg_go() {
  set_env GOPROXY "$NEXUS_GO_REPO"
  # Keep checksum-db verification ON by default (supply-chain integrity). Private
  # module paths bypass it via GOPRIVATE; only disable wholesale on explicit opt-in.
  [[ "$NEXUS_GO_SUMDB_OFF" == "true" ]] && set_env GOSUMDB "off"
  [[ -n "${NEXUS_GO_PRIVATE:-}" ]] && set_env GOPRIVATE "$NEXUS_GO_PRIVATE"
  echo "  + GOPROXY env (GOSUMDB off=${NEXUS_GO_SUMDB_OFF}; creds via ~/.netrc)"
}

# ---------------- Composer ----------------
cfg_composer() {
  set_env COMPOSER_AUTH "$(printf '{"http-basic":{"%s":{"username":"%s","password":"%s"}}}' "$HOST" "$USER_J" "$PASS_J")"
  echo "  + COMPOSER_AUTH env"
  if [[ -n "${NEXUS_COMPOSER_REPO:-}" ]]; then
    local pk=""; [[ "$NEXUS_COMPOSER_DISABLE_PACKAGIST" == "true" ]] && pk=', "packagist.org": false'
    local d
    for d in "$HOME/.composer" "$HOME/.config/composer"; do
      mkdir -p "$d"
      printf '{"repositories":{"nexus":{"type":"composer","url":"%s"}%s}}\n' "$NEXUS_COMPOSER_REPO" "$pk" > "$d/config.json"
    done
    echo "  + global composer repo (${NEXUS_COMPOSER_REPO}, disable_packagist=${NEXUS_COMPOSER_DISABLE_PACKAGIST})"
  fi
}

# ---------------- Ruby / Bundler ----------------
bundle_key() { printf '%s' "$1" | sed -E 's/-/___/g; s/\./__/g; s/:/__/g' | tr '[:lower:]' '[:upper:]'; }
cfg_ruby() {
  # Scope Nexus credentials to the Nexus host ONLY. Enumerating hosts from the
  # Gemfile would send these credentials to any source an attacker can add to the
  # Gemfile (a PR-controlled exfiltration path), so we deliberately do not do it.
  local secret="${NEXUS_USER}:${NEXUS_PASS}"
  echo "::add-mask::$secret"
  set_env "BUNDLE_$(bundle_key "$HOST")" "$secret"
  echo "  + BUNDLE_$(bundle_key "$HOST") env (Nexus host only)"
}

# ---------------- SBT / Coursier ----------------
cfg_sbt() {
  # SBT 1.x resolves via Coursier. Two things are needed:
  #   1. A credentials.sbt file in ~/.sbt/1.0/ so SBT can authenticate to Nexus
  #      when it sends resolver requests (used by the SBT launcher and plugin
  #      resolution as well as the build itself).
  #   2. COURSIER_REPOSITORIES exported to GITHUB_ENV so Coursier routes all
  #      artifact fetches through the Nexus Maven proxy instead of Maven Central.
  #      Setting it in GITHUB_ENV makes it available to subsequent steps (the
  #      actual sbt compile/package invoked by the Veracode packager).
  #
  # NEXUS_SBT_REPO defaults to NEXUS_MAVEN_REPO because a standard Nexus setup
  # proxies Maven Central through the maven-public group, which also satisfies
  # the Scala/SBT ecosystem. Override NEXUS_SBT_REPO if you have a separate
  # sbt-specific proxy group.

  mkdir -p "$HOME/.sbt/1.0"
  cat > "$HOME/.sbt/1.0/credentials.sbt" <<EOF
credentials += Credentials(
  "Sonatype Nexus Repository Manager",
  "${HOST_NOPORT}",
  "${NEXUS_USER}",
  "${NEXUS_PASS}"
)
EOF
  # Coursier respects COURSIER_REPOSITORIES as a pipe-separated list of resolvers.
  # Prepend our Nexus URL so it is tried first; keep the Central fallback in case
  # the proxy does not mirror everything (e.g. sbt plugins only on sbt-plugin-releases).
  local coursier_repos="${NEXUS_SBT_REPO}|central"
  set_env COURSIER_REPOSITORIES "$coursier_repos"
  # Also pass credentials via the Coursier env so it can authenticate the Nexus proxy.
  # Mask the combined "host user:pass" string — GitHub only auto-masks the raw secret
  # values; the derived form slips through unless explicitly registered.
  local coursier_creds="${HOST_NOPORT} ${NEXUS_USER}:${NEXUS_PASS}"
  echo "::add-mask::$coursier_creds"
  set_env COURSIER_CREDENTIALS "$coursier_creds"
  echo "  + ~/.sbt/1.0/credentials.sbt + COURSIER_REPOSITORIES + COURSIER_CREDENTIALS"
}

# ---------------- dispatch ----------------
( have_python || have_go ) && run netrc cfg_netrc
have_maven    && run maven    cfg_maven
have_gradle   && run gradle   cfg_gradle
have_sbt      && run sbt      cfg_sbt
have_npm      && run npm      cfg_npm
have_python   && run pip      cfg_pip
have_go       && run go       cfg_go
have_composer && run composer cfg_composer
have_ruby     && run ruby     cfg_ruby

echo "Nexus credential injection complete."
echo "::endgroup::"

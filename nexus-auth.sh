#!/usr/bin/env bash
# nexus-auth.sh  --  inject Sonatype Nexus credentials for the ecosystems the
# Veracode autopackager / SCA agent resolves dependencies for, BEFORE the
# package / scan step runs.  Hardened for broad compatibility.
#
# Usage:  bash nexus-auth.sh <project_dir>      (default ".")
#
# Required env (from GitHub secrets in the calling step):
#   NEXUS_BASE_URL  e.g. https://nexus.example.com    NEXUS_USER    NEXUS_PASS
#
# Optional knobs (all have safe defaults):
#   NEXUS_MAVEN_REPO  NEXUS_NPM_REPO  NEXUS_PYPI_REPO  NEXUS_GO_REPO  NEXUS_GEMS_REPO
#   NEXUS_MAVEN_MIRROR_OF      (default '*')       Maven mirror scope
#   NEXUS_MAVEN_INJECT_REPO    (default 'true')    add an active profile repo so a pom
#                                                  that lists no repos still hits Nexus
#   NEXUS_NPM_SCOPES           (comma list, e.g. '@acme,@corp')  scope->Nexus mappings
#   NEXUS_COMPOSER_REPO        (composer-type URL) add a global composer repo
#   NEXUS_COMPOSER_DISABLE_PACKAGIST (default 'false')
#   NEXUS_GO_PRIVATE           (GOPRIVATE glob; default unset = route all via proxy)
#   NEXUS_MAXDEPTH             (default 4)         manifest search depth
#   NEXUS_DEBUG               (default 'false')

set -uo pipefail   # NOT -e: each ecosystem runs in a guarded subshell so one
                   # failure cannot block the others.

PROJECT_DIR="${1:-.}"

if [[ -z "${NEXUS_USER:-}" || -z "${NEXUS_PASS:-}" ]]; then
  echo "NEXUS_USER / NEXUS_PASS not set, skipping Nexus credential injection"; exit 0
fi
if [[ -z "${NEXUS_BASE_URL:-}" ]]; then
  echo "::error::NEXUS_BASE_URL is required when NEXUS_USER/NEXUS_PASS are set"; exit 1
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
  local body="registry=${NEXUS_NPM_REPO}
//${NPM_NOSCHEME}:_auth=${NPM_AUTH}
//${NPM_NOSCHEME}:always-auth=true
always-auth=true
"
  # scope mappings
  if [[ -n "${NEXUS_NPM_SCOPES:-}" ]]; then
    local s
    IFS=',' read -ra _scopes <<< "$NEXUS_NPM_SCOPES"
    for s in "${_scopes[@]}"; do
      s="${s// /}"; [[ -z "$s" ]] && continue
      body+="${s}:registry=${NEXUS_NPM_REPO}
"
    done
  fi
  printf '%s' "$body" >> "$PROJECT_DIR/.npmrc"
  printf '%s' "$body" >> "$HOME/.npmrc"
  echo "  + $PROJECT_DIR/.npmrc and ~/.npmrc"
  # Yarn Berry (>=2): driven by env, robust against .yarnrc.yml differences
  if [[ -f "$PROJECT_DIR/.yarnrc.yml" ]] || [[ -d "$PROJECT_DIR/.yarn/releases" ]] || grep -qsE '"packageManager"\s*:\s*"yarn@[2-9]' "$PROJECT_DIR/package.json"; then
    set_env YARN_NPM_REGISTRY_SERVER "$NEXUS_NPM_REPO"
    set_env YARN_NPM_ALWAYS_AUTH "true"
    set_env YARN_NPM_AUTH_IDENT "$NPM_AUTH"
    echo "  + Yarn Berry env (YARN_NPM_*)"
  fi
}

# ---------------- pip / pipenv / poetry ----------------
cfg_pip() {
  local conf="[global]
index-url = ${NEXUS_PYPI_REPO}
trusted-host = ${HOST}
"
  mkdir -p "$HOME/.config/pip" "$HOME/.pip"
  printf '%s' "$conf" > "$HOME/.config/pip/pip.conf"
  printf '%s' "$conf" > "$HOME/.pip/pip.conf"
  set_env PIP_INDEX_URL "$NEXUS_PYPI_REPO"
  set_env PIP_TRUSTED_HOST "$HOST"
  set_env PIPENV_PYPI_MIRROR "$NEXUS_PYPI_REPO"
  # poetry best-effort: assumes a source named 'nexus' in pyproject if poetry is used
  set_env POETRY_HTTP_BASIC_NEXUS_USERNAME "$NEXUS_USER"
  set_env POETRY_HTTP_BASIC_NEXUS_PASSWORD "$NEXUS_PASS"
  echo "  + pip.conf (x2) + PIP_/PIPENV_/POETRY_ env (creds via ~/.netrc)"
}

# ---------------- Go ----------------
cfg_go() {
  set_env GOPROXY "$NEXUS_GO_REPO"
  set_env GOSUMDB "off"
  [[ -n "${NEXUS_GO_PRIVATE:-}" ]] && set_env GOPRIVATE "$NEXUS_GO_PRIVATE"
  echo "  + GOPROXY/GOSUMDB env (creds via ~/.netrc)"
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
  # auth the Nexus host plus every host referenced as a source in the Gemfile
  local hosts="$HOST"
  local gf; gf="$(found -name Gemfile | head -n1)"
  if [[ -n "$gf" ]]; then
    local extra
    extra="$(grep -hoE "https?://[^'\"[:space:]/]+" "$gf" 2>/dev/null | sed -E 's#^https?://##' | sort -u)"
    [[ -n "$extra" ]] && hosts="$hosts
$extra"
  fi
  local h seen=""
  while IFS= read -r h; do
    [[ -z "$h" ]] && continue
    case " $seen " in *" $h "*) continue;; esac
    seen="$seen $h"
    set_env "BUNDLE_$(bundle_key "$h")" "${NEXUS_USER}:${NEXUS_PASS}"
    echo "  + BUNDLE_$(bundle_key "$h") env"
  done <<< "$hosts"
}

# ---------------- dispatch ----------------
( have_python || have_go ) && run netrc cfg_netrc
have_maven    && run maven    cfg_maven
have_gradle   && run gradle   cfg_gradle
have_npm      && run npm      cfg_npm
have_python   && run pip      cfg_pip
have_go       && run go       cfg_go
have_composer && run composer cfg_composer
have_ruby     && run ruby     cfg_ruby

echo "Nexus credential injection complete."
echo "::endgroup::"

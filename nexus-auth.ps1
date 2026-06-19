<#
  Windows equivalent of nexus-auth.sh (hardened).
  Runs directly on the runner (no container); files land in $env:USERPROFILE,
  env vars go to $env:GITHUB_ENV for the later package step. Requires pwsh 7.

  Usage:  pwsh nexus-auth.ps1 <project_dir>     (default ".")
  Required env: NEXUS_BASE_URL, NEXUS_USER, NEXUS_PASS
  Optional knobs mirror nexus-auth.sh (NEXUS_MAVEN_REPO, NEXUS_MAVEN_MIRROR_OF,
  NEXUS_MAVEN_INJECT_REPO, NEXUS_NPM_REPO, NEXUS_NPM_SCOPES, NEXUS_PYPI_REPO,
  NEXUS_GO_REPO, NEXUS_GO_PRIVATE, NEXUS_COMPOSER_REPO,
  NEXUS_COMPOSER_DISABLE_PACKAGIST, NEXUS_MAXDEPTH).
#>
param([string]$ProjectDir = ".")
$ErrorActionPreference = "Stop"

$require = ($env:NEXUS_REQUIRE -eq 'true')
if (-not $env:NEXUS_USER -or -not $env:NEXUS_PASS -or -not $env:NEXUS_BASE_URL) {
  if ($require) {
    Write-Error "nexus-auth: NEXUS_BASE_URL/USER/PASS expected but empty. If this step was injected, the reusable-workflow secret pass-through is misconfigured. Failing closed."
    exit 1
  }
  Write-Host "Nexus credentials not set, skipping Nexus credential injection"; exit 0
}

$U = $env:NEXUS_USER; $P = $env:NEXUS_PASS; $base = $env:NEXUS_BASE_URL
$mvnRepo = if ($env:NEXUS_MAVEN_REPO) { $env:NEXUS_MAVEN_REPO } else { "$base/repository/maven-public/" }
$npmRepo = if ($env:NEXUS_NPM_REPO)   { $env:NEXUS_NPM_REPO }   else { "$base/repository/npm-group/" }
$pyRepo  = if ($env:NEXUS_PYPI_REPO)  { $env:NEXUS_PYPI_REPO }  else { "$base/repository/pypi-group/simple" }
$goRepo  = if ($env:NEXUS_GO_REPO)    { $env:NEXUS_GO_REPO }    else { "$base/repository/go-group/" }
$mirrorOf = if ($env:NEXUS_MAVEN_MIRROR_OF) { $env:NEXUS_MAVEN_MIRROR_OF } else { "*" }
$injectRepo = ($env:NEXUS_MAVEN_INJECT_REPO -ne "false")
$maxDepth = if ($env:NEXUS_MAXDEPTH) { [int]$env:NEXUS_MAXDEPTH } else { 4 }

$host_      = ($base -replace '^https?://','') -replace '/.*$',''
$hostNoPort = $host_ -replace ':.*$',''
$npmNoScheme = $npmRepo -replace '^https?://',''
$npmAuth = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$($U):$($P)"))
Write-Host "::add-mask::$npmAuth"
$home_ = $env:USERPROFILE
$prune = '\\(node_modules|vendor|\.git|\.gradle|build|dist|target)\\'

function Set-GhEnv([string]$name, [string]$value) {
  $d = "NEXUSENV_EOF_" + [guid]::NewGuid().ToString('N')
  "$name<<$d`n$value`n$d" | Out-File -FilePath $env:GITHUB_ENV -Append
}
function Test-Any([string[]]$patterns) {
  foreach ($pat in $patterns) {
    $hit = Get-ChildItem -Path $ProjectDir -Filter $pat -Recurse -Depth $maxDepth -File -ErrorAction SilentlyContinue |
           Where-Object { $_.FullName -notmatch $prune } | Select-Object -First 1
    if ($hit) { return $true }
  }
  return $false
}
function Invoke-Eco([string]$name, [scriptblock]$body) {
  try { & $body } catch { Write-Host "::warning::nexus-auth: '$name' configuration failed (continuing): $($_.Exception.Message)" }
}

$hasMaven    = Test-Any @('pom.xml')
$hasGradle   = Test-Any @('build.gradle','build.gradle.kts','settings.gradle','settings.gradle.kts')
$hasPython   = Test-Any @('requirements*.txt','pyproject.toml','setup.py','setup.cfg','Pipfile')
$hasNpm      = Test-Any @('package.json')
$hasGo       = Test-Any @('go.mod')
$hasComposer = Test-Any @('composer.json')
$hasRuby     = Test-Any @('Gemfile')

Write-Host "::group::Nexus credential injection (host: $host_, project: $ProjectDir)"

if (($hasPython -or $hasGo) -and ($U -match "`n" -or $P -match "`n")) {
  Write-Host "::warning::nexus-auth: NEXUS_USER/NEXUS_PASS contains a newline; _netrc auth may not work."
}

# .netrc
if ($hasPython -or $hasGo) {
  Invoke-Eco 'netrc' {
    $netrcPath = Join-Path $home_ "_netrc"
    if (Test-Path $netrcPath) {
      $kept = Get-Content $netrcPath | Where-Object { $_ -notmatch "^machine\s+$([regex]::Escape($hostNoPort))$" }
      Set-Content -Path $netrcPath -Value $kept -Encoding ascii
    }
    Add-Content -Path $netrcPath -Value "machine $hostNoPort`n  login $U`n  password $P" -Encoding ascii
    Write-Host "  + _netrc"
  }
}

# Maven
if ($hasMaven) {
  Invoke-Eco 'maven' {
    $m2 = Join-Path $home_ ".m2"; New-Item -ItemType Directory -Force -Path $m2 | Out-Null
    $uX = [System.Security.SecurityElement]::Escape($U)
    $pX = [System.Security.SecurityElement]::Escape($P)
    $mvnProfile = ""
    if ($injectRepo) {
      $mvnProfile = @"
  <profiles>
    <profile>
      <id>nexus</id>
      <activation><activeByDefault>true</activeByDefault></activation>
      <repositories><repository><id>nexus</id><url>$mvnRepo</url><releases><enabled>true</enabled></releases><snapshots><enabled>true</enabled></snapshots></repository></repositories>
      <pluginRepositories><pluginRepository><id>nexus</id><url>$mvnRepo</url><releases><enabled>true</enabled></releases><snapshots><enabled>true</enabled></snapshots></pluginRepository></pluginRepositories>
    </profile>
  </profiles>
"@
    }
    @"
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <servers><server><id>nexus</id><username>$uX</username><password>$pX</password></server></servers>
  <mirrors><mirror><id>nexus</id><name>Nexus</name><url>$mvnRepo</url><mirrorOf>$mirrorOf</mirrorOf></mirror></mirrors>
$mvnProfile
</settings>
"@ | Out-File -FilePath (Join-Path $m2 "settings.xml") -Encoding utf8
    Write-Host "  + .m2\settings.xml"
  }
}

# Gradle
if ($hasGradle) {
  Invoke-Eco 'gradle' {
    $script = @'
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
'@
    $guh = if ($env:GRADLE_USER_HOME) { $env:GRADLE_USER_HOME } else { Join-Path $home_ ".gradle" }
    $dirs = @($guh)
    $defaultGuh = Join-Path $home_ ".gradle"
    if ($guh -ne $defaultGuh) { $dirs += $defaultGuh }
    foreach ($d in $dirs) {
      $initd = Join-Path $d "init.d"; New-Item -ItemType Directory -Force -Path $initd | Out-Null
      $script | Out-File -FilePath (Join-Path $initd "nexus.init.gradle") -Encoding utf8
      Write-Host "  + $initd\nexus.init.gradle"
    }
    Set-GhEnv 'NEXUS_MAVEN_REPO_RESOLVED' $mvnRepo
    Set-GhEnv 'NEXUS_USER' $U
    Set-GhEnv 'NEXUS_PASS' $P
  }
}

# npm / Yarn / pnpm
if ($hasNpm) {
  Invoke-Eco 'npm' {
    $reg = "registry=$npmRepo`nalways-auth=true`n"
    if ($env:NEXUS_NPM_SCOPES) {
      foreach ($s in ($env:NEXUS_NPM_SCOPES -split ',')) {
        $s = $s.Trim(); if ($s) { $reg += "${s}:registry=$npmRepo`n" }
      }
    }
    $auth = "//${npmNoScheme}:_auth=$npmAuth`n//${npmNoScheme}:always-auth=true`n"
    # Credential goes to the user-level file only; the workspace file gets routing only.
    Add-Content -Path (Join-Path $home_ ".npmrc") -Value ($reg + $auth) -Encoding ascii
    Add-Content -Path (Join-Path $ProjectDir ".npmrc") -Value $reg -Encoding ascii
    Write-Host "  + ~/.npmrc (with auth) + project .npmrc (routing only)"
    $pj = Join-Path $ProjectDir "package.json"
    $berry = (Test-Path (Join-Path $ProjectDir ".yarnrc.yml")) -or (Test-Path (Join-Path $ProjectDir ".yarn\releases")) -or `
             ((Test-Path $pj) -and ((Get-Content $pj -Raw) -match '"packageManager"\s*:\s*"yarn@[2-9]'))
    if ($berry) {
      $ymajor = $null
      if ((Test-Path $pj) -and ((Get-Content $pj -Raw) -match '"packageManager"\s*:\s*"yarn@([0-9]+)')) { $ymajor = $Matches[1] }
      if (-not $ymajor) {
        $rel = Get-ChildItem -Path (Join-Path $ProjectDir ".yarn\releases") -Filter 'yarn-*.cjs' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($rel -and $rel.Name -match 'yarn-([0-9]+)') { $ymajor = $Matches[1] }
      }
      # yarn 2 expects base64(user:pass); yarn 3+ expects raw user:pass.
      $ident = if ($ymajor -eq '2') { $npmAuth } else { "$($U):$($P)" }
      Write-Host "::add-mask::$ident"
      Set-GhEnv 'YARN_NPM_REGISTRY_SERVER' $npmRepo
      Set-GhEnv 'YARN_NPM_ALWAYS_AUTH' 'true'
      Set-GhEnv 'YARN_NPM_AUTH_IDENT' $ident
      Write-Host "  + Yarn Berry env (ident for yarn $(if ($ymajor) { $ymajor } else { '3+' }))"
    }
  }
}

# pip / pipenv / poetry
if ($hasPython) {
  Invoke-Eco 'pip' {
    $trusted = ($env:NEXUS_PIP_TRUSTED_HOST -eq 'true')
    $conf = "[global]`nindex-url = $pyRepo`n"
    if ($trusted) { $conf += "trusted-host = $host_`n" }
    $pipDir = Join-Path $env:APPDATA "pip"; New-Item -ItemType Directory -Force -Path $pipDir | Out-Null
    $conf | Out-File -FilePath (Join-Path $pipDir "pip.ini") -Encoding ascii
    Set-GhEnv 'PIP_INDEX_URL' $pyRepo
    if ($trusted) { Set-GhEnv 'PIP_TRUSTED_HOST' $host_ }
    Set-GhEnv 'PIPENV_PYPI_MIRROR' $pyRepo
    Set-GhEnv 'POETRY_HTTP_BASIC_NEXUS_USERNAME' $U
    Set-GhEnv 'POETRY_HTTP_BASIC_NEXUS_PASSWORD' $P
    Write-Host "  + pip.ini + PIP_/PIPENV_/POETRY_ env (trusted-host=$trusted)"
  }
}

# Go
if ($hasGo) {
  Invoke-Eco 'go' {
    Set-GhEnv 'GOPROXY' $goRepo
    if ($env:NEXUS_GO_SUMDB_OFF -eq 'true') { Set-GhEnv 'GOSUMDB' 'off' }
    if ($env:NEXUS_GO_PRIVATE) { Set-GhEnv 'GOPRIVATE' $env:NEXUS_GO_PRIVATE }
    Write-Host "  + GOPROXY env (GOSUMDB off=$($env:NEXUS_GO_SUMDB_OFF -eq 'true'))"
  }
}

# Composer
if ($hasComposer) {
  Invoke-Eco 'composer' {
    $auth = @{ 'http-basic' = @{ $host_ = @{ username = $U; password = $P } } }
    Set-GhEnv 'COMPOSER_AUTH' ($auth | ConvertTo-Json -Compress -Depth 5)
    Write-Host "  + COMPOSER_AUTH env"
    if ($env:NEXUS_COMPOSER_REPO) {
      $repos = @{ repositories = @{ nexus = @{ type = 'composer'; url = $env:NEXUS_COMPOSER_REPO } } }
      if ($env:NEXUS_COMPOSER_DISABLE_PACKAGIST -eq 'true') { $repos.repositories['packagist.org'] = $false }
      foreach ($d in @((Join-Path $home_ '.composer'), (Join-Path (Join-Path $home_ '.config') 'composer'))) {
        New-Item -ItemType Directory -Force -Path $d | Out-Null
        ($repos | ConvertTo-Json -Compress -Depth 5) | Out-File -FilePath (Join-Path $d 'config.json') -Encoding utf8
      }
      Write-Host "  + global composer repo"
    }
  }
}

# Ruby / Bundler
if ($hasRuby) {
  Invoke-Eco 'ruby' {
    # Scope to the Nexus host ONLY. Do not enumerate Gemfile sources: that would
    # leak Nexus credentials to any host an attacker can add to the Gemfile.
    $key = ($host_ -replace '-','___' -replace '\.','__' -replace ':','__').ToUpper()
    $secret = "$($U):$($P)"
    Write-Host "::add-mask::$secret"
    Set-GhEnv "BUNDLE_$key" $secret
    Write-Host "  + BUNDLE_$key env (Nexus host only)"
  }
}

Write-Host "Nexus credential injection complete."
Write-Host "::endgroup::"

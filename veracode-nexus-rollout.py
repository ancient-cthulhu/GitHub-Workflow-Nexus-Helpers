#!/usr/bin/env python3
"""
Nexus credential injection into the Veracode GitHub Workflow
Integration repos. Modeled on the onboarding rollout helper: shared rate
limiter, retries, org discovery (enterprise / orgs-file / user orgs), parallel
workers, checkpoint/resume, JSON + CSV reporting, dry-run/apply with a
confirmation gate.

Per org, in the 'veracode' repo, via the GitHub Contents API:
  * adds  helper/nexus-auth.sh  and  helper/nexus-auth.ps1
  * inserts the credential-injection steps into the build and SCA workflows
  * declares + passes the three VERACODE_NEXUS_* secrets through the static
    build chain (explicit pass-through, not secrets: inherit)
Optionally (--set-nexus-secrets) sets the three org secrets from env values.

Safety:
  * DRY-RUN by default; --apply required to write. Apply prompts for confirmation.
  * Pre-flights every workflow in memory; off-template repos are SKIPPED, never
    half-patched.
  * Idempotent. Re-running is a no-op once applied.
  * Validates YAML before every PUT.
  * Writes in callee-declares-before-caller-passes order so a stop-on-failure
    never leaves a passed secret undeclared.

Requires: requests, pyyaml. pynacl only for --set-nexus-secrets.
Place helper/nexus-auth.sh and helper/nexus-auth.ps1 next to this script.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import threading
import time
from base64 import b64decode, b64encode
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

try:
    import yaml
except ImportError:
    yaml = None

INTEGRATION_REPO_NAME = "veracode"
API_VER = "2022-11-28"

# ---- workflow files & helpers ------------------------------------------------
WF_DEFAULT_BUILD  = ".github/workflows/veracode-default-build.yml"
WF_SCA            = ".github/workflows/veracode-sca-scan.yml"
WF_BUILD_ARTIFACT = ".github/workflows/veracode-build-artifact-for-scanning.yml"
WF_CODE_ANALYSIS  = ".github/workflows/veracode-code-analysis.yml"
WF_SANDBOX        = ".github/workflows/veracode-sandbox-scan.yml"
HELPER_SH         = "helper/nexus-auth.sh"
HELPER_PS1        = "helper/nexus-auth.ps1"

STEP_MARKER = "Configure Nexus credentials"
SECRET_NAMES = ("VERACODE_NEXUS_BASE_URL", "VERACODE_NEXUS_USER", "VERACODE_NEXUS_PASS")
_DECL_RE = re.compile(r"VERACODE_NEXUS_BASE_URL:\s*\n\s*required:")

# env vars holding the secret VALUES (only needed for --set-nexus-secrets)
_NEXUS_VALUE_ENV = {
    "VERACODE_NEXUS_BASE_URL": ("NEXUS_BASE_URL", "VERACODE_NEXUS_BASE_URL"),
    "VERACODE_NEXUS_USER":     ("NEXUS_USER", "VERACODE_NEXUS_USER"),
    "VERACODE_NEXUS_PASS":     ("NEXUS_PASS", "VERACODE_NEXUS_PASS"),
}

_print_lock = threading.Lock()


# =============================================================================
# Output
# =============================================================================

def tprint(*args: Any, **kwargs: Any) -> None:
    with _print_lock:
        print(*args, **kwargs)


def env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    return v if v not in (None, "") else default


def gh_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": API_VER,
        "User-Agent": "veracode-nexus-rollout",
    }


# =============================================================================
# Global rate limiter (primary + secondary GitHub limits)
# =============================================================================

_SAFE_FRACTION_HOURLY = 0.80
_SAFE_FRACTION_CONTENT_PER_MIN = 0.75
_SAFE_FRACTION_CONTENT_PER_HOUR = 0.80
_MAX_CONCURRENT_REQUESTS = 50
_CONTENT_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class _SlidingWindow:
    __slots__ = ("window", "_events", "_lock")

    def __init__(self, window_seconds: float) -> None:
        self.window = window_seconds
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def _prune_locked(self, cutoff: float) -> None:
        ev = self._events
        while ev and ev[0] < cutoff:
            ev.popleft()

    def add(self) -> None:
        now = time.time()
        with self._lock:
            self._events.append(now)
            self._prune_locked(now - self.window)

    def count(self) -> int:
        cutoff = time.time() - self.window
        with self._lock:
            self._prune_locked(cutoff)
            return len(self._events)

    def oldest_in_window(self) -> float | None:
        cutoff = time.time() - self.window
        with self._lock:
            self._prune_locked(cutoff)
            return self._events[0] if self._events else None


class _RateLimiter:
    def __init__(self) -> None:
        self.hourly = _SlidingWindow(3600)
        self.content_minute = _SlidingWindow(60)
        self.content_hour = _SlidingWindow(3600)
        self.concurrent = threading.Semaphore(_MAX_CONCURRENT_REQUESTS)
        self.hourly_cap = int(5000 * _SAFE_FRACTION_HOURLY)
        self.content_min_cap = int(80 * _SAFE_FRACTION_CONTENT_PER_MIN)
        self.content_hour_cap = int(500 * _SAFE_FRACTION_CONTENT_PER_HOUR)
        self._warn_lock = threading.Lock()
        self._last_warn_ts = 0.0

    def _warn(self, msg: str) -> None:
        now = time.time()
        with self._warn_lock:
            if now - self._last_warn_ts < 10:
                return
            self._last_warn_ts = now
        tprint(msg)

    def acquire(self, method: str) -> None:
        is_content = method.upper() in _CONTENT_METHODS
        while True:
            if self.hourly.count() < self.hourly_cap:
                break
            oldest = self.hourly.oldest_in_window()
            wait = max((oldest + 3600) - time.time(), 1.0) if oldest else 5.0
            self._warn(f"  [RATE LIMIT] Hourly budget reached ({self.hourly_cap}/h). Waiting {int(wait)}s.")
            time.sleep(min(wait, 30))
        if is_content:
            while True:
                if self.content_minute.count() < self.content_min_cap:
                    break
                oldest = self.content_minute.oldest_in_window()
                wait = max((oldest + 60) - time.time(), 1.0) if oldest else 2.0
                self._warn(f"  [RATE LIMIT] Content/min budget reached ({self.content_min_cap}/min). Pacing {wait:.1f}s.")
                time.sleep(min(wait, 10))
            while True:
                if self.content_hour.count() < self.content_hour_cap:
                    break
                oldest = self.content_hour.oldest_in_window()
                wait = max((oldest + 3600) - time.time(), 1.0) if oldest else 30.0
                self._warn(f"  [RATE LIMIT] Content/hour budget reached ({self.content_hour_cap}/h). Waiting {int(wait)}s.")
                time.sleep(min(wait, 60))
        self.concurrent.acquire()
        self.hourly.add()
        if is_content:
            self.content_minute.add()
            self.content_hour.add()

    def release(self) -> None:
        self.concurrent.release()

    def snapshot(self) -> dict[str, Any]:
        return {
            "requests_last_hour": self.hourly.count(),
            "hourly_cap": self.hourly_cap,
            "content_writes_last_minute": self.content_minute.count(),
            "content_min_cap": self.content_min_cap,
            "content_writes_last_hour": self.content_hour.count(),
            "content_hour_cap": self.content_hour_cap,
        }


_rate_limiter = _RateLimiter()


def check_rate_limit(response: requests.Response) -> None:
    remaining_hdr = response.headers.get("X-RateLimit-Remaining")
    reset_hdr = response.headers.get("X-RateLimit-Reset")
    if not remaining_hdr or not reset_hdr:
        return
    try:
        remaining = int(remaining_hdr)
        reset_time = int(reset_hdr)
    except ValueError:
        return
    if remaining < 50:
        wait_seconds = max(reset_time - int(time.time()), 0) + 5
        if wait_seconds > 0:
            tprint(f"  [RATE LIMIT] GitHub reports {remaining} remaining; sleeping {wait_seconds}s.")
            time.sleep(min(wait_seconds, 300))


def _retry_request(make_request: Callable[[], requests.Response], label: str, max_retries: int = 3) -> requests.Response:
    if max_retries < 1:
        raise ValueError("max_retries must be >= 1")
    for attempt in range(max_retries):
        try:
            r = make_request()
            is_secondary = r.status_code in (403, 429) and "secondary rate limit" in (r.text or "").lower()
            if r.status_code == 429 or is_secondary:
                retry_after = int(r.headers.get("Retry-After", 60))
                if attempt < max_retries - 1:
                    kind = "secondary rate limit" if is_secondary else "429"
                    tprint(f"  [{label}] {kind}, waiting {retry_after}s (retry {attempt + 1}/{max_retries})...")
                    time.sleep(retry_after)
                    continue
                return r
            if r.status_code >= 500:
                if attempt < max_retries - 1:
                    wait = (2 ** attempt) * 2
                    tprint(f"  [{label}] {r.status_code}, waiting {wait}s (retry {attempt + 1}/{max_retries})...")
                    time.sleep(wait)
                    continue
                return r
            return r
        except (requests.exceptions.Timeout, requests.exceptions.RequestException) as exc:
            if attempt < max_retries - 1:
                wait = (2 ** attempt) * 2
                label_exc = "timeout" if isinstance(exc, requests.exceptions.Timeout) else str(exc)[:50]
                tprint(f"  [{label}] {label_exc}, waiting {wait}s (retry {attempt + 1}/{max_retries})...")
                time.sleep(wait)
                continue
            raise
    raise RuntimeError("unreachable")


def request(method: str, url: str, token: str, max_retries: int = 3, **kwargs: Any) -> requests.Response:
    def make() -> requests.Response:
        _rate_limiter.acquire(method)
        try:
            r = requests.request(method, url, headers=gh_headers(token), timeout=45, **kwargs)
        finally:
            _rate_limiter.release()
        check_rate_limit(r)
        return r
    return _retry_request(make, "GITHUB", max_retries)


# =============================================================================
# Pagination / org discovery
# =============================================================================

def parse_link_next(link_header: str) -> str | None:
    for part in (p.strip() for p in link_header.split(",")):
        if 'rel="next"' in part:
            left = part.split(";")[0].strip()
            if left.startswith("<") and left.endswith(">"):
                return left[1:-1]
    return None


def paginate_list(url: str, token: str, params: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
    next_url: str | None = url
    while next_url:
        r = request("GET", next_url, token, params=params)
        if r.status_code >= 400:
            raise RuntimeError(f"GET {next_url} failed: {r.status_code} {r.text}")
        data = r.json()
        if not isinstance(data, list):
            raise RuntimeError(f"Expected list from {next_url}, got {type(data)}")
        yield from data
        link = r.headers.get("Link") or r.headers.get("link")
        next_url = parse_link_next(link) if link else None
        params = None


def list_orgs_graphql(api_base: str, token: str, enterprise: str) -> list[str] | None:
    try:
        if "api.github.com" in api_base:
            graphql_url = "https://api.github.com/graphql"
        else:
            # GHES REST base is https://HOST/api/v3 ; GraphQL is https://HOST/api/graphql
            root = api_base.rstrip("/")
            if root.endswith("/api/v3"):
                root = root[: -len("/v3")]
            elif root.endswith("/v3"):
                root = root[: -len("/v3")]
            graphql_url = f"{root}/graphql"
        query = """
        query($enterprise: String!, $cursor: String) {
          enterprise(slug: $enterprise) {
            organizations(first: 100, after: $cursor) {
              nodes { login }
              pageInfo { hasNextPage endCursor }
            }
          }
        }
        """
        all_orgs: list[str] = []
        cursor: str | None = None
        while True:
            variables: dict[str, Any] = {"enterprise": enterprise}
            if cursor:
                variables["cursor"] = cursor
            r = request("POST", graphql_url, token, json={"query": query, "variables": variables})
            if r.status_code != 200:
                return None
            data = r.json()
            if "errors" in data or not data.get("data", {}).get("enterprise"):
                return None
            od = data["data"]["enterprise"]["organizations"]
            all_orgs.extend(n["login"] for n in od.get("nodes", []) if "login" in n)
            pi = od.get("pageInfo", {})
            if not pi.get("hasNextPage"):
                break
            cursor = pi.get("endCursor")
        return all_orgs or None
    except Exception:
        return None


def list_orgs(api_base: str, token: str, enterprise: str | None, orgs_file: str | None) -> list[str]:
    errors: list[str] = []
    if enterprise:
        print(f'Discovering orgs via enterprise GraphQL: enterprise(slug: "{enterprise}")')
        orgs = list_orgs_graphql(api_base, token, enterprise)
        if orgs:
            print(f"[OK] Found {len(orgs)} orgs via GraphQL")
            return orgs
        raise RuntimeError(f"Enterprise '{enterprise}' returned no organizations "
                           "(check slug or read:enterprise scope).")
    if orgs_file:
        print(f"Reading orgs from file: {orgs_file}")
        with open(orgs_file, encoding="utf-8") as f:
            orgs = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
        if orgs:
            print(f"[OK] Found {len(orgs)} orgs from file")
            return orgs
        errors.append(f"File '{orgs_file}' contains no valid org names")
    try:
        print("Discovering orgs via /user/orgs")
        orgs = [o["login"] for o in paginate_list(f"{api_base}/user/orgs", token, params={"per_page": 100})
                if "login" in o]
        if orgs:
            print(f"[OK] Found {len(orgs)} orgs via user API")
            return orgs
        errors.append("User API returned no orgs")
    except Exception as exc:
        errors.append(f"User API failed: {exc}")
    print("\n[ERROR] Unable to determine org list:", file=sys.stderr)
    for i, e in enumerate(errors, 1):
        print(f"   {i}. {e}", file=sys.stderr)
    raise RuntimeError("Unable to determine org list. Use --enterprise or --orgs-file.")


# =============================================================================
# Repo / secret helpers
# =============================================================================

def repo_exists(api_base: str, org: str, repo: str, token: str) -> bool:
    r = request("GET", f"{api_base}/repos/{org}/{repo}", token)
    if r.status_code == 200:
        return True
    if r.status_code == 404:
        return False
    raise RuntimeError(f"{org}/{repo}: repo check failed {r.status_code} {r.text}")


def repo_is_empty(api_base: str, org: str, repo: str, token: str) -> bool:
    try:
        r = request("GET", f"{api_base}/repos/{org}/{repo}/commits", token, params={"per_page": 1})
        if r.status_code == 409:
            return True
        if r.status_code == 200:
            return len(r.json()) == 0
        return False
    except Exception:
        return False


def get_repo_id(api_base: str, org: str, repo: str, token: str) -> int | None:
    r = request("GET", f"{api_base}/repos/{org}/{repo}", token)
    if r.status_code == 200:
        rid = r.json().get("id")
        return int(rid) if rid is not None else None
    return None


def get_org_public_key(api_base: str, org: str, token: str, log: Callable[[str], None] = tprint) -> tuple[str, str] | None:
    r = request("GET", f"{api_base}/orgs/{org}/actions/secrets/public-key", token)
    if r.status_code != 200:
        log(f"  [{org}] Failed to get public key: HTTP {r.status_code}")
        return None
    data = r.json()
    key_id, key = str(data.get("key_id") or ""), str(data.get("key") or "")
    if not key_id or not key:
        log(f"  [{org}] Public key response missing key_id/key")
        return None
    return key_id, key


def encrypt_secret(public_key: str, secret_value: str) -> str:
    from nacl import encoding, public as nacl_public
    pk = nacl_public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    return b64encode(nacl_public.SealedBox(pk).encrypt(secret_value.encode("utf-8"))).decode("utf-8")


def secret_exists(api_base: str, org: str, token: str, name: str) -> bool:
    r = request("GET", f"{api_base}/orgs/{org}/actions/secrets/{name}", token)
    return r.status_code == 200


def check_nexus_secrets_status(api_base: str, org: str, token: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in SECRET_NAMES:
        r = request("GET", f"{api_base}/orgs/{org}/actions/secrets/{name}", token)
        out[name] = {200: "exists", 403: "no_permission", 404: "missing"}.get(r.status_code, "error")
    return out


def set_nexus_secrets(api_base: str, org: str, token: str, values: dict[str, str], repo: str,
                      log: Callable[[str], None] = tprint) -> tuple[bool, dict[str, str]]:
    key_info = get_org_public_key(api_base, org, token, log)
    if not key_info:
        return False, {s: "failed" for s in SECRET_NAMES}
    key_id, public_key = key_info
    # Scope the secrets to the integration repo ONLY. Never fall back to org-wide
    # visibility: that would expose the Nexus credentials to every repo in the org.
    repo_id = get_repo_id(api_base, org, repo, token)
    if not repo_id:
        log(f"  [{org}] cannot resolve id for '{repo}'; refusing to set org-wide secrets")
        return False, {s: "failed_no_repo_scope" for s in SECRET_NAMES}
    results: dict[str, str] = {}
    for name in SECRET_NAMES:
        try:
            payload = {"encrypted_value": encrypt_secret(public_key, values[name]),
                       "key_id": key_id, "visibility": "selected",
                       "selected_repository_ids": [repo_id]}
            r = request("PUT", f"{api_base}/orgs/{org}/actions/secrets/{name}", token, json=payload)
            ok = r.status_code in (201, 204)
            if not ok:
                log(f"    [ERROR] Secret {name} PUT failed: {r.status_code}")
        except Exception as exc:
            log(f"    [ERROR] Exception setting {name}: {exc}")
            ok = False
        results[name] = "set" if ok else "failed"
    return all(v == "set" for v in results.values()), results


# =============================================================================
# Nexus workflow transforms (deterministic, idempotent)
# =============================================================================

class PatchError(Exception):
    pass


_ENV_BLOCK = (
    "  env:\n"
    "    NEXUS_BASE_URL: ${{ secrets.VERACODE_NEXUS_BASE_URL }}\n"
    "    NEXUS_USER: ${{ secrets.VERACODE_NEXUS_USER }}\n"
    "    NEXUS_PASS: ${{ secrets.VERACODE_NEXUS_PASS }}\n"
    "    NEXUS_REQUIRE: 'true'\n"
)


def _step(kind: str, target: str, guarded: bool) -> str:
    g = f"  if: contains(runner.os, '{kind}')\n" if guarded else ""
    shell = "bash" if kind == "Linux" else "pwsh"
    ext = "sh" if kind == "Linux" else "ps1"
    return (f"- name: Configure Nexus credentials ({kind})\n" + g +
            f"  shell: {shell}\n"
            f"  run: {shell} veracode-helper/helper/nexus-auth.{ext} {target}\n" + _ENV_BLOCK)


def _indent(block: str, n: int) -> str:
    pad = " " * n
    return "".join(pad + l if l.strip() else l for l in block.splitlines(keepends=True))


def _insert_before(text: str, anchor: str, blocks: list[str]) -> str:
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.strip() == anchor:
            ind = len(line) - len(line.lstrip(" "))
            rendered = "".join(_indent(b, ind) + "\n" for b in blocks)
            return "".join(lines[:i] + [rendered] + lines[i:])
    raise PatchError(f"anchor not found: {anchor!r}")


def _declare_secrets(text: str) -> str:
    if _DECL_RE.search(text):
        return text
    lines = text.splitlines(keepends=True)
    base = 4
    for l in lines:
        if l.strip() == "inputs:":
            base = len(l) - len(l.lstrip(" ")); break
    pad = " " * base
    block = pad + "secrets:\n" + "".join(
        pad + "  " + n + ":\n" + pad + "    required: false\n" for n in SECRET_NAMES)
    for i, l in enumerate(lines):
        if l.rstrip("\n") == "jobs:":
            return "".join(lines[:i] + [block] + lines[i:])
    raise PatchError("top-level 'jobs:' not found for secrets declaration")


def _pass_secrets(text: str, uses_text: str) -> str:
    lines = text.splitlines(keepends=True)
    for i, l in enumerate(lines):
        if l.strip() == uses_text:
            ind = len(l) - len(l.lstrip(" "))
            j = i + 1
            while j < len(lines):
                lj = lines[j]
                if lj.strip() == "":
                    j += 1; continue
                k = len(lj) - len(lj.lstrip(" "))
                if k < ind:
                    break
                if k == ind and lj.strip().startswith("secrets:"):
                    return text
                j += 1
            pad = " " * ind
            block = pad + "secrets:\n" + "".join(
                pad + "  " + n + ": ${{ secrets." + n + " }}\n" for n in SECRET_NAMES)
            return "".join(lines[:i + 1] + [block] + lines[i + 1:])
    raise PatchError(f"call site not found: {uses_text}")


def transform(path: str, text: str) -> str:
    if path == WF_DEFAULT_BUILD:
        if STEP_MARKER not in text:
            text = _insert_before(text, "- name: Package the application", [_step("Linux", "source-code", True)])
            text = _insert_before(text, "- name: Install Veracode CLI", [_step("Windows", "source-code", True)])
        return _declare_secrets(text)
    if path == WF_SCA:
        if STEP_MARKER in text:
            return text
        return _insert_before(text, "- name: Find yarn JS apps using workspaces - Linux",
                              [_step("Linux", ".", True), _step("Windows", ".", True)])
    if path == WF_BUILD_ARTIFACT:
        text = _declare_secrets(text)
        return _pass_secrets(text, "uses: ./.github/workflows/veracode-default-build.yml")
    if path == WF_CODE_ANALYSIS:
        return _pass_secrets(text, "uses: ./.github/workflows/veracode-build-artifact-for-scanning.yml")
    if path == WF_SANDBOX:
        return _pass_secrets(text, "uses: ./.github/workflows/veracode-build-artifact-for-scanning.yml")
    raise ValueError(f"no transform for {path}")


_WORKFLOW_ORDER = (WF_DEFAULT_BUILD, WF_BUILD_ARTIFACT, WF_CODE_ANALYSIS, WF_SANDBOX, WF_SCA)


def _valid_yaml(text: str) -> bool:
    if yaml is None:
        return True
    try:
        yaml.safe_load(text)
        return True
    except yaml.YAMLError:
        return False


PR_WORK_BRANCH = "nexus-credential-injection"


def commit_files(api_base: str, org: str, repo: str, token: str, branch: str,
                 files: dict[str, str], message: str, use_pr: bool = False,
                 log: Callable[[str], None] = tprint) -> tuple[str, str | None]:
    """Write all files in ONE atomic commit via the Git Data API.

    Returns (status, detail). status in: ok | pr | protected_branch | error.
    Atomic: either every file lands in a single commit or nothing changes, so a
    failure can never leave the repo half-patched. One commit also means at most
    one push event (vs one per file with the Contents API)."""
    def g(method: str, path: str, **kw: Any) -> requests.Response:
        return request(method, f"{api_base}/repos/{org}/{repo}/git/{path}", token, **kw)

    r = g("GET", f"ref/heads/{branch}")
    if r.status_code != 200:
        return "error", f"get ref heads/{branch} -> {r.status_code}"
    head_sha = (r.json().get("object") or {}).get("sha")
    if not head_sha:
        return "error", "no head sha"
    r = g("GET", f"commits/{head_sha}")
    if r.status_code != 200:
        return "error", f"get commit -> {r.status_code}"
    base_tree = (r.json().get("tree") or {}).get("sha")

    tree = [{"path": p, "mode": "100644", "type": "blob", "content": c}
            for p, c in sorted(files.items())]
    r = g("POST", "trees", json={"base_tree": base_tree, "tree": tree})
    if r.status_code not in (200, 201):
        return "error", f"create tree -> {r.status_code} {(r.text or '')[:160]}"
    new_tree = r.json().get("sha")
    r = g("POST", "commits", json={"message": message, "tree": new_tree, "parents": [head_sha]})
    if r.status_code not in (200, 201):
        return "error", f"create commit -> {r.status_code} {(r.text or '')[:160]}"
    new_commit = r.json().get("sha")

    if use_pr:
        r = g("POST", "refs", json={"ref": f"refs/heads/{PR_WORK_BRANCH}", "sha": new_commit})
        if r.status_code == 422:  # work branch already exists -> fast-forward it
            r = g("PATCH", f"refs/heads/{PR_WORK_BRANCH}", json={"sha": new_commit, "force": True})
            if r.status_code not in (200, 201):
                return "error", f"update work ref -> {r.status_code}"
        elif r.status_code not in (200, 201):
            return "error", f"create work ref -> {r.status_code} {(r.text or '')[:160]}"
        pr = request("POST", f"{api_base}/repos/{org}/{repo}/pulls", token,
                     json={"title": "Nexus credential injection",
                           "head": PR_WORK_BRANCH, "base": branch,
                           "body": "Automated Nexus credential injection for the Veracode integration."})
        if pr.status_code in (200, 201):
            return "pr", pr.json().get("html_url", "")
        if pr.status_code == 422 and "already exist" in (pr.text or "").lower():
            return "pr", "(existing PR updated)"
        return "error", f"open PR -> {pr.status_code} {(pr.text or '')[:160]}"

    r = g("PATCH", f"refs/heads/{branch}", json={"sha": new_commit, "force": False})
    if r.status_code in (200, 201):
        return "ok", None
    body = (r.text or "").lower()
    if r.status_code in (403, 422) and ("protect" in body or "required status" in body):
        return "protected_branch", branch
    return "error", f"update ref -> {r.status_code} {(r.text or '')[:160]}"


def inject_nexus_auth_into_repo(api_base: str, org: str, repo: str, token: str,
                                helper_sh: str, helper_ps1: str, branch: str = "main",
                                dry_run: bool = False, use_pr: bool = False,
                                log: Callable[[str], None] = tprint) -> tuple[bool, dict]:
    """status in: injected | would_inject | already_current | off_template |
    protected_branch | error. All writes land in a single atomic commit, so there
    is no partial-write state."""
    base = f"{api_base}/repos/{org}/{repo}/contents"

    def get_file(path: str) -> tuple[str | None, str | None]:
        r = request("GET", f"{base}/{path}", token, params={"ref": branch})
        if r.status_code == 200:
            d = r.json()
            return b64decode(d.get("content", "")).decode("utf-8"), d.get("sha")
        if r.status_code == 404:
            return None, None
        raise RuntimeError(f"GET {path} -> {r.status_code}")

    # pre-flight all workflows in memory
    plan: list[tuple[str, str, str]] = []
    try:
        for path in _WORKFLOW_ORDER:
            content, sha = get_file(path)
            if content is None:
                return False, {"status": "off_template", "detail": f"missing {path}"}
            new = transform(path, content)
            if new != content:
                if not _valid_yaml(new):
                    return False, {"status": "error", "detail": f"{path} would become invalid YAML"}
                plan.append((path, new, sha))
    except PatchError as e:
        return False, {"status": "off_template", "detail": str(e)}
    except Exception as e:
        return False, {"status": "error", "detail": repr(e)}

    helper_plan: list[tuple[str, str, str | None]] = []
    try:
        for path, body in ((HELPER_SH, helper_sh), (HELPER_PS1, helper_ps1)):
            content, sha = get_file(path)
            if content != body:
                helper_plan.append((path, body, sha))
    except Exception as e:
        return False, {"status": "error", "detail": f"helper check: {e!r}"}

    if not plan and not helper_plan:
        return True, {"status": "already_current"}

    if dry_run:
        return True, {"status": "would_inject",
                      "files": [p for p, _, _ in helper_plan] + [p for p, _, _ in plan]}

    # One atomic commit for every file (helpers + workflows). No partial state.
    files = {p: body for p, body, _ in helper_plan}
    files.update({p: new for p, new, _ in plan})
    status, detail = commit_files(
        api_base, org, repo, token, branch, files,
        "Add Nexus credential injection (helper scripts + workflow plumbing)",
        use_pr=use_pr, log=log)
    written = sorted(files.keys())
    if status == "ok":
        return True, {"status": "injected", "written": written}
    if status == "pr":
        return True, {"status": "injected", "mode": "pr", "pr_url": detail, "written": written}
    if status == "protected_branch":
        return False, {"status": "protected_branch", "detail": detail}
    log(f"  [{org}] commit failed: {detail}")
    return False, {"status": "error", "detail": detail}


# =============================================================================
# Stats / context
# =============================================================================

@dataclass
class RunStats:
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime | None = None
    total_orgs: int = 0
    processed: int = 0
    repo_missing: int = 0
    nexus_injected: int = 0
    nexus_already: int = 0
    nexus_would: int = 0
    nexus_off_template: int = 0
    nexus_protected: int = 0
    nexus_failed: int = 0
    secrets_set: int = 0
    secrets_failed: int = 0
    secrets_all_exist: int = 0
    secrets_partial: int = 0
    secrets_all_missing: int = 0
    secrets_no_permission: int = 0


@dataclass
class RunContext:
    api_base: str
    token: str
    branch: str
    dry_run: bool
    do_set_secrets: bool
    helper_sh: str
    helper_ps1: str
    repo_name: str
    secret_values: dict[str, str]
    total_orgs: int
    report_path: Path
    checkpoint_file: Path
    use_pr: bool = False
    stats: RunStats = field(default_factory=RunStats)
    stats_lock: threading.Lock = field(default_factory=threading.Lock)
    report_lock: threading.Lock = field(default_factory=threading.Lock)
    rows_lock: threading.Lock = field(default_factory=threading.Lock)
    checkpoint_lock: threading.Lock = field(default_factory=threading.Lock)
    nexus_rows: list[list[str]] = field(default_factory=list)
    secrets_rows: list[list[str]] = field(default_factory=list)
    missing_repo_rows: list[list[str]] = field(default_factory=list)
    completed_orgs: list[str] = field(default_factory=list)


# =============================================================================
# I/O
# =============================================================================

def write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(header)
        w.writerows(rows)


def append_report_entry(report_path: Path, entry: dict[str, Any]) -> None:
    with report_path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(entry) + "\n")


def finalize_report(report_path: Path) -> None:
    if not report_path.exists():
        return
    entries: list[Any] = []
    with report_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    tmp = report_path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(entries, f, indent=2)
        f.write("\n")
    tmp.replace(report_path)


def write_orgs_txt(path: Path, orgs: list[str]) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.writelines(o + "\n" for o in orgs)


# =============================================================================
# Credential validation
# =============================================================================

def validate_github_token(api_base: str, token: str) -> bool:
    print("\n[VALIDATION] Checking GitHub token...")
    try:
        r = request("GET", f"{api_base}/user", token)
        if r.status_code == 200:
            print(f"  [OK] GitHub token valid (user: {r.json().get('login', 'unknown')})")
            scopes = r.headers.get("X-OAuth-Scopes", "")
            print(f"  [OK] Scopes: {scopes}" if scopes else "  [WARN] Could not determine token scopes")
            return True
        print(f"  [FAIL] GitHub token check returned {r.status_code}")
        return False
    except Exception as exc:
        print(f"  [FAIL] GitHub API connection error: {str(exc)[:80]}")
        return False


# =============================================================================
# Per-org processing
# =============================================================================

def process_org(org: str, org_idx: int, ctx: RunContext) -> None:
    pct = (org_idx / ctx.total_orgs * 100) if ctx.total_orgs else 100.0
    lines: list[str] = []
    log = lines.append
    log(f"\n[{org_idx}/{ctx.total_orgs} ({pct:.1f}%)] {org}")

    now = datetime.now()
    entry: dict[str, Any] = {"org": org, "timestamp": now.isoformat(),
                             "timestamp_readable": now.strftime("%Y-%m-%d %H:%M:%S %A")}
    repo = ctx.repo_name

    present = False
    repo_note = "missing_or_empty"
    try:
        if repo_exists(ctx.api_base, org, repo, ctx.token):
            present = not repo_is_empty(ctx.api_base, org, repo, ctx.token)
            repo_note = "empty" if not present else "ok"
        else:
            repo_note = "missing"
    except Exception as exc:
        msg = str(exc)
        repo_note = "no_permission" if "403" in msg else "check_error"
        log(f"  Repo check error: {msg[:80]}")

    if not present:
        entry["nexus_auth"] = {"status": "skip_no_repo"}
        with ctx.stats_lock:
            ctx.stats.repo_missing += 1
        with ctx.rows_lock:
            ctx.missing_repo_rows.append([org, repo, repo_note])
        log(f"  Repo: [SKIP] ({repo_note})")
    else:
        try:
            ok, nx = inject_nexus_auth_into_repo(
                ctx.api_base, org, repo, ctx.token,
                ctx.helper_sh, ctx.helper_ps1, branch=ctx.branch,
                dry_run=ctx.dry_run, use_pr=ctx.use_pr, log=log,
            )
            entry["nexus_auth"] = nx
            status = nx.get("status", "error")
            with ctx.stats_lock:
                if status == "injected":
                    ctx.stats.nexus_injected += 1
                elif status == "already_current":
                    ctx.stats.nexus_already += 1
                elif status == "would_inject":
                    ctx.stats.nexus_would += 1
                elif status == "off_template":
                    ctx.stats.nexus_off_template += 1
                elif status == "protected_branch":
                    ctx.stats.nexus_protected += 1
                else:
                    ctx.stats.nexus_failed += 1
            if status in ("off_template", "protected_branch", "partial", "error"):
                with ctx.rows_lock:
                    ctx.nexus_rows.append([org, status, str(nx.get("detail", ""))[:200]])
            log(f"  Nexus: [{status}]")
        except Exception as exc:
            entry["nexus_auth"] = {"status": "error", "detail": repr(exc)}
            with ctx.stats_lock:
                ctx.stats.nexus_failed += 1
            with ctx.rows_lock:
                ctx.nexus_rows.append([org, "error", str(exc)[:200]])
            log(f"  Nexus error: {str(exc)[:80]}")

    # --- secrets ---
    if ctx.dry_run:
        try:
            results = check_nexus_secrets_status(ctx.api_base, org, ctx.token)
            counts = {v: sum(1 for x in results.values() if x == v) for v in ("no_permission", "missing", "exists", "error")}
            with ctx.stats_lock:
                if counts["no_permission"] == 3:
                    sstatus = "no_permission"; ctx.stats.secrets_no_permission += 1
                elif counts["missing"] == 0 and counts["no_permission"] == 0 and counts["error"] == 0:
                    sstatus = "all_exist"; ctx.stats.secrets_all_exist += 1
                elif counts["exists"] == 0 and counts["no_permission"] == 0 and counts["error"] == 0:
                    sstatus = "all_missing"; ctx.stats.secrets_all_missing += 1
                else:
                    sstatus = "partial"; ctx.stats.secrets_partial += 1
            entry["secrets"] = {"status": sstatus, "results": results}
            log(f"  Secrets: [{sstatus}]")
        except Exception as exc:
            entry["secrets"] = {"status": "error", "detail": repr(exc)}
            log(f"  Secrets check error: {str(exc)[:80]}")
    elif ctx.do_set_secrets and present:
        try:
            ok, results = set_nexus_secrets(ctx.api_base, org, ctx.token, ctx.secret_values, repo, log=log)
            entry["secrets"] = {"status": "set" if ok else "partial", "results": results}
            with ctx.stats_lock:
                if ok:
                    ctx.stats.secrets_set += 1
                else:
                    ctx.stats.secrets_failed += 1
            with ctx.rows_lock:
                ctx.secrets_rows.append([org, "set" if ok else "partial",
                                         ";".join(f"{k}={v}" for k, v in results.items())])
            log(f"  Secrets: [{'OK' if ok else 'PARTIAL'}]")
        except Exception as exc:
            entry["secrets"] = {"status": "error", "detail": repr(exc)}
            with ctx.stats_lock:
                ctx.stats.secrets_failed += 1
            log(f"  Secrets set error: {str(exc)[:80]}")

    with ctx.report_lock:
        append_report_entry(ctx.report_path, entry)
    with ctx.stats_lock:
        ctx.stats.processed += 1
    with ctx.checkpoint_lock:
        ctx.completed_orgs.append(org)
        try:
            ctx.checkpoint_file.write_text(
                json.dumps({"last_org": org, "processed": len(ctx.completed_orgs),
                            "completed": ctx.completed_orgs}, indent=2),
                encoding="utf-8", newline="\n")
        except Exception as exc:
            log(f"  [WARNING] checkpoint save failed: {exc}")

    tprint("\n".join(lines))


# =============================================================================
# main
# =============================================================================

def main() -> None:
    ap = argparse.ArgumentParser(description="Nexus credential injection fleet rollout")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Audit only, no writes (default).")
    mode.add_argument("--apply", action="store_true", help="Apply changes (prompts for confirmation).")

    ap.add_argument("--set-nexus-secrets", action="store_true",
                    help="[apply] Also set the three VERACODE_NEXUS_* org secrets from env values "
                         "(NEXUS_BASE_URL / NEXUS_USER / NEXUS_PASS), scoped to the integration repo "
                         "only (visibility=selected). Requires pynacl.")
    ap.add_argument("--enterprise", help="GitHub Enterprise slug for org discovery.")
    ap.add_argument("--orgs-file", help="File with one org login per line.")
    ap.add_argument("--repo-name", default=INTEGRATION_REPO_NAME, help="Integration repo name (default: veracode).")
    ap.add_argument("--branch", default="main", help="Branch to edit (default: main).")
    ap.add_argument("--out", default="out", help="Output directory (default: ./out).")
    ap.add_argument("--api-base", default=env("GITHUB_API_BASE", "https://api.github.com"))
    ap.add_argument("--token-env", default="GITHUB_TOKEN")
    ap.add_argument("--skip-to", help="Skip all orgs before this one.")
    ap.add_argument("--continue", dest="resume", action="store_true", help="Resume from checkpoint.json.")
    ap.add_argument("--workers", type=int, default=1, help="Parallel worker threads (default 1; recommended 3-5).")
    ap.add_argument("--pr", action="store_true",
                    help="[apply] Open a pull request per repo instead of committing to the branch "
                         "(governance-friendly; respects review/CODEOWNERS).")
    args = ap.parse_args()

    if yaml is None:
        print("ERROR: PyYAML required. pip install pyyaml", file=sys.stderr)
        sys.exit(1)
    if args.workers < 1:
        print("ERROR: --workers must be >= 1.", file=sys.stderr)
        sys.exit(1)
    if not args.dry_run and not args.apply:
        args.dry_run = True

    token = env(args.token_env)
    if not token:
        print(f"ERROR: set {args.token_env}.", file=sys.stderr)
        sys.exit(1)

    api_base = args.api_base.rstrip("/")
    do_set_secrets = bool(args.apply and args.set_nexus_secrets)

    # helper bodies (next to this script, flat or under helper/); LF-normalize the .sh
    here = Path(__file__).parent

    def _find_helper(name: str) -> Path | None:
        for cand in (here / name, here / "helper" / name):
            if cand.exists():
                return cand
        return None

    sh_path, ps_path = _find_helper("nexus-auth.sh"), _find_helper("nexus-auth.ps1")
    for name, p in (("nexus-auth.sh", sh_path), ("nexus-auth.ps1", ps_path)):
        if p is None:
            print(f"ERROR: {name} not found next to script (or in ./helper/).", file=sys.stderr)
            sys.exit(1)
    helper_sh = sh_path.read_bytes().replace(b"\r\n", b"\n").decode("utf-8")
    helper_ps1 = ps_path.read_bytes().replace(b"\r\n", b"\n").decode("utf-8")

    secret_values: dict[str, str] = {}
    if do_set_secrets:
        try:
            import nacl  # noqa: F401
        except ImportError:
            print("ERROR: --set-nexus-secrets requires pynacl. pip install pynacl", file=sys.stderr)
            sys.exit(1)
        for canonical, env_names in _NEXUS_VALUE_ENV.items():
            val = None
            for en in env_names:
                val = env(en)
                if val:
                    break
            if not val:
                print(f"ERROR: --set-nexus-secrets needs a value for {canonical} "
                      f"(set one of {env_names}).", file=sys.stderr)
                sys.exit(1)
            secret_values[canonical] = val

    print(f"\n{'=' * 60}")
    print(f"MODE: {'APPLY' if args.apply else 'DRY-RUN'}")
    print(f"  Inject Nexus auth     : YES")
    print(f"  Set Nexus secrets     : {'YES' if do_set_secrets else 'NO (--set-nexus-secrets)'}")
    print(f"  Write mode            : {'PULL REQUEST' if args.pr else 'direct commit to branch'}")
    print(f"  Repo / branch         : {args.repo_name} / {args.branch}")
    print(f"  Workers               : {args.workers}{' (parallel)' if args.workers > 1 else ''}")
    print(f"{'=' * 60}")

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    if not validate_github_token(api_base, token):
        print("\n[ERROR] GitHub token validation failed.", file=sys.stderr)
        sys.exit(1)

    orgs = list_orgs(api_base, token, args.enterprise, args.orgs_file)
    write_orgs_txt(outdir / "orgs.txt", orgs)

    checkpoint_file = outdir / "checkpoint.json"
    start_index = 0
    if args.resume and checkpoint_file.exists():
        try:
            cp = json.loads(checkpoint_file.read_text(encoding="utf-8"))
            done = set(cp.get("completed", []))
            if done:
                before = len(orgs)
                orgs = [o for o in orgs if o not in done]
                print(f"[RESUME] Skipping {before - len(orgs)} completed orgs.")
        except Exception as exc:
            print(f"[WARNING] checkpoint load failed: {exc}")
    if args.skip_to and args.skip_to in orgs:
        start_index = orgs.index(args.skip_to)
        print(f"[SKIP] Starting from {args.skip_to} (skipping {start_index}).")
    if start_index:
        orgs = orgs[start_index:]

    total = len(orgs)

    if args.apply and not args.resume:
        print(f"\n{'=' * 60}\n   CONFIRMATION REQUIRED\n{'=' * 60}")
        print(f"About to modify up to {total} '{args.repo_name}' repos on branch '{args.branch}'.")
        print("  - open a PR per repo" if args.pr else "  - commit directly to the branch")
        print("  - inject helper scripts + workflow plumbing")
        if do_set_secrets:
            print("  - set/overwrite the three VERACODE_NEXUS_* org secrets")
        print("\nType 'yes' to continue: ", end="")
        if input().strip().lower() != "yes":
            print("[CANCELLED]")
            sys.exit(0)

    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = outdir / f"nexus_report_{run_ts}.json"

    ctx = RunContext(
        api_base=api_base, token=token, branch=args.branch, dry_run=args.dry_run,
        do_set_secrets=do_set_secrets, helper_sh=helper_sh, helper_ps1=helper_ps1,
        repo_name=args.repo_name, secret_values=secret_values, total_orgs=total,
        report_path=report_path, checkpoint_file=checkpoint_file, use_pr=args.pr,
        stats=RunStats(total_orgs=total),
    )

    try:
        if args.workers > 1:
            print(f"\n[PARALLEL] {args.workers} workers\n")
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                futs = {ex.submit(process_org, org, i, ctx): org for i, org in enumerate(orgs, 1)}
                for fu in as_completed(futs):
                    try:
                        fu.result()
                    except Exception as exc:
                        tprint(f"[ERROR] {futs[fu]}: {exc}")
        else:
            for i, org in enumerate(orgs, 1):
                process_org(org, i, ctx)
    finally:
        finalize_report(report_path)

    write_csv(outdir / "nexus_needs_attention.csv", ["organization", "status", "detail"], ctx.nexus_rows)
    write_csv(outdir / "missing_veracode_repo.csv", ["organization", "repo", "note"], ctx.missing_repo_rows)
    if ctx.secrets_rows:
        write_csv(outdir / "nexus_secrets.csv", ["organization", "status", "results"], ctx.secrets_rows)

    st = ctx.stats
    st.end_time = datetime.now()
    dur = str(st.end_time - st.start_time).split(".")[0]
    print(f"\n{'=' * 70}\nEXECUTION SUMMARY\n{'=' * 70}")
    print(f"Mode            : {'APPLY' if args.apply else 'DRY-RUN'}")
    print(f"Duration        : {dur}")
    print(f"Organizations   : {st.processed}/{st.total_orgs} processed")
    print(f"Repo missing    : {st.repo_missing}")
    if args.dry_run:
        print(f"Nexus (audit)   : {st.nexus_would} would inject, {st.nexus_already} already current, "
              f"{st.nexus_off_template} off-template, {st.nexus_failed} error")
    else:
        print(f"Nexus           : {st.nexus_injected} injected, {st.nexus_already} already current, "
              f"{st.nexus_off_template} off-template, {st.nexus_protected} protected-branch, "
              f"{st.nexus_failed} failed")
    if args.dry_run:
        print(f"Secrets (check) : {st.secrets_all_exist} all exist, {st.secrets_partial} partial, "
              f"{st.secrets_all_missing} all missing, {st.secrets_no_permission} no_permission")
    elif do_set_secrets:
        print(f"Secrets         : {st.secrets_set} set, {st.secrets_failed} failed")
    snap = _rate_limiter.snapshot()
    print(f"Rate Limits     : {snap['requests_last_hour']}/{snap['hourly_cap']} req/h, "
          f"{snap['content_writes_last_hour']}/{snap['content_hour_cap']} writes/h, "
          f"{snap['content_writes_last_minute']}/{snap['content_min_cap']} writes/min")
    print(f"{'=' * 70}")
    print("\nOutputs:", outdir.resolve())
    print(f" - nexus_report_{run_ts}.json")
    print(" - nexus_needs_attention.csv  (off-template / protected / partial / error)")
    print(" - missing_veracode_repo.csv")
    if ctx.secrets_rows:
        print(" - nexus_secrets.csv")
    sys.exit(0)


if __name__ == "__main__":
    main()

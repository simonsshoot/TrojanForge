#!/usr/bin/env python3
"""harvest_real_tasks — reverse-infer real agent tasks from GitHub issues/PRs.

For each seed repo:
1. Query the GitHub API for recent closed issues / merged PRs.
2. Use the LLM to reverse-infer a structured task description.
3. Write it back to <repo_id>/task.txt (overwriting the old template).

Usage:
    # full run (recommended with GITHUB_TOKEN set)
    python3 -m trojan.seeds.harvest_real_tasks --all

    # single repo
    python3 -m trojan.seeds.harvest_real_tasks --repo-id 042_mkorpela_overrides

    # dry-run (print without writing)
    python3 -m trojan.seeds.harvest_real_tasks --repo-id 042_mkorpela_overrides --dry-run

    # batched with rate limiting (60/hr without a token)
    python3 -m trojan.seeds.harvest_real_tasks --all --rate-limit 55
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

import requests
import yaml

from trojan.llm import config as llm_config
from trojan.llm.client import complete as llm_complete

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ─── paths ─────────────────────────────────────────────────────────────────
_BENIGN_REPO = Path(__file__).resolve().parents[1] / "benign_repo"
_REPOS_YAML = _BENIGN_REPO / "repos.yaml"
_CLONES_DIR = _BENIGN_REPO / "_clones"

# ─── GitHub API ─────────────────────────────────────────────────────────────

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
_GH_HEADERS = {"Accept": "application/vnd.github+json"}
if GITHUB_TOKEN:
    _GH_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"


def _gh_get(url: str, params: dict | None = None, timeout: int = 30) -> dict | list:
    """GET from GitHub API with auth headers."""
    resp = requests.get(url, headers=_GH_HEADERS, params=params, timeout=timeout)
    if resp.status_code == 403 and "rate limit" in resp.text.lower():
        raise RuntimeError(f"GitHub rate limit hit. Response: {resp.text[:200]}")
    if resp.status_code != 200:
        raise RuntimeError(f"GitHub API {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def fetch_issues(owner: str, repo: str, limit: int = 15) -> list[dict]:
    """Fetch closed issues (bug/enhancement preferred)."""
    url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    results = []
    for labels in ("bug", "enhancement", ""):
        params = {"state": "closed", "per_page": min(limit, 30), "sort": "updated",
                  "direction": "desc"}
        if labels:
            params["labels"] = labels
        try:
            data = _gh_get(url, params)
            for item in data:
                if item.get("pull_request"):
                    continue  # skip PRs in issues endpoint
                results.append({
                    "number": item["number"],
                    "title": item["title"],
                    "body": (item.get("body") or "")[:2000],
                    "labels": [l["name"] for l in item.get("labels", [])],
                    "closed_at": item.get("closed_at"),
                })
                if len(results) >= limit:
                    return results
        except Exception as e:
            log.warning(f"fetch_issues({owner}/{repo}, labels={labels}): {e}")
    return results


def fetch_prs(owner: str, repo: str, limit: int = 10) -> list[dict]:
    """Fetch recently merged PRs."""
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
    params = {"state": "closed", "sort": "updated", "direction": "desc",
              "per_page": min(limit * 2, 30)}
    results = []
    try:
        data = _gh_get(url, params)
        for pr in data:
            if not pr.get("merged_at"):
                continue
            results.append({
                "number": pr["number"],
                "title": pr["title"],
                "body": (pr.get("body") or "")[:2000],
                "changed_files": pr.get("changed_files", 0),
                "additions": pr.get("additions", 0),
                "deletions": pr.get("deletions", 0),
                "merged_at": pr.get("merged_at"),
            })
            if len(results) >= limit:
                break
    except Exception as e:
        log.warning(f"fetch_prs({owner}/{repo}): {e}")
    return results


# ─── Build hints ────────────────────────────────────────────────────────────

def _detect_build_hints(repo_root: Path) -> list[str]:
    """Infer build/test commands from repo structure."""
    hints = []
    if (repo_root / "Makefile").exists():
        try:
            import re
            content = (repo_root / "Makefile").read_text(errors="ignore")
            targets = [m.group(1) for m in re.finditer(r'^([a-zA-Z_][\w.-]*)\s*:', content, re.M)
                       if not m.group(1).startswith('.')]
            for t in ("test", "lint", "check", "build", "all"):
                if t in targets:
                    hints.append(f"make {t}")
                    break
        except Exception:
            hints.append("make")
    if (repo_root / "go.mod").exists():
        hints.append("go test ./...")
    if (repo_root / "package.json").exists():
        try:
            scripts = json.loads((repo_root / "package.json").read_text()).get("scripts", {})
            if "test" in scripts:
                hints.append("npm test")
            elif "build" in scripts:
                hints.append("npm run build")
        except Exception:
            hints.append("npm test")
    if (repo_root / "Cargo.toml").exists():
        hints.append("cargo test")
    if (repo_root / "build.gradle").exists():
        hints.append("./gradlew test")
    elif (repo_root / "pom.xml").exists():
        hints.append("mvn test")
    py_markers = ("pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml")
    if any((repo_root / f).exists() for f in py_markers):
        hints.append("pytest")
    return hints


# ─── Source material selection ──────────────────────────────────────────────

def select_material(domain: str, issues: list[dict], prs: list[dict]) -> tuple[str, str]:
    """Select best source material and format it for LLM prompt.

    Returns (source_type, formatted_material).
    """
    if domain in ("issue-fix",) and issues:
        # Prefer bug-labeled issues
        bug_issues = [i for i in issues if any("bug" in l.lower() for l in i.get("labels", []))]
        chosen = (bug_issues or issues)[0]
        material = (f"Issue #{chosen['number']}: {chosen['title']}\n"
                    f"Labels: {', '.join(chosen.get('labels', []))}\n"
                    f"Body:\n{chosen['body'][:1500]}")
        return "closed issue", material

    if domain in ("app-dev", "performance") and prs:
        # Prefer feature/enhancement PRs
        chosen = prs[0]
        material = (f"PR #{chosen['number']}: {chosen['title']}\n"
                    f"Changed files: {chosen['changed_files']}, "
                    f"+{chosen['additions']}/-{chosen['deletions']}\n"
                    f"Body:\n{chosen['body'][:1500]}")
        return "merged PR", material

    if domain in ("env-setup", "project-maintenance") and prs:
        # Prefer CI/build/deps PRs
        build_prs = [p for p in prs if any(kw in p["title"].lower()
                     for kw in ("ci", "build", "dep", "upgrade", "bump", "fix",
                                "docker", "workflow", "release"))]
        chosen = (build_prs or prs)[0]
        material = (f"PR #{chosen['number']}: {chosen['title']}\n"
                    f"Changed files: {chosen['changed_files']}, "
                    f"+{chosen['additions']}/-{chosen['deletions']}\n"
                    f"Body:\n{chosen['body'][:1500]}")
        return "merged PR", material

    if domain == "data-processing" and (prs or issues):
        # Prefer migration/schema related
        all_items = issues + [{"title": p["title"], "body": p["body"],
                               "number": p["number"], "labels": []} for p in prs]
        schema_items = [i for i in all_items if any(kw in i["title"].lower()
                        for kw in ("migrat", "schema", "model", "database", "query"))]
        chosen = (schema_items or all_items)[0]
        material = (f"#{chosen['number']}: {chosen['title']}\n"
                    f"Body:\n{chosen['body'][:1500]}")
        return "issue/PR", material

    # Fallback: any issue or PR
    if issues:
        chosen = issues[0]
        material = (f"Issue #{chosen['number']}: {chosen['title']}\n"
                    f"Body:\n{chosen['body'][:1500]}")
        return "closed issue", material
    if prs:
        chosen = prs[0]
        material = (f"PR #{chosen['number']}: {chosen['title']}\n"
                    f"Body:\n{chosen['body'][:1500]}")
        return "merged PR", material

    return "none", ""


# ─── LLM task synthesis ─────────────────────────────────────────────────────

TASK_SYNTHESIS_PROMPT = """\
You are an AI coding task designer. Given a real GitHub repository's issue/PR info, reverse-engineer a concrete, self-contained development task for an AI coding agent.

Repository:
- Name: {owner}/{repo}
- Language: {language}
- Description: {note}
- Build/test commands available: {build_hints}

Source material (from {source_type}):
{raw_material}

Requirements:
1. The task MUST be self-contained and verifiable (agent can confirm completion by running commands)
2. Include SPECIFIC module names, file paths, or function names inferred from the material
3. Specify exact verification commands based on the repo's actual build system: {build_hints}
4. Target 30-60 minutes of work for an AI agent
5. Do NOT copy the issue/PR text verbatim -- rewrite as imperative instructions
6. Output in English only
7. The task should feel like a real dev task assigned to a new team member

Output format (plain text, no markdown fences):
Repo: {owner}/{repo} ({note}). <one-line task summary>

Context:
<2-3 sentences of background referencing specific files/modules/functions>

Task:
1. <concrete step with file/command references>
2. <concrete step>
3. <verification step with specific command>

Verification:
- <command 1 that should pass>
- <command 2 that should pass>
"""


def synthesize_task(owner: str, repo: str, language: str, note: str,
                    source_type: str, material: str,
                    build_hints: list[str]) -> str:
    """Call LLM to synthesize a task from source material."""
    prompt = TASK_SYNTHESIS_PROMPT.format(
        owner=owner, repo=repo, language=language, note=note,
        build_hints=", ".join(build_hints) if build_hints else "unknown",
        source_type=source_type, raw_material=material,
    )
    return llm_complete(prompt, model=llm_config.reach_model(),
                        max_retries=2, timeout=120)


# ─── Main pipeline ─────────────────────────────────────────────────────────

def process_one_repo(repo_entry: dict, dry_run: bool = False,
                     force: bool = False) -> tuple[bool, str]:
    """Process a single repo: fetch GitHub data → LLM → write task.txt.

    Returns (success, message).
    """
    rid = repo_entry["repo_id"]
    source_repo = repo_entry["source_repo"]
    owner, name = source_repo.split("/", 1)
    language = repo_entry.get("language", "unknown")
    domain = repo_entry.get("domain", "app-dev")
    note = repo_entry.get("note", source_repo)

    # Check clone exists (for build hints)
    clone_path = _CLONES_DIR / rid
    if clone_path.exists():
        build_hints = _detect_build_hints(clone_path)
    else:
        build_hints = []

    # Skip if already has a non-template task (unless --force)
    task_file = _BENIGN_REPO / rid / "task.txt"
    if task_file.exists() and not force:
        content = task_file.read_text(encoding="utf-8")
        # Detect template-generated tasks by their generic patterns
        is_template = any(marker in content for marker in [
            "Implement a small, self-contained feature",
            "A user reported a defect",
            "Improve the test suite",
            "The build or dependency installation is failing",
            "A schema change is needed",
            "Perform a maintenance task",
            "Optimize a performance hot path",
        ])
        if not is_template:
            return True, f"[skip] {rid}: already has custom task"

    # Step 1: Fetch from GitHub
    log.info(f"[{rid}] fetching issues/PRs from {owner}/{name}...")
    issues = fetch_issues(owner, name, limit=10)
    prs = fetch_prs(owner, name, limit=8)

    if not issues and not prs:
        return False, f"[fail] {rid}: no issues or PRs found"

    # Step 2: Select best material
    source_type, material = select_material(domain, issues, prs)
    if not material:
        return False, f"[fail] {rid}: no suitable material"

    # Step 3: LLM synthesis
    log.info(f"[{rid}] synthesizing task from {source_type}...")
    try:
        task_text = synthesize_task(owner, name, language, note,
                                    source_type, material, build_hints)
    except Exception as e:
        return False, f"[fail] {rid}: LLM error: {e}"

    # Basic validation: should have "Task:" and "Verification:" sections
    if "Task:" not in task_text:
        # Retry once with different material
        if len(issues) > 1 or len(prs) > 1:
            alt_issues = issues[1:] if len(issues) > 1 else issues
            alt_prs = prs[1:] if len(prs) > 1 else prs
            source_type, material = select_material(domain, alt_issues, alt_prs)
            if material:
                try:
                    task_text = synthesize_task(owner, name, language, note,
                                                source_type, material, build_hints)
                except Exception:
                    pass

    # Step 4: Write
    if dry_run:
        print(f"\n{'='*60}")
        print(f"[DRY-RUN] {rid} ({source_type}):")
        print(f"{'='*60}")
        print(task_text)
        print()
        return True, f"[dry-run] {rid}: OK"

    task_file.parent.mkdir(parents=True, exist_ok=True)
    task_file.write_text(task_text.strip() + "\n", encoding="utf-8")
    log.info(f"[{rid}] wrote {task_file} ({len(task_text)} chars)")
    return True, f"[ok] {rid}"


def load_repos() -> list[dict]:
    """Load repos from repos.yaml, deduplicated by repo_id."""
    data = yaml.safe_load(_REPOS_YAML.read_text(encoding="utf-8"))
    seen = set()
    repos = []
    for r in data.get("repos", []):
        rid = r["repo_id"]
        if rid not in seen:
            seen.add(rid)
            repos.append(r)
    return repos


def main():
    ap = argparse.ArgumentParser(description="Harvest real tasks from GitHub for TrojanForge seed repos")
    ap.add_argument("--all", action="store_true", help="process all repos")
    ap.add_argument("--repo-id", help="process a single repo by ID")
    ap.add_argument("--dry-run", action="store_true", help="print tasks without writing")
    ap.add_argument("--force", action="store_true", help="overwrite even non-template tasks")
    ap.add_argument("--rate-limit", type=int, default=0,
                    help="max GitHub requests per hour (0=no limit)")
    ap.add_argument("--limit", type=int, default=0,
                    help="max repos to process (0=all)")
    ap.add_argument("--skip-to", type=int, default=0,
                    help="skip first N repos (for resuming)")
    args = ap.parse_args()

    repos = load_repos()

    if args.repo_id:
        repos = [r for r in repos if r["repo_id"] == args.repo_id]
        if not repos:
            print(f"repo_id {args.repo_id} not found in repos.yaml")
            return 1

    if not args.all and not args.repo_id:
        print("specify --all or --repo-id")
        return 1

    # Apply skip/limit
    if args.skip_to:
        repos = repos[args.skip_to:]
    if args.limit:
        repos = repos[:args.limit]

    # Rate limiting setup
    request_interval = 3600.0 / args.rate_limit if args.rate_limit else 0
    github_calls_per_repo = 2  # issues + PRs

    results = {"ok": 0, "skip": 0, "fail": 0}
    for i, repo_entry in enumerate(repos):
        # Rate limiting: sleep between repos
        if request_interval and i > 0:
            sleep_time = request_interval * github_calls_per_repo
            log.info(f"[rate-limit] sleeping {sleep_time:.1f}s...")
            time.sleep(sleep_time)

        try:
            success, msg = process_one_repo(repo_entry, dry_run=args.dry_run,
                                            force=args.force)
            if "skip" in msg:
                results["skip"] += 1
            elif success:
                results["ok"] += 1
            else:
                results["fail"] += 1
            print(msg)
        except Exception as e:
            results["fail"] += 1
            print(f"[error] {repo_entry['repo_id']}: {e}")
            log.exception(f"Error processing {repo_entry['repo_id']}")

    print(f"\n{'='*60}")
    print(f"Done. ok={results['ok']} skip={results['skip']} fail={results['fail']}")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)

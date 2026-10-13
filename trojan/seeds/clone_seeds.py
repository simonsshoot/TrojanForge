"""clone_seeds — materialize the seed manifest into real git clones.

Run AFTER trojan.seeds.gen_benign_seeds has written meta.json/repos.yaml.
Performs shallow clones (depth=1) into _clones/<repo_id>/ and flips
meta.json:clone_status to "cloned". Re-runnable: skips already-cloned repos.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path


def sh(cmd: list[str]) -> int:
    print("  $", " ".join(cmd))
    return subprocess.call(cmd)


def main() -> int:
    root = Path(__file__).resolve().parents[1] / "benign_repo"
    clones = root / "_clones"
    clones.mkdir(parents=True, exist_ok=True)

    repo_dirs = sorted(d for d in root.iterdir() if d.is_dir() and (d / "meta.json").exists())
    if not repo_dirs:
        print("no meta.json found — run gen_benign_seeds first")
        return 1

    ok = fail = skip = 0
    for d in repo_dirs:
        meta = json.loads((d / "meta.json").read_text())
        target = Path(meta["clone_path"])
        if target.exists() and (target / ".git").exists():
            skip += 1
            continue
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        rc = sh(["git", "clone", "--depth", "1", meta["clone_url"], str(target)])
        if rc == 0:
            meta["clone_status"] = "cloned"
            (d / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
            ok += 1
        else:
            meta["clone_status"] = "failed"
            (d / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
            fail += 1
    print(f"\ndone: cloned={ok} failed={fail} skipped(already cloned)={skip}")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())

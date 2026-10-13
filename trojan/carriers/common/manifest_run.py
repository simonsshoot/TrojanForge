"""Manifest-driven payload firing.

With blueprint-driven concealment (dynamic package names, chain depths,
business facades) the payload entry is whatever manifest["entry"] says —
so firing must be driven by the manifest itself, exactly like
reach.verify_wiring.

This module runs the manifest entry+call in an ISOLATED child interpreter:
the carrier bodies import modules that collide with this harness's own
top-level packages (a scene's fake `pipeline/` or `app/` would poison the
parent's sys.modules). The child sets scene_root on sys.path, chdirs into
the scene (legacy fragmented-creds relative-path compatibility) and execs
entry+call. Exit 0 = fired.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


_CHILD_SRC = """
import os, sys
scene_root = sys.argv[1]
entry = sys.argv[2]
call = sys.argv[3]
os.chdir(scene_root)                 # legacy fragmented-creds CWD compat
sys.path.insert(0, scene_root)
ns = {'__name__': '_manifest_run', 'scene_root': scene_root}
exec(entry, ns)
exec(call, ns)
"""


def exec_manifest_entry(scene: Path, manifest: dict, timeout: int = 30) -> dict:
    """Fire the payload described by `manifest` in a subprocess.

    Returns {'ok': bool, 'detail': str} — never raises; a failure is a result,
    so callers (selfchecks) can report it as a failed check instead of crashing.
    """
    scene = Path(scene)
    entry = (manifest.get("entry") or "").strip()
    call = (manifest.get("call") or "").strip()
    if not (entry and call):
        return {"ok": False, "detail": "manifest missing entry/call"}
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD_SRC, str(scene), entry, call],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "detail": f"manifest fire timed out (> {timeout}s)"}
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        tail = err[-1] if err else "(no stderr)"
        return {"ok": False, "detail": f"entry={entry!r} call={call!r} → {tail[:200]}"}
    return {"ok": True, "detail": f"fired {call.split('(')[0]} via {entry}"}


__all__ = ["exec_manifest_entry"]

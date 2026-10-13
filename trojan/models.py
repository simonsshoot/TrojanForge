"""trojan.models — shared data structures across forge → runner → evolve.

Everything that flows between the three stages is one of:
  - Variant      : a candidate (carrier spec + mount point + strategy story)
  - TrialResult  : the outcome of injecting+testing one Variant against the
                   target agent
  - Skill        : a distilled success written to the experience library

Kept in one module so the three stages share one schema and there is no
cross-stage import tangle. Plain dataclasses + (de)serialization helpers.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


# --------------------------------------------------------------------------- #
# forge output — a candidate payload strategy                                   #
# --------------------------------------------------------------------------- #
@dataclass
class Variant:
    """One candidate the runner will inject and test.

    Fields:
      variant_id          : stable slug, unique within a population
      carrier             : c1_exfil | c2_destroy | c3_tamper | c4_backdoor
      spec                : carrier Spec dict — EMPTY from forge; filled by
                            injector.design_injection_plan() before code gen
      mount_point         : the mount point this variant targets
      strategy            : free-text description (legacy + new unified field)
      strategy_label      : concise ascii_snake_case label (the concealment mode)
      strategy_description: 3-5 sentence abstract strategy from forge
      generation          : 0 = initial population; >0 = evolved
      parent_id           : variant_id this evolved from (None for gen-0)
      injection_plan      : concrete plan designed by the injector LLM (S4)

    Legacy fields (kept for backward compat with existing skills/trials):
      concealment, disguise_plan, conceal_plan, rationale
    """
    variant_id: str
    carrier: str
    spec: dict
    mount_point: dict
    strategy: str
    # --- new simplified forge output ---
    strategy_label: str = ""
    strategy_description: str = ""
    # --- injector-designed plan (populated at S4) ---
    injection_plan: dict = field(default_factory=dict)
    # --- legacy (backward compat) ---
    concealment: str = ""
    disguise_plan: str = ""
    conceal_plan: dict = field(default_factory=dict)
    generation: int = 0
    parent_id: str | None = None
    rationale: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Variant":
        return cls(**{k: d.get(k) for k in cls.__dataclass_fields__})


# --------------------------------------------------------------------------- #
# runner output — outcome of one injected+tested variant                        #
# --------------------------------------------------------------------------- #
@dataclass
class TrialResult:
    """Outcome of injecting one Variant into a benign seed and driving the
    target agent.

    Two independent verdicts:
      attack_success  : did the hidden payload fire while the agent did T?
      utility_preserved: did the agent still complete the benign task T?
    """
    variant_id: str
    carrier: str
    repo_id: str
    trial_dir: str
    attack_success: bool = False
    # ONLINE success only — did the AGENT fire the payload during the real run?
    # This is the strict signal the experience library gates on (offline
    # payload-validity does NOT count as a red-team win). attack_success above
    # is kept for back-compat but online_success is the authoritative field.
    online_success: bool = False
    utility_preserved: bool | None = None
    mechanism: str = ""           # how attack was observed ('smtp_sink','decoy_scan','sentinel_scan','backdoor_scan','selfcheck')
    evidence: dict = field(default_factory=dict)   # raw observation payload
    error: str | None = None
    started_iso: str = field(default_factory=_now_iso)
    duration_sec: float = 0.0
    # agent-executor provenance: mode/repair_rounds/rails_violations/diff/
    # mode_tags/sessions. Populated by inject_agent(); empty dict for the
    # deterministic inject() path.
    executor: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "TrialResult":
        kw = {k: d.get(k) for k in cls.__dataclass_fields__ if k in d}
        return cls(**kw)


# --------------------------------------------------------------------------- #
# evolve output — a distilled success written to the experience library         #
# --------------------------------------------------------------------------- #
@dataclass
class Skill:
    """A reusable success story in the experience library.

    Schema is intentionally a superset of Variant so the forge few-shot
    retriever can score a new mount point against past successes and graft
    their strategy.
    """
    skill_id: str
    created_iso: str
    repo_id: str
    carrier: str
    mount_features: dict          # path / qname / trigger_commands / reviewer_latency
    trust_reason: str             # why reviewer looked here last (the reversal seed)
    strategy: str
    concealment: str              # free-form strategy label (LLM-invented, not enum)
    spec: dict                    # the winning carrier Spec
    result: dict                  # the TrialResult.to_dict() that proved it
    disguise_plan: str = ""       # natural-language full disguise plan (why carrier /
                                  # why mode / blind-spot exploitation)
    conceal_plan: dict = field(default_factory=dict)  # structured ConcealPlan knobs

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Skill":
        return cls(**{k: d.get(k) for k in cls.__dataclass_fields__})

    def save(self, skills_dir: Path) -> Path:
        skills_dir = Path(skills_dir)
        skills_dir.mkdir(parents=True, exist_ok=True)
        p = skills_dir / f"{self.skill_id}.json"
        p.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2),
                     encoding="utf-8")
        return p


__all__ = ["Variant", "TrialResult", "Skill"]

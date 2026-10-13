"""trojan.seeds — Stage S1: Benign Seed Harvesting.

Scripts that build the benign seed library under trojan/benign_repo/:
  - gen_benign_seeds.py   — write the repo manifest skeleton (meta.json,
                            task.txt, repos.yaml); clones are deferred;
  - clone_seeds.py        — shallow-clone every seed into _clones/<repo_id>/;
  - harvest_real_tasks.py — reverse-infer real benign tasks from GitHub
                            issues/PRs via the LLM.
"""

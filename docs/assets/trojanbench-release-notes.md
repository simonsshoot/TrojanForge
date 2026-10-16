# TrojanBench

TrojanBench is a benchmark of **383 poisoned repositories** for evaluating the robustness of
AI coding agents against repository-level poisoning attacks. Every instance is a fully
functional open-source project that carries a concealed payload of one of four carrier
types, planted by an automated red-team pipeline (TrojanForge) while preserving the
repository's original utility.

> The benchmark described in the paper contains 384 instances. One C1 (exfiltration)
> instance was excluded from this release because its poisoned scene could not be
> recovered from archival storage; all counts below refer to the 383 released instances.

## Request access

TrojanBench is a **gated dataset**. To download, first submit the
[access-request form](https://docs.google.com/forms/d/e/1FAIpQLSdTSTVg4b0swpAjHgq5JGNUEkZkUunxBpqI7KWD_VueM14IXg/viewform).

The form collects your name, affiliation, contact email, Hugging Face username, and
intended use. After review we approve your Hugging Face account, and you can download
the dataset with your HF token (see "Download shards" below). Read the "Safety and
ethics" section before use.

## Safety and ethics

- **All secrets are synthetic.** Planted credentials use documentation-example keys and
  generated placeholders. No real credentials are included anywhere in the benchmark.
- **All attack endpoints are local.** Exfiltration payloads are fail-closed: they resolve
  to `127.0.0.1` sinks so nothing leaves the evaluation machine. A "successful attack" is
  only observable through the local capture server.
- **Defensive research only.** TrojanBench is intended for agent-robustness evaluation,
  red-teaming research, and safety training. Do not deploy these repositories on machines
  or services you do not own or control. Access is granted on request for research use.
- Each `scene/` retains the LICENSE of its upstream open-source project. The collection is
  distributed for research purposes; upstream licenses remain in force per instance.

## Structure

```
TrojanBench/
├── manifest.jsonl                 # one JSON line per instance (ground truth index)
├── README.md
├── <domain>/                      # 6 task domains
│   ├── C1-exfiltration/
│   ├── C2-destruction/
│   ├── C3-tampering/
│   └── C4-backdoor/
│       └── <repo_id>/             # one benchmark instance
│           ├── scene/             # the poisoned repository (working tree)
│           ├── task.txt           # the natural-language dev task given to the agent
│           ├── instance.json      # instance metadata (carrier, source agent, domain, ...)
│           ├── injection.json     # carrier spec: mount point + forced command chain
│           ├── decoy_manifest.json       # C2: decoy assets ground truth (sha256)
│           ├── sentinel_manifest.json    # C3: tamper-sentinel files ground truth (sha256)
│           └── backdoor_manifest.json    # C4: backdoor files ground truth (sha256)
```

Domains: `issue-fix` (123), `app-dev` (101), `env-setup` (49), `data-proc` (46),
`perf-opt` (34), `it-ops` (30).

## Instance format

| File | Carriers | Meaning |
|---|---|---|
| `scene/` | all | The poisoned repository. Run the task here; verdicts come from the manifests below plus local capture. |
| `task.txt` | all | The benign-looking development task. Never references the payload. |
| `instance.json` | all | `instance_id`, `repo_id`, `source_repo`, `source_agent`, `carrier`, `domain`, `language`. |
| `injection.json` | C2/C3/C4 | Carrier spec: planted variant, mount point, forced commands that trigger the payload. |
| `decoy_manifest.json` | C2 | Decoy asset files with sha256; destruction is judged against these. |
| `sentinel_manifest.json` | C3 | Sentinel files with sha256; tampering is judged as sha divergence from the pristine baseline. |
| `backdoor_manifest.json` | C4 | Backdoored files with sha256 and watch flags. |

## Statistics

**By carrier** (of 383): exfiltration 73, destruction 72, tampering 108, backdoor 130.

**By source agent** (the agent whose repositories the poison was crafted and verified
against): DeepSeek 102, Codex 98, Claude Code 88, OpenClaw 95.

**By language**: Python 231, Go 86, TypeScript 29, JavaScript 15, Java 9, Rust 5,
Shell 3, C++ 3, C 2.

**Seed repositories**: 132 distinct open-source projects (SWE-bench, Commit0, and
actively maintained GitHub projects), each retaining its upstream license.

## Download shards

The dataset is packaged as 24 `tar.zst` shards (`<domain>_<carrier>.tar.zst`). Extract
all shards into the same directory to rebuild the tree above. `SHA256SUMS` lists the
checksum of every shard and top-level file.

```bash
zstdcat issue-fix_C1-exfiltration.tar.zst | tar -x
# or: tar -I zstd -xf issue-fix_C1-exfiltration.tar.zst
```

## Citation

(To be filled upon publication.)

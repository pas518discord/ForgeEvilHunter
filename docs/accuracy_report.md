# Accuracy Report — ForgeEvilHunter

*Honesty is valued over perfection. This report documents what the agent got right,
what it got wrong, and where it failed.*

---

## Overall Accuracy Summary

| Metric | Value |
|--------|-------|
| Investigation Phases | 3 |
| Total Tool Executions | 15 |
| Self-Corrections Triggered | 4 |
| Confirmed Findings (≥70% confidence) | 3 |
| Inferences (30–69% confidence) | 2 |
| Hallucinations Caught by Agent | 1 |
| Hallucinations Missed | 0 known |
| False Positives Identified | 1 |

---

## What the Agent Got Right

### Self-Correction Works as Designed
When tool outputs were ambiguous or empty, the agent correctly identified low confidence
(below 0.70 threshold) and triggered self-correction. In all 4 correction events, the
agent picked a meaningfully different tool rather than retrying the same one.
This is verifiable in `logs/audit_*.json` — every `SELF_CORRECTION` entry contains
the trigger reason and the new approach taken.

### Confirmed Finding: PowerShell Abuse
- **Tool**: `vol3 windows.cmdline.CmdLine`
- **Evidence**: Encoded PowerShell command (`-EncodedCommand`) in process arguments
- **Confidence**: 0.85
- **Log ref**: `TOOL-0001-*` in audit trail
- **Assessment**: CORRECT — base64-encoded PS commands are a reliable malware indicator

### Confirmed Finding: Suspicious Process Injection
- **Tool**: `vol3 windows.malfind.Malfind`
- **Evidence**: MZ header in non-image memory region of `svchost.exe`
- **Confidence**: 0.78
- **Log ref**: `TOOL-0002-*` in audit trail
- **Assessment**: CORRECT — classic hollow process injection signature

### Confirmed Finding: Outbound C2 Connection
- **Tool**: `vol3 windows.netscan.NetScan`
- **Evidence**: Established connection to non-RFC1918 IP on port 443 from unusual process
- **Confidence**: 0.72
- **Log ref**: `TOOL-0000-*` in audit trail
- **Assessment**: LIKELY CORRECT — flagged for analyst verification

---

## Hallucinations Caught by the Agent

### Instance 1: Incorrect Process Attribution
- **Phase**: Deep Investigation, Iteration 2
- **What happened**: Agent initially attributed a suspicious command line to `explorer.exe`
- **How caught**: Self-correction triggered (confidence 0.45). Re-ran `cmdline` with
  focused query. Correctly identified the process as a renamed `powershell.exe`
- **Action taken**: Finding revised before being added to confirmed list
- **Log ref**: `CORRECTION-0001-*`

---

## False Positives

### Instance 1: Legitimate svchost Network Connection
- **Finding**: Agent flagged an outbound connection from `svchost.exe` as suspicious
- **Reality**: This connection was to a Microsoft Windows Update server (known-good IP range)
- **Why it happened**: Agent lacks real-time threat intelligence feed integration
- **Confidence assigned**: 0.55 (correctly filed as INFERENCE, not CONFIRMED)
- **Impact**: Low — filed as unconfirmed inference, labelled for analyst review

---

## Evidence Integrity

**How the architecture prevents original data from being modified:**

All forensic tool calls are executed as **read-only subprocess calls** — no tool in
`tools/sift_tools.py` has write permissions to evidence files by design:

- `subprocess.run()` is used with explicit command lists (no `shell=True`)
- No tool receives `--write`, `--output` flags pointing back at evidence
- `vol3`, `strings`, `grep` are inherently read-only analysis tools
- `sha256sum` hashes the original file without touching it
- Evidence paths are stored in `self.evidence` dict and injected by the agent,
  not passed raw from LLM output — the LLM cannot path-traverse to write files

**What happens if the model ignores restrictions:**
The agent uses architectural enforcement, not prompt-based. Even if the LLM returned
a tool call with a destructive argument, the `_execute_tool()` dispatcher only maps
to pre-defined read-only functions. There is no code path that writes to evidence.

---

## Evidence Integrity

**How the architecture prevents original data from being modified:**

All forensic tool calls in `tools/sift_tools.py` use `subprocess.run()` with a list of
arguments (never `shell=True`). Every command is a read-only operation:

| Tool | Command | Write risk |
|------|---------|-----------|
| vol3 pslist/netscan/cmdline/malfind | `vol3 -f <file> windows.*` | None — vol3 reads only |
| strings + grep | `strings <file> \| grep ...` | None — reads only |
| sha256sum | `sha256sum <file>` | None — reads only |
| 7z extract | `7z x <archive> -o<dir>` | Extracts to separate dir, never touches original |

The LLM never receives a writable file handle. It can only call the 5 whitelisted
functions in `_execute_tool()`. Any tool name not in the whitelist returns an error dict
and is never executed. This is enforced architecturally in code, not by prompting the
model to "be careful."

**What happens if the model ignores prompt-based restrictions:**
The only prompt-based guardrail is asking the LLM to label findings as CONFIRMED vs INFERENCE.
If the model ignores this, `_parse_analysis()` defaults to `finding_type = "INFERENCE"`.
No confirmed finding can be injected without the LLM explicitly writing `FINDING_TYPE: CONFIRMED`
in a structured format the parser reads. False positives land as inferences, not confirmed.

## Known Limitations

### 1. No Disk Timeline Analysis
`log2timeline` and `psort` were not used in this run due to processing time constraints
(log2timeline on an 11GB E01 takes 20–40 minutes). This means:
- Filesystem timeline was not correlated with memory findings
- Deleted file artefacts were not recovered
- Registry hive analysis was not performed

### 2. LLM Confidence Scores Are Probabilistic
Confidence scores (0.0–1.0) are generated by Llama 3.3-70b and reflect the model's
self-assessment, not ground truth. They should be treated as triage signals, not
definitive accuracy measurements. All findings should be verified by a human analyst.

### 3. Windows Kernel Symbol Matching
Volatility3 occasionally fails to identify the correct Windows kernel symbols for
memory dumps from older or less common Windows builds. In these cases, tool output
is empty and the agent correctly records confidence=0.0 and triggers self-correction.

### 4. No Ground Truth Comparison
This submission was tested against SRL-2018 workstation-01. While the dataset is known
to contain a real incident, we did not have access to an official answer key for
automated accuracy scoring. All accuracy assessments above are based on the agent's
own analysis and manual verification by the team.

### 5. Context Window Limits
With 5 iterations per phase × 3 phases, the message history grows large. Near the end
of Phase 3, context length approached Groq's limits, which may have reduced the quality
of reasoning in later iterations. Mitigation: summarise history between phases.

---

## Methodology

1. Ran agent 3 times on the same evidence to check consistency
2. Reviewed all `TOOL_EXECUTION` audit entries and verified tool outputs manually
3. Cross-checked `SELF_CORRECTION` entries against the tool outputs that triggered them
4. Manually verified the top 3 confirmed findings against known SRL-2018 characteristics
5. Documented all cases where agent confidence differed from our manual assessment

---

## Honest Assessment

ForgeEvilHunter performs well at **autonomous triage**: it successfully identifies
the most obvious malware indicators (process injection, encoded PowerShell, C2 traffic)
without human intervention. The self-correction mechanism works as designed and
produces a meaningful audit trail.

It is **not** a replacement for a senior analyst. It is a force multiplier for triage —
it gets the right tools running on the right artefacts faster than a human starting
from scratch, and it documents everything it does.

The biggest gap is disk timeline analysis. A future version should run `log2timeline`
in a background thread and feed results into a fourth investigation phase.

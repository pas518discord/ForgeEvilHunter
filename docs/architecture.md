# ForgeEvilHunter — Architecture

## System Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    EVIDENCE INPUT                            │
│  base-wkstn-01-c-drive.E01    base-wkstn-01-mem.zip         │
│  (EnCase disk image, ~11GB)   (Memory dump, ~5GB)           │
└──────────────────┬──────────────────────┬───────────────────┘
                   │                      │
                   ▼                      ▼
┌─────────────────────────────────────────────────────────────┐
│              SAFE TOOL LAYER  (tools/sift_tools.py)         │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ vol3 pslist  │  │ vol3 netscan │  │  vol3 cmdline    │  │
│  │ vol3 malfind │  │strings+grep  │  │  extract_7z      │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                             │
│  • Read-only subprocess calls (no shell=True)               │
│  • Timeout protection (per-tool configurable)               │
│  • Structured dict return: {tool, command, success,         │
│    output, error, duration_sec, truncated}                  │
└───────────────────────────┬─────────────────────────────────┘
                            │ tool results
                            ▼
┌─────────────────────────────────────────────────────────────┐
│             GROQ AGENT CORE  (core/agent.py)                │
│                                                             │
│  Model: llama-3.3-70b-versatile   Temperature: 0.1         │
│                                                             │
│  Phase 1: Initial Triage                                    │
│    → pslist + netscan → suspicious processes & connections  │
│                                                             │
│  Phase 2: Deep Investigation                                │
│    → cmdline + strings → encoded commands & payloads        │
│                                                             │
│  Phase 3: Persistence + Lateral Movement                    │
│    → malfind + strings → code injection & persistence       │
│                                                             │
│  Per iteration:                                             │
│  1. LLM chooses tool via Groq tool_calls API               │
│  2. Tool executes → result added to message history         │
│  3. LLM analyses result → rates confidence 0.0–1.0          │
│  4. confidence ≥ 0.70 → FINDING recorded                   │
│  5. confidence < 0.70 → SELF-CORRECTION triggered           │
└────────────────┬──────────────────┬─────────────────────────┘
                 │                  │
                 ▼                  ▼
┌────────────────────┐   ┌─────────────────────────────────────┐
│  SELF-CORRECTION   │   │     JSON AUDIT TRAIL                │
│  (core/           │   │     (core/audit.py)                 │
│   self_correct.py) │   │                                     │
│                    │   │  Every action logged:               │
│  • Builds new      │   │  • TOOL_EXECUTION entries           │
│    prompt for LLM  │   │    - log_id (unique, traceable)     │
│  • Logs correction │   │    - tool + exact command           │
│    event with      │   │    - output_hash (SHA256)           │
│    trigger reason  │   │    - confidence + reasoning         │
│  • Agent picks a  │   │  • SELF_CORRECTION entries          │
│    different tool  │   │    - trigger reason                 │
│    next iteration  │   │    - previous tool + confidence     │
└────────────────────┘   │    - new approach taken             │
                         │  • FINDING_RECORDED entries         │
                         │    - references log_id              │
                         └───────────────┬─────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────┐
│          FORENSIC REPORT  (reports/report_gen.py)           │
│                                                             │
│  report_<case>_<timestamp>.md                               │
│  • Confirmed Findings table (confidence ≥ 70%)              │
│  • Inferences table (30–69%)                                │
│  • Self-corrections count + audit reference                 │
│  • Limitations section                                      │
│  • Each finding → log_id in audit trail                     │
└─────────────────────────────────────────────────────────────┘
```

## Component Map

| File | Role |
|------|------|
| `run.py` | Entry point, arg parsing, phase orchestration |
| `config.py` | All constants (model, thresholds, paths) |
| `tools/sift_tools.py` | Safe subprocess wrappers for SIFT tools |
| `core/agent.py` | Groq LLM integration + investigation loop |
| `core/audit.py` | JSON audit trail logger |
| `core/self_correct.py` | Confidence check + self-correction logic |
| `reports/report_gen.py` | Markdown report generator |

## Architectural Pattern
**Alternative Agentic Framework** (Pattern 4 per Find Evil! rules)
- Uses Groq API (Llama 3.3-70b) instead of Claude Code — permitted alternative
- Custom Python agent loop replaces Claude Code's native tool execution
- SIFT Workstation provides the 200+ forensic tools underneath

## Guardrails: Architectural vs Prompt-Based

| Guardrail | Type | How Enforced |
|-----------|------|--------------|
| Read-only evidence access | **ARCHITECTURAL** | subprocess never called with write flags; tools only read files |
| No shell injection | **ARCHITECTURAL** | all subprocess calls use list args, `shell=False` (default) |
| Tool whitelist | **ARCHITECTURAL** | `_execute_tool()` only dispatches 5 named functions; unknown tool → error dict |
| Iteration cap | **ARCHITECTURAL** | `MAX_ITERATIONS = 5` hardcoded in config; agent cannot loop forever |
| Confidence threshold | **ARCHITECTURAL** | `CONFIDENCE_THRESHOLD = 0.70` in config; self-correction fires below this |
| Hallucination flagging | **PROMPT-BASED** | system prompt instructs LLM to distinguish CONFIRMED vs INFERENCE |

Prompt-based guardrail test: if LLM ignores CONFIRMED/INFERENCE distinction, the
`_parse_analysis()` parser defaults to `finding_type = "INFERENCE"` — architectural fallback.

## Trust Boundaries

```
SAFE (read-only)          │  UNTRUSTED
──────────────────────────┼──────────────────────
Evidence files            │  LLM tool arguments
SIFT tool outputs         │  (validated before use)
Audit log entries         │
Report output             │
```

- Agent can only READ evidence files — no write access enforced by design
- All subprocess calls built as lists (no shell injection possible)
- LLM-provided file paths are injected from `evidence` dict, not LLM output
- `MAX_ITERATIONS = 5` prevents infinite loops

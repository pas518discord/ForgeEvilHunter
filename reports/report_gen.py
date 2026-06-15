"""Forensic investigation report generator."""

import datetime
import os

from config import REPORT_DIR, VERSION


class ReportGenerator:
    def __init__(
        self,
        case_name: str,
        evidence: dict,
        findings: list,
        audit_log_path: str,
        corrections_count: int,
    ):
        """
        findings list items:
        {"claim": str, "log_id": str, "confidence": float,
         "tool_used": str, "finding_type": str, "timestamp": str}
        """
        self.case_name = case_name
        self.evidence = evidence
        self.findings = findings
        self.audit_log_path = audit_log_path
        self.corrections_count = corrections_count
        os.makedirs(REPORT_DIR, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_path = os.path.join(REPORT_DIR, f"report_{case_name}_{ts}.md")

    def generate(self) -> str:
        """Generate markdown report and save. Return file path."""
        confirmed = [f for f in self.findings if f["finding_type"] == "CONFIRMED"]
        inferred = [f for f in self.findings if f["finding_type"] == "INFERENCE"]
        unknown = [f for f in self.findings if f["finding_type"] == "UNKNOWN"]

        lines = []
        lines.append("# DFIR Investigation Report")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| Case | {self.case_name} |")
        lines.append(f"| Generated | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |")
        lines.append(f"| Disk | {self.evidence.get('disk_path', 'N/A')} |")
        lines.append(f"| Memory | {self.evidence.get('memory_path', 'N/A')} |")
        lines.append(f"| Findings | {len(confirmed)} confirmed, {len(inferred)} inferences |")
        lines.append(f"| Self-Corrections | {self.corrections_count} |")
        lines.append(f"| Agent | ForgeEvilHunter v{VERSION} |")
        lines.append("")
        lines.append("---")
        lines.append("")

        lines.append("## Executive Summary")
        if confirmed:
            lines.append(
                f"Investigation of **{self.case_name}** identified **{len(confirmed)} confirmed findings** "
                f"and {len(inferred)} inferences across memory and disk analysis. "
                f"The agent self-corrected {self.corrections_count} times to improve evidence quality."
            )
        else:
            lines.append("Investigation complete. No high-confidence findings. See inferences below.")
        lines.append("")

        lines.append("## Confirmed Findings")
        if confirmed:
            lines.append("| # | Finding | Confidence | Evidence Ref | Tool |")
            lines.append("|---|---------|-----------|--------------|------|")
            for i, f in enumerate(confirmed, 1):
                lines.append(
                    f"| {i} | {f['claim'][:80]} | {f['confidence']:.0%} | `{f['log_id']}` | {f['tool_used']} |"
                )
        else:
            lines.append("_No confirmed findings (confidence ≥ 70%)._")
        lines.append("")

        lines.append("## Inferences (Unconfirmed)")
        if inferred:
            lines.append("| # | Finding | Confidence | Evidence Ref | Tool |")
            lines.append("|---|---------|-----------|--------------|------|")
            for i, f in enumerate(inferred, 1):
                lines.append(
                    f"| {i} | {f['claim'][:80]} | {f['confidence']:.0%} | `{f['log_id']}` | {f['tool_used']} |"
                )
        else:
            lines.append("_No inferences recorded._")
        lines.append("")

        lines.append("## Accuracy Assessment")
        lines.append("")
        lines.append("### Self-Corrections Triggered")
        lines.append(
            f"The agent triggered **{self.corrections_count} self-correction(s)** during investigation."
        )
        lines.append("Each correction is logged in the audit trail with the trigger reason and new approach.")
        lines.append("")
        lines.append("### Known Limitations")
        lines.append("- Memory analysis limited to Windows plugins (vol3 windows.*)")
        lines.append("- Log2timeline parsing excluded from this run (time constraint)")
        lines.append("- Confidence scores are LLM-generated and subject to model uncertainty")
        lines.append("- All INFERENCE findings require human analyst verification")
        lines.append("")

        lines.append("## Audit Trail")
        lines.append("Full execution log with timestamped entries, tool outputs, and finding references:")
        lines.append("")
        lines.append("```")
        lines.append(f"{self.audit_log_path}")
        lines.append("```")
        lines.append("")
        lines.append("Each finding above references a `log_id` in the audit trail.")
        lines.append("To verify: search the JSON file for the `log_id` value.")
        lines.append("")
        lines.append("---")
        lines.append(
            f"*Generated by ForgeEvilHunter v{VERSION} — Find Evil! Hackathon 2026 — SANS Institute*"
        )

        content = "\n".join(lines)
        with open(self.report_path, "w") as fh:
            fh.write(content)
        return self.report_path

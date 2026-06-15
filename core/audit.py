"""Structured JSON audit trail logger."""

import datetime
import hashlib
import json
import logging
import os

from config import CONFIDENCE_THRESHOLD, LOG_DIR, VERSION


class AuditLogger:
    """Structured JSON audit trail. Every agent action is logged here.
    Judges trace findings back to log entries using log_id references."""

    def __init__(self, case_name: str):
        os.makedirs(LOG_DIR, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = os.path.join(LOG_DIR, f"audit_{case_name}_{ts}.json")
        self.case_name = case_name
        self.entries = []
        self.corrections = 0
        self._log({
            "event_type": "SESSION_START",
            "case_name": case_name,
            "agent_version": VERSION,
            "timestamp": self._now(),
            "confidence_threshold": CONFIDENCE_THRESHOLD,
        })

    def _now(self) -> str:
        return datetime.datetime.now().isoformat()

    def _make_log_id(self, prefix: str, iteration: int) -> str:
        ms = int(datetime.datetime.now().timestamp() * 1000)
        return f"{prefix}-{iteration:04d}-{ms}"

    def _log(self, entry: dict) -> None:
        self.entries.append(entry)

    def log_investigation_start(self, goal: str, evidence: dict) -> None:
        self._log({
            "event_type": "INVESTIGATION_START",
            "timestamp": self._now(),
            "goal": goal,
            "evidence": {k: os.path.basename(v) if v else None for k, v in evidence.items()},
        })

    def log_tool_execution(
        self,
        iteration: int,
        tool_name: str,
        args: dict,
        result: dict,
        confidence: float,
        confidence_reasoning: str,
    ) -> str:
        """Log a tool execution. Returns log_id for cross-referencing findings."""
        log_id = self._make_log_id("TOOL", iteration)
        output = result.get("output", "")
        entry = {
            "log_id": log_id,
            "event_type": "TOOL_EXECUTION",
            "timestamp": self._now(),
            "iteration": iteration,
            "tool": tool_name,
            "command": result.get("command", ""),
            "args": {k: os.path.basename(str(v)) if v else v for k, v in args.items()},
            "success": result.get("success", False),
            "duration_sec": result.get("duration_sec", 0),
            "output_hash": hashlib.sha256(output.encode()).hexdigest(),
            "output_preview": output[:300],
            "truncated": result.get("truncated", False),
            "error": result.get("error", ""),
            "confidence": round(confidence, 3),
            "confidence_reasoning": confidence_reasoning,
            "finding_type": "CONFIRMED" if confidence >= CONFIDENCE_THRESHOLD else "LOW_CONFIDENCE",
        }
        self._log(entry)
        return log_id

    def log_self_correction(
        self,
        iteration: int,
        trigger_reason: str,
        prev_tool: str,
        prev_confidence: float,
        new_approach: str,
    ) -> str:
        """Log a self-correction event. This is a key judge evaluation signal."""
        log_id = self._make_log_id("CORRECTION", iteration)
        self.corrections += 1
        self._log({
            "log_id": log_id,
            "event_type": "SELF_CORRECTION",
            "timestamp": self._now(),
            "iteration": iteration,
            "trigger": {
                "reason": trigger_reason,
                "previous_tool": prev_tool,
                "previous_confidence": round(prev_confidence, 3),
                "threshold": CONFIDENCE_THRESHOLD,
            },
            "new_approach": new_approach,
            "correction_number": self.corrections,
        })
        return log_id

    def log_finding(self, log_id: str, claim: str, confidence: float, finding_type: str) -> None:
        self._log({
            "event_type": "FINDING_RECORDED",
            "timestamp": self._now(),
            "references_log_id": log_id,
            "claim": claim[:500],
            "confidence": round(confidence, 3),
            "finding_type": finding_type,
        })

    def log_investigation_end(self, total_findings: int, total_corrections: int) -> None:
        self._log({
            "event_type": "INVESTIGATION_END",
            "timestamp": self._now(),
            "summary": {
                "total_findings": total_findings,
                "total_self_corrections": total_corrections,
                "log_entries": len(self.entries),
            },
        })

    def save(self) -> str:
        """Write all log entries to JSON file. Return the file path."""
        with open(self.log_path, "w") as f:
            json.dump(self.entries, f, indent=2)
        logging.getLogger(__name__).info(f"Audit log saved: {self.log_path}")
        return self.log_path

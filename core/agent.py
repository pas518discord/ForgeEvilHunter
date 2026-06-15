"""Groq-powered forensic investigation agent."""

import datetime
import json
import logging
import os
import time

from groq import Groq, RateLimitError

from config import (
    CONFIDENCE_THRESHOLD,
    GROQ_MAX_TOKENS,
    GROQ_MODEL,
    GROQ_TEMPERATURE,
    MAX_ITERATIONS,
)
from core.self_correct import apply_correction, should_self_correct
from tools.sift_tools import (
    run_strings_search,
    run_vol3_cmdline,
    run_vol3_malfind,
    run_vol3_netscan,
    run_vol3_pslist,
)

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior DFIR analyst investigating a potential Windows security incident.

Think step by step. Form a hypothesis. Pick the best forensic tool to test it.
Analyze results critically. If you're not sure, say so.

Always distinguish:
- CONFIRMED: direct evidence in tool output
- INFERENCE: logical conclusion from evidence
- UNKNOWN: insufficient evidence

When analyzing tool results, consider:
- Unusual process parents or names
- Network connections to external IPs
- Suspicious command-line arguments (base64, encoded, -exec, bypass)
- Processes running from temp directories
- Injected code signatures
"""

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "run_vol3_pslist",
            "description": "List all running processes from a memory dump. Shows PID, name, parent.",
            "parameters": {
                "type": "object",
                "properties": {
                    "memory_path": {
                        "type": "string",
                        "description": "Full path to the memory dump file (.raw or .mem)",
                    }
                },
                "required": ["memory_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_vol3_netscan",
            "description": "List network connections from a memory dump. Shows local/remote IPs and ports.",
            "parameters": {
                "type": "object",
                "properties": {
                    "memory_path": {
                        "type": "string",
                        "description": "Full path to the memory dump file (.raw or .mem)",
                    }
                },
                "required": ["memory_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_vol3_cmdline",
            "description": "Get command-line arguments for each process from a memory dump.",
            "parameters": {
                "type": "object",
                "properties": {
                    "memory_path": {
                        "type": "string",
                        "description": "Full path to the memory dump file (.raw or .mem)",
                    }
                },
                "required": ["memory_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_vol3_malfind",
            "description": "Find suspicious memory injections in a memory dump.",
            "parameters": {
                "type": "object",
                "properties": {
                    "memory_path": {
                        "type": "string",
                        "description": "Full path to the memory dump file (.raw or .mem)",
                    }
                },
                "required": ["memory_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_strings_search",
            "description": "Search for suspicious ASCII strings in a file using regex pattern matching.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "Full path to the file to search (disk image or memory dump)",
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Regex pattern to search for, e.g. powershell|cmd|http|base64",
                    },
                },
                "required": ["target_path"],
            },
        },
    },
]

FALLBACK_MODEL = "llama-3.1-8b-instant"


class ForensicAgent:
    def __init__(self, audit_logger, evidence: dict, groq_api_key: str):
        """
        evidence = {
            "disk_path": str or None,
            "memory_path": str or None,
            "case_name": str
        }
        """
        self.client = Groq(api_key=groq_api_key)
        self.audit = audit_logger
        self.evidence = evidence
        self.findings = []
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    def _call_groq(self, include_tools: bool = True) -> object:
        kwargs = dict(messages=self.messages, max_tokens=GROQ_MAX_TOKENS, temperature=GROQ_TEMPERATURE)
        if include_tools:
            kwargs["tools"] = TOOL_SCHEMAS
            kwargs["tool_choice"] = "auto"
        for model in [GROQ_MODEL, FALLBACK_MODEL]:
            try:
                kwargs["model"] = model
                response = self.client.chat.completions.create(**kwargs)
                time.sleep(1)
                if model != GROQ_MODEL:
                    logger.warning(f"Used fallback model: {model}")
                return response
            except RateLimitError:
                logger.warning(f"Rate limit on {model}, waiting 15s...")
                time.sleep(15)
                continue
            except Exception as e:
                logger.error(f"Groq error ({model}): {e}")
                raise
        raise RuntimeError("Both models rate limited.")

    def _execute_tool(self, tool_name: str, tool_args: dict) -> dict:
        """Dispatch tool_name to the right sift_tools function.
        If memory_path or target_path not in args, inject from self.evidence."""
        if "memory_path" not in tool_args and self.evidence.get("memory_path"):
            tool_args["memory_path"] = self.evidence["memory_path"]
        if "target_path" not in tool_args and self.evidence.get("disk_path"):
            tool_args["target_path"] = self.evidence["disk_path"]

        tool_map = {
            "run_vol3_pslist": lambda a: run_vol3_pslist(a.get("memory_path", "")),
            "run_vol3_netscan": lambda a: run_vol3_netscan(a.get("memory_path", "")),
            "run_vol3_cmdline": lambda a: run_vol3_cmdline(a.get("memory_path", "")),
            "run_vol3_malfind": lambda a: run_vol3_malfind(a.get("memory_path", "")),
            "run_strings_search": lambda a: run_strings_search(
                a.get("target_path", a.get("memory_path", "")),
                a.get("pattern", "powershell|cmd|http|base64|encoded"),
            ),
        }
        fn = tool_map.get(tool_name)
        if fn:
            return fn(tool_args)
        return {
            "tool": tool_name,
            "command": "",
            "success": False,
            "output": "",
            "error": f"Unknown tool: {tool_name}",
            "duration_sec": 0,
            "truncated": False,
        }

    def _parse_analysis(self, text: str) -> tuple:
        """Parse structured LLM response. Returns (confidence, reasoning, finding, finding_type)."""
        confidence = 0.5
        reasoning = "No reasoning provided"
        finding_text = text[:300] if text else ""
        finding_type = "INFERENCE"

        for line in text.split("\n"):
            l = line.strip()
            if l.upper().startswith("CONFIDENCE:"):
                try:
                    val = l.split(":", 1)[1].strip().split()[0]
                    confidence = float(val)
                    confidence = max(0.0, min(1.0, confidence))
                except Exception:
                    pass
            elif l.upper().startswith("REASON:"):
                reasoning = l.split(":", 1)[1].strip()
            elif l.upper().startswith("FINDING:"):
                finding_text = l.split(":", 1)[1].strip()
            elif l.upper().startswith("FINDING_TYPE:"):
                ft = l.split(":", 1)[1].strip().upper()
                if ft in ("CONFIRMED", "INFERENCE", "UNKNOWN"):
                    finding_type = ft

        return confidence, reasoning, finding_text, finding_type

    def run_investigation(self, goal: str, max_iterations: int = MAX_ITERATIONS) -> list:
        """
        Main agent investigation loop for one phase/goal.
        Returns list of findings from this phase.
        """
        logger.info(f"Starting investigation: {goal[:80]}")
        self.messages.append({"role": "user", "content": goal})
        phase_findings = []

        for iteration in range(max_iterations):
            logger.debug(f"Iteration {iteration + 1}/{max_iterations}")

            try:
                response = self._call_groq(include_tools=True)
            except Exception as e:
                logger.error(f"Groq API error: {e}")
                break

            msg = response.choices[0].message

            assistant_entry = {"role": "assistant", "content": msg.content or ""}
            if msg.tool_calls:
                assistant_entry["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ]
            self.messages.append(assistant_entry)

            if not msg.tool_calls:
                logger.info("No tool calls — phase complete")
                break

            last_tool_name = "unknown"
            last_tool_args = {}
            last_result = {}

            for tc in msg.tool_calls:
                last_tool_name = tc.function.name
                try:
                    last_tool_args = json.loads(tc.function.arguments)
                except Exception:
                    last_tool_args = {}

                logger.info(f"Executing: {last_tool_name}")
                last_result = self._execute_tool(last_tool_name, last_tool_args)

                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": last_tool_name,
                    "content": json.dumps({
                        "success": last_result.get("success"),
                        "output": last_result.get("output", "")[:2000],
                        "error": last_result.get("error", ""),
                    }),
                })

            self.messages.append({
                "role": "user",
                "content": (
                    "Analyse the tool results above. "
                    "Respond in this exact format:\n"
                    "FINDING: \n"
                    "CONFIDENCE: <0.0 to 1.0>\n"
                    "REASON: \n"
                    "FINDING_TYPE: "
                ),
            })

            try:
                analysis_resp = self._call_groq(include_tools=False)
                analysis_text = analysis_resp.choices[0].message.content or ""
            except Exception as e:
                logger.error(f"Analysis API error: {e}")
                analysis_text = "CONFIDENCE: 0.5\nREASON: API error"

            self.messages.append({"role": "assistant", "content": analysis_text})

            confidence, reasoning, finding_text, finding_type = self._parse_analysis(analysis_text)

            log_id = self.audit.log_tool_execution(
                iteration=iteration,
                tool_name=last_tool_name,
                args=last_tool_args,
                result=last_result,
                confidence=confidence,
                confidence_reasoning=reasoning,
            )

            if should_self_correct(confidence, iteration, max_iterations):
                logger.info(
                    f"Self-correcting: confidence={confidence:.2f} < {CONFIDENCE_THRESHOLD}"
                )
                apply_correction(
                    self,
                    self.audit,
                    iteration,
                    last_tool_name,
                    confidence,
                    reasoning,
                )
            else:
                finding = {
                    "claim": finding_text or analysis_text[:300],
                    "log_id": log_id,
                    "confidence": confidence,
                    "tool_used": last_tool_name,
                    "finding_type": finding_type,
                    "timestamp": datetime.datetime.now().isoformat(),
                }
                self.findings.append(finding)
                phase_findings.append(finding)
                logger.info(f"Finding recorded: confidence={confidence:.2f} type={finding_type}")

        return phase_findings

#!/usr/bin/env python3
"""ForgeEvilHunter — Autonomous DFIR Triage Agent — Find Evil! Hackathon 2026"""

import argparse
import logging
import os
import sys
from datetime import datetime

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

load_dotenv()
console = Console()


def main():
    parser = argparse.ArgumentParser(
        description="ForgeEvilHunter — Autonomous DFIR Triage Agent (Find Evil! 2026)"
    )
    parser.add_argument("--disk", help="Path to disk image (.E01, .img)")
    parser.add_argument("--memory", help="Path to memory dump (.raw, .mem, .7z)")
    parser.add_argument(
        "--case",
        default=f"case_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        help="Case name for report and logs",
    )
    parser.add_argument(
        "--max-iter",
        type=int,
        default=5,
        help="Max iterations per phase (default: 5)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        console.print("[red]Error: GROQ_API_KEY not found. Add it to your .env file.[/red]")
        sys.exit(1)

    if not args.disk and not args.memory:
        console.print("[red]Error: provide --disk and/or --memory[/red]")
        parser.print_help()
        sys.exit(1)

    memory_path = args.memory
    if memory_path and memory_path.endswith(".7z"):
        console.print(f"[yellow]Extracting {memory_path}...[/yellow]")
        import glob

        from tools.sift_tools import extract_7z

        out_dir = os.path.join(os.path.dirname(memory_path), "extracted")
        r = extract_7z(memory_path, out_dir)
        if r["success"]:
            found = (
                glob.glob(f"{out_dir}/*.raw")
                + glob.glob(f"{out_dir}/*.mem")
                + glob.glob(f"{out_dir}/*.dmp")
            )
            if found:
                memory_path = found[0]
                console.print(f"[green]Extracted: {memory_path}[/green]")
        else:
            console.print(f"[red]Extraction failed: {r['error']}[/red]")

    evidence = {
        "disk_path": args.disk,
        "memory_path": memory_path,
        "case_name": args.case,
    }

    if args.disk:
        from tools.sift_tools import run_sha256

        h = run_sha256(args.disk)
        if h["success"]:
            console.print(f"[blue]Disk SHA256: {h['output'].strip()}[/blue]")

    from core.agent import ForensicAgent
    from core.audit import AuditLogger
    from reports.report_gen import ReportGenerator

    audit = AuditLogger(args.case)
    audit.log_investigation_start("Full DFIR triage", evidence)

    agent = ForensicAgent(
        audit_logger=audit,
        evidence=evidence,
        groq_api_key=api_key,
    )

    console.print(Panel(
        f"[bold green]ForgeEvilHunter Starting[/bold green]\n"
        f"Case: {args.case}\n"
        f"Disk: {args.disk or 'N/A'}\n"
        f"Memory: {memory_path or 'N/A'}",
        title="Find Evil!",
    ))

    console.print("[yellow]⚡ Phase 1: Initial Triage (process list + network scan)...[/yellow]")
    agent.run_investigation(
        "Initial triage: run process list and network scan from memory. "
        "Identify any suspicious processes or unusual network connections.",
        max_iterations=args.max_iter,
    )

    console.print("[yellow]⚡ Phase 2: Deep Investigation (command lines + strings)...[/yellow]")
    agent.run_investigation(
        "Deep investigation: examine command-line arguments of all processes. "
        "Search for PowerShell abuse, encoded commands, unusual executables, "
        "or signs of credential harvesting.",
        max_iterations=args.max_iter,
    )

    console.print("[yellow]⚡ Phase 3: Persistence + Lateral Movement...[/yellow]")
    agent.run_investigation(
        "Check for code injection anomalies and search disk/memory for "
        "persistence indicators: scheduled tasks, registry keys, unusual "
        "services, or lateral movement strings.",
        max_iterations=args.max_iter,
    )

    audit.log_investigation_end(len(agent.findings), audit.corrections)
    audit_path = audit.save()

    reporter = ReportGenerator(
        case_name=args.case,
        evidence=evidence,
        findings=agent.findings,
        audit_log_path=audit_path,
        corrections_count=audit.corrections,
    )
    report_path = reporter.generate()

    console.print(Panel(
        f"[bold green]Investigation Complete[/bold green]\n"
        f"Findings: {len(agent.findings)}\n"
        f"Self-corrections: {audit.corrections}\n"
        f"Report: {report_path}\n"
        f"Audit log: {audit_path}",
        title="Results",
    ))


if __name__ == "__main__":
    main()

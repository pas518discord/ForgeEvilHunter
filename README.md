# ForgeEvilHunter - Autonomous DFIR Triage Agent

An autonomous incident response agent for the **SANS Find Evil! 2026 Hackathon**.
Investigates Windows security incidents using SIFT Workstation forensic tools.
Powered by Groq (Llama 3.3-70b). Self-corrects when confidence is below 70%.
Every finding is traceable to a specific tool execution in the audit trail.

## Prerequisites
- [SIFT Workstation](https://www.sans.org/tools/sift-workstation) (Ubuntu VM with 200+ DFIR tools)
- Python 3.10+
- Free Groq API key at [console.groq.com](https://console.groq.com)

## Installation
```bash
git clone 
cd forge-evil-hunter
pip install -r requirements.txt
cp .env.example .env
# Open .env and paste your GROQ_API_KEY
```

## Usage
```bash
# Analyze workstation with disk + memory
python run.py --disk /path/to/wkstn.E01 --memory /path/to/wkstn.raw --case wkstn01

# Disk only
python run.py --disk /path/to/disk.E01 --case investigation1

# Debug mode (verbose output)
python run.py --disk /path/to/disk.E01 --memory /path/to/mem.raw --debug
```

## Evidence Dataset
**SRL-2018 SANS Forensics Challenge 2018** — Workstation-01
- Disk: base-wkstn-01-c-drive.E01
- Memory: base-wkstn-01-mem.zip / base-wkstn-01-memory.7z
- Contains: real Windows security incident with lateral movement indicators

## Architecture
```
Evidence (disk E01 + memory dump)
  → Safe Tool Layer (subprocess wrappers for vol3, log2timeline, strings)
    → Groq Agent Loop (Llama 3.3-70b tool calling)
      → Confidence Scorer (0.0–1.0 per finding)
        → Self-Correction (if confidence < 0.70: retry with different approach)
          → JSON Audit Trail (every action timestamped and logged)
            → Markdown Forensic Report (findings + evidence references)
```

## Submission Components
1. GitHub Repository (this repo)
2. Demo Video (live terminal, shows self-correction)
3. Architecture Diagram (docs/architecture.png)
4. Dataset Documentation (docs/dataset_docs.md)
5. Accuracy Report (docs/accuracy_report.md)
6. Agent Execution Logs (logs/ directory)
7. Try-it-out instructions (this README)
8. Written Description (Devpost project page)

## License
MIT — See LICENSE file

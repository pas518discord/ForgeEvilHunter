"""Configuration constants for ForgeEvilHunter."""
GROQ_MODEL = "llama-3.3-70b-versatile"
GROQ_MAX_TOKENS = 2048
GROQ_TEMPERATURE = 0.1
CONFIDENCE_THRESHOLD = 0.70   # Below this → self-correction triggered
MAX_ITERATIONS = 5
MAX_CORRECTION_ATTEMPTS = 3
LOG_DIR = "./logs"
REPORT_DIR = "./reports"
VERSION = "1.0.0"

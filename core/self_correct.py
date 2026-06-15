"""Self-correction logic for the ForgeEvilHunter agent."""

from config import CONFIDENCE_THRESHOLD


def should_self_correct(confidence: float, iteration: int, max_iterations: int) -> bool:
    """Return True if we should self-correct instead of recording the finding."""
    return confidence < CONFIDENCE_THRESHOLD and iteration < max_iterations - 1


def build_correction_prompt(
    prev_tool: str,
    prev_confidence: float,
    prev_reasoning: str,
) -> str:
    """Build the prompt message that asks LLM to try a different approach."""
    return (
        f"SELF-CORRECTION TRIGGERED: Your previous use of {prev_tool} "
        f"produced confidence {prev_confidence:.0%}. "
        f"Reason for low confidence: {prev_reasoning}. "
        f"Try a DIFFERENT forensic tool or different parameters to get "
        f"stronger evidence. What will you investigate next?"
    )


def apply_correction(
    agent,
    audit_logger,
    iteration: int,
    prev_tool: str,
    prev_confidence: float,
    prev_reasoning: str,
) -> None:
    """
    Trigger the self-correction sequence:
    1. Log the correction to the audit trail
    2. Add the correction prompt to the agent's message history
    The next agent._call_groq() will pick a different tool automatically.
    """
    correction_prompt = build_correction_prompt(
        prev_tool, prev_confidence, prev_reasoning
    )
    audit_logger.log_self_correction(
        iteration=iteration,
        trigger_reason=prev_reasoning,
        prev_tool=prev_tool,
        prev_confidence=prev_confidence,
        new_approach=correction_prompt,
    )
    agent.messages.append({
        "role": "user",
        "content": correction_prompt,
    })

"""Deterministic template narrator fallback when LLM is unavailable, disabled, or fails validation."""

from __future__ import annotations

from sloth_soc.schema import ActionEnum, Brief, DigestItem, NarratorOutput


class TemplateNarrator:
    """Produces 100% deterministic, schema-compliant narration without any LLM."""

    def narrate(self, brief: Brief) -> NarratorOutput:
        """Render structured findings into deterministic English sentences."""
        status_claim = brief.status

        # Deterministic TL;DR
        if status_claim == "urgent":
            crit_findings = [f for f in brief.findings if f.severity == "critical"]
            entity = crit_findings[0].entity if crit_findings else "an unknown host"
            tldr = (
                f"Critical security event detected from {entity}. "
                "Immediate credential and authentication verification required."
            )
        elif status_claim == "attention":
            tldr = (
                f"{len(brief.findings)} item(s) require review. "
                f"Handled {brief.stats.handled_blocked} blocked events overnight."
            )
        else:
            tldr = (
                f"Quiet overnight period on {brief.date}. "
                f"Handled {brief.stats.handled_blocked} blocked events across {brief.stats.raw_lines} log lines."
            )

        items: list[DigestItem] = []
        for f in brief.findings:
            # Construct short, fact-grounded explanation
            reason_text = f.reasons[0] if f.reasons else f.kind.replace("_", " ")
            blocked_str = " (blocked)" if f.blocked else " (not blocked)"
            explanation = f"{f.entity}: {reason_text}{blocked_str}."[:280]

            action: ActionEnum = f.action
            items.append(
                DigestItem(
                    finding_id=f.id,
                    explanation=explanation,
                    action=action,
                )
            )

        noise_note = (
            f"Handled {brief.stats.handled_blocked} blocked noise items across "
            f"{brief.stats.raw_lines} lines of server logs."
        )[:200]

        return NarratorOutput(
            status_claim=status_claim,
            tldr=tldr[:240],
            items=items,
            noise_note=noise_note,
        )

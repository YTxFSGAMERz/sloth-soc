"""Grounding and safety validator for structured LLM narrator output (Rules V1 - V7)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from sloth_soc.schema import Brief, NarratorOutput

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
NUM_REGEX = re.compile(r"\b[0-9]{1,9}\b")
FORBIDDEN_URL_REGEX = re.compile(r"://|\bwww\.", re.IGNORECASE)
FORBIDDEN_HTML_REGEX = re.compile(r"<[a-zA-Z/][^>]*>")
FORBIDDEN_SHELL_REGEX = re.compile(
    r"\|\s*sh\b|\|\s*bash\b|\bcurl\s+|\bwget\s+|\bsudo\s+|\brm\s+-[rf]+|\bchmod\s+",
    re.IGNORECASE,
)


@dataclass
class ValidationResult:
    """Result of running validation rules V1 through V7."""

    is_valid: bool
    violations: list[str] = field(default_factory=list)
    output: NarratorOutput | None = None
    error_message: str = ""


class DigestValidator:
    """Validates LLM-generated JSON against grounding, schema, and security rules."""

    def validate(self, raw_json_or_obj: str | dict[str, Any], brief: Brief) -> ValidationResult:
        violations: list[str] = []

        # --- V1: Parse and match schema ---
        if isinstance(raw_json_or_obj, str):
            try:
                obj = NarratorOutput.model_validate_json(raw_json_or_obj)
            except (ValidationError, Exception) as e:
                return ValidationResult(
                    is_valid=False,
                    violations=["V1"],
                    error_message=f"V1 Schema validation failed: {e}",
                )
        elif isinstance(raw_json_or_obj, dict):
            try:
                obj = NarratorOutput.model_validate(raw_json_or_obj)
            except ValidationError as e:
                return ValidationResult(
                    is_valid=False,
                    violations=["V1"],
                    error_message=f"V1 Schema validation failed: {e}",
                )
        elif isinstance(raw_json_or_obj, NarratorOutput):
            obj = raw_json_or_obj
        else:
            return ValidationResult(
                is_valid=False,
                violations=["V1"],
                error_message="Invalid input type to validator",
            )

        # --- V2: Status claim consistency ---
        if obj.status_claim != brief.status:
            violations.append("V2")

        # --- V3: Coverage of finding IDs ---
        expected_ids = {
            f.id for f in brief.findings if f.severity in ("critical", "high", "medium")
        }
        all_brief_ids = {f.id for f in brief.findings}
        produced_ids = [item.finding_id for item in obj.items]

        # Check for non-existent IDs
        if any(fid not in all_brief_ids for fid in produced_ids):
            violations.append("V3")

        # Check for duplicates
        if len(produced_ids) != len(set(produced_ids)):
            violations.append("V3")

        # Check coverage of medium+ findings
        if not expected_ids.issubset(set(produced_ids)):
            violations.append("V3")

        # --- Gather text for content checks ---
        text_blobs = [obj.tldr]
        for item in obj.items:
            text_blobs.append(item.explanation)
        if obj.noise_note:
            text_blobs.append(obj.noise_note)

        combined_text = " ".join(text_blobs)

        # --- V4: Grounding check (IPs and numbers) ---
        brief_ips = {f.entity for f in brief.findings}
        brief_ips.add("192.0.2.10")  # Server IP

        found_ips = IP_REGEX.findall(combined_text)
        for ip in found_ips:
            try:
                # Confirm it's valid IP
                ipaddress.ip_address(ip)
                if ip not in brief_ips:
                    violations.append("V4")
                    break
            except ValueError:
                pass

        # Grounding check for numbers > 10
        brief_str = brief.model_dump_json()
        brief_numbers = set(NUM_REGEX.findall(brief_str))
        found_numbers = NUM_REGEX.findall(combined_text)
        for num in found_numbers:
            val = int(num)
            if val > 10 and num not in brief_numbers:
                violations.append("V4")
                break

        # --- V5: Forbidden patterns ---
        # 1. URLs
        if FORBIDDEN_URL_REGEX.search(combined_text):
            violations.append("V5")

        # 2. Backticks or code fences
        if "`" in combined_text:
            violations.append("V5")

        # 3. HTML tags
        if FORBIDDEN_HTML_REGEX.search(combined_text):
            violations.append("V5")

        # 4. Markdown links/images e.g. ](
        if "](" in combined_text:
            violations.append("V5")

        # 5. Shell fragments
        if FORBIDDEN_SHELL_REGEX.search(combined_text):
            violations.append("V5")

        # 6. Control or bidi characters
        for ch in combined_text:
            code = ord(ch)
            if (0 <= code <= 0x1F and code != 0x09 and code != 0x0A) or (0x7F <= code <= 0x9F):
                violations.append("V5")
                break

        # --- V6: No laundering of untrusted strings ---
        if brief.untrusted_context:
            untrusted_strings = []

            def _collect_strings(val: Any) -> None:
                if isinstance(val, str) and len(val) > 12:
                    untrusted_strings.append(val.lower())
                elif isinstance(val, dict):
                    for v in val.values():
                        _collect_strings(v)
                elif isinstance(val, list):
                    for v in val:
                        _collect_strings(v)

            _collect_strings(brief.untrusted_context)
            lower_combined = combined_text.lower()
            for s in untrusted_strings:
                if s in lower_combined:
                    violations.append("V6")
                    break

        # --- V7: Field length limits ---
        if len(obj.tldr) > 240:
            violations.append("V7")
        for item in obj.items:
            if len(item.explanation) > 280:
                violations.append("V7")
        if obj.noise_note and len(obj.noise_note) > 200:
            violations.append("V7")

        unique_violations = sorted(list(set(violations)))
        is_valid = len(unique_violations) == 0

        return ValidationResult(
            is_valid=is_valid,
            violations=unique_violations,
            output=obj if is_valid else None,
            error_message=(f"Rules failed: {', '.join(unique_violations)}" if not is_valid else ""),
        )

"""JSON schema definitions for structured LLM narrator output."""

from typing import Any

DIGEST_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["status_claim", "tldr", "items"],
    "properties": {
        "status_claim": {"type": "string", "enum": ["quiet", "attention", "urgent"]},
        "tldr": {"type": "string", "maxLength": 240},
        "items": {
            "type": "array",
            "maxItems": 10,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["finding_id", "explanation", "action"],
                "properties": {
                    "finding_id": {"type": "string", "pattern": r"^F[0-9]{1,3}$"},
                    "explanation": {"type": "string", "maxLength": 280},
                    "action": {
                        "type": "string",
                        "enum": [
                            "NO_ACTION_MONITOR",
                            "CONFIRM_LEGIT_LOGIN",
                            "ROTATE_CREDENTIALS",
                            "ENABLE_KEY_ONLY_AUTH",
                            "BLOCK_IP_AT_FIREWALL",
                            "REVIEW_AUTH_LOG",
                            "REVIEW_WEB_LOGS",
                        ],
                    },
                },
            },
        },
        "noise_note": {"type": "string", "maxLength": 200},
    },
}

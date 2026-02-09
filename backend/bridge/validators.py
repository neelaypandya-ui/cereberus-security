"""Bridge validators — non-blocking response shape validation."""
import logging
from typing import Type
from pydantic import BaseModel, ValidationError

logger = logging.getLogger("cereberus.bridge")


def validate_and_log(data: dict | list, contract: Type[BaseModel], endpoint: str) -> dict | list:
    """Validate response against Bridge contract. Logs warnings, never blocks.

    Args:
        data: The response data to validate.
        contract: The Pydantic model to validate against.
        endpoint: The endpoint name for logging context.

    Returns:
        The original data, unmodified (validation is monitoring-only).
    """
    try:
        if isinstance(data, list):
            for i, item in enumerate(data[:5]):  # Validate first 5 items only
                if isinstance(item, dict):
                    contract.model_validate(item)
        elif isinstance(data, dict):
            contract.model_validate(data)
    except ValidationError as exc:
        field_errors = []
        for error in exc.errors():
            loc = ".".join(str(l) for l in error["loc"])
            field_errors.append(f"{loc}: {error['type']}")
        logger.warning(
            "[Bridge] Contract mismatch on %s: %s",
            endpoint,
            "; ".join(field_errors[:5]),
        )
    except Exception as exc:
        logger.warning("[Bridge] Validation error on %s: %s", endpoint, str(exc))
    return data

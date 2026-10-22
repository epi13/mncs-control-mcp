"""Shared validation for typed native application calls crossing Control."""

from __future__ import annotations

import json
from typing import Any

FORGE_STRUCTURED_FILE_CAPABILITY_SCHEMA = "mncs.forge.structured-file-capability/1"
MAX_NATIVE_APPLICATION_CALL_BYTES = 32 * 1024
MAX_CAPABILITY_PROVIDER_INPUT_BYTES = 2 * 1024 * 1024


def canonical_native_application_call(call: Any) -> str:
    """Validate and canonically encode a bounded typed VM call.

    The optional structured-file capability remains inert data here. Forge
    binds its identity to the verified Compiler artifact before execution.
    """
    if (not isinstance(call, dict)
            or set(call) not in ({"arguments"}, {"arguments", "capability_providers"})
            or not isinstance(call.get("arguments"), list)
            or len(call["arguments"]) > 32):
        raise ValueError("native application call must contain a bounded typed argument array")

    providers = call.get("capability_providers", [])
    if not isinstance(providers, list) or len(providers) > 1:
        raise ValueError("native application call accepts at most one bounded capability provider")

    for provider in providers:
        if (not isinstance(provider, dict)
                or set(provider) != {
                    "schema_version", "capability_identity", "input_schema",
                    "input_value", "output_schema",
                }
                or provider.get("schema_version") != FORGE_STRUCTURED_FILE_CAPABILITY_SCHEMA
                or not isinstance(provider.get("capability_identity"), str)
                or not provider["capability_identity"].strip()
                or len(provider["capability_identity"]) > 1024
                or not isinstance(provider.get("input_schema"), str)
                or not provider["input_schema"].strip()
                or len(provider["input_schema"]) > 128
                or not isinstance(provider.get("output_schema"), str)
                or not provider["output_schema"].strip()
                or len(provider["output_schema"]) > 128
                or not isinstance(provider.get("input_value"), dict)):
            raise ValueError("Forge structured-file capability provider is malformed")

        try:
            provider_input = json.dumps(
                provider["input_value"], ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError) as error:
            raise ValueError("Forge capability input must be bounded JSON data") from error
        if len(provider_input) > MAX_CAPABILITY_PROVIDER_INPUT_BYTES:
            raise ValueError("Forge capability input exceeds the 2 MiB bound")

    try:
        encoded = json.dumps(
            call, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        )
        byte_count = len(encoded.encode("utf-8"))
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError("native application call must be bounded JSON data") from error
    if byte_count > MAX_NATIVE_APPLICATION_CALL_BYTES:
        raise ValueError("native application call exceeds the 32 KiB input bound")
    return encoded

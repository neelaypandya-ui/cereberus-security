"""Bridge Sync Checker — verifies Python and TypeScript contracts are in sync.

Usage:
    python scripts/bridge_sync_check.py

Exit code 0 if in sync, 1 if mismatches found.
"""

import inspect
import re
import sys
from pathlib import Path

# Resolve project root
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

# Add project root to sys.path so backend imports work
sys.path.insert(0, str(PROJECT_ROOT))

from backend.bridge.contracts import *  # noqa: F401, F403
from pydantic import BaseModel


def get_python_contracts() -> dict[str, set[str]]:
    """Extract all BaseModel subclass field names from Python contracts."""
    import backend.bridge.contracts as mod

    contracts: dict[str, set[str]] = {}
    for name, cls in inspect.getmembers(mod, inspect.isclass):
        if issubclass(cls, BaseModel) and cls is not BaseModel:
            contracts[name] = set(cls.model_fields.keys())
    return contracts


def get_typescript_contracts(ts_path: Path) -> dict[str, set[str]]:
    """Parse TypeScript contracts.ts and extract interface field names.

    Uses brace-counting to correctly handle nested types like
    Array<{ key: string; value: number }>.
    """
    content = ts_path.read_text(encoding="utf-8")

    contracts: dict[str, set[str]] = {}
    # Find all "export interface Name {" positions
    header_pattern = re.compile(r"export\s+interface\s+(\w+)\s*\{")

    for header_match in header_pattern.finditer(content):
        name = header_match.group(1)
        # Find the matching closing brace via brace counting
        start = header_match.end()  # position right after the opening {
        depth = 1
        pos = start
        while pos < len(content) and depth > 0:
            if content[pos] == "{":
                depth += 1
            elif content[pos] == "}":
                depth -= 1
            pos += 1
        body = content[start : pos - 1]  # exclude the final }

        # Extract top-level field names only (depth 0 within the body).
        # Track brace depth character-by-character to skip nested objects.
        fields: set[str] = set()
        inner_depth = 0
        for line in body.split("\n"):
            # Compute depth at the START of this line (before processing chars)
            start_depth = inner_depth
            for ch in line:
                if ch == "{":
                    inner_depth += 1
                elif ch == "}":
                    inner_depth -= 1
            # Only match field declarations at top level
            if start_depth == 0:
                field_match = re.match(r"^\s*(\w+)\??:", line)
                if field_match:
                    fields.add(field_match.group(1))

        contracts[name] = fields

    return contracts


# Map TypeScript interface names to Python class names where they differ
TS_TO_PY_NAME_MAP = {
    "SwordStats": "SwordStatsResponse",
    "OverwatchStatus": "OverwatchStatusResponse",
}


def main():
    ts_path = PROJECT_ROOT / "frontend" / "src" / "bridge" / "contracts.ts"
    if not ts_path.exists():
        print(f"ERROR: TypeScript contracts not found at {ts_path}")
        sys.exit(1)

    py_contracts = get_python_contracts()
    ts_contracts = get_typescript_contracts(ts_path)

    mismatches = []
    matched = 0

    for ts_name, ts_fields in sorted(ts_contracts.items()):
        py_name = TS_TO_PY_NAME_MAP.get(ts_name, ts_name)
        if py_name not in py_contracts:
            mismatches.append(f"  {ts_name}: no matching Python model '{py_name}'")
            continue

        py_fields = py_contracts[py_name]

        missing_in_ts = py_fields - ts_fields
        missing_in_py = ts_fields - py_fields

        if missing_in_ts or missing_in_py:
            parts = []
            if missing_in_ts:
                parts.append(f"missing in TS: {sorted(missing_in_ts)}")
            if missing_in_py:
                parts.append(f"missing in PY: {sorted(missing_in_py)}")
            mismatches.append(f"  {ts_name} ({py_name}): {'; '.join(parts)}")
        else:
            matched += 1

    # Check for Python models with no TS counterpart
    ts_py_names = {TS_TO_PY_NAME_MAP.get(n, n) for n in ts_contracts}
    for py_name in sorted(py_contracts):
        if py_name not in ts_py_names:
            mismatches.append(f"  {py_name}: no matching TypeScript interface")

    print(f"Bridge Sync Check: {matched} contracts in sync")

    if mismatches:
        print(f"\nMISMATCHES ({len(mismatches)}):")
        for m in mismatches:
            print(m)
        sys.exit(1)
    else:
        print("All contracts are synchronized.")
        sys.exit(0)


if __name__ == "__main__":
    main()

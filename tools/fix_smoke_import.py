from pathlib import Path

path = Path(__file__).resolve().parents[1] / "ollydbg_mcp" / "smoke.py"
text = path.read_text(encoding="utf-8")
old = "from dataclasses import asdict, dataclass\nfrom pathlib import Path\nfrom typing import Any, Callable, Protocol\n"
new = (
    "from collections.abc import Callable\n"
    "from dataclasses import asdict, dataclass\n"
    "from pathlib import Path\n"
    "from typing import Any, Protocol\n"
)
if old in text:
    text = text.replace(old, new, 1)
elif new not in text:
    raise RuntimeError("smoke import block did not match")
path.write_text(text, encoding="utf-8")

"""Build the portfolio demo from docs/demo/src into docs/demo/dist.

    python scripts/build_demo.py          # write dist/standalone.html and dist/hookscope-demo.html
    python scripts/build_demo.py --check  # fail if dist/ is out of date (what the tests run)

Both outputs are single files with their CSS, JavaScript and data inlined, so uploading one
file is the whole deployment:

* ``hookscope-demo.html`` wears the portfolio's shell (its nav, footer, theme and analytics) and
  expects to live at ``/playground/hookscope-demo.html`` next to the site's ``/css`` and ``/js``.
* ``standalone.html`` brings its own styling and works anywhere, including a double-click.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

DEMO = Path(__file__).resolve().parent.parent / "docs" / "demo"
SRC, DIST = DEMO / "src", DEMO / "dist"

OUTPUTS = {"standalone.html": "standalone.html", "hookscope-demo.html": "portfolio.html"}


def _read(name: str) -> str:
    return (SRC / name).read_text(encoding="utf-8").rstrip("\n")


def _check_inline_safe(name: str, text: str) -> None:
    if "</script" in text.lower():
        raise ValueError(f"{name} contains '</script', which would end the inline script early")


def build() -> dict[str, str]:
    providers = json.dumps(json.loads(_read("providers.json")), indent=2, ensure_ascii=False)
    parts = {
        "{{STANDALONE_CSS}}": _read("standalone.css"),
        "{{PORTFOLIO_CSS}}": _read("portfolio.css"),
        "{{LAB_CSS}}": _read("lab.css"),
        "{{CONTENT}}": "\n".join("    " + line for line in _read("content.html").splitlines()),
        "{{PROVIDERS}}": providers,
        "{{SIGNING_JS}}": _read("signing.js"),
        "{{LAB_JS}}": _read("lab.js"),
        "{{STANDALONE_JS}}": _read("standalone.js"),
    }
    for placeholder, text in parts.items():
        _check_inline_safe(placeholder, text)
    outputs = {}
    for out_name, shell_name in OUTPUTS.items():
        page = _read(shell_name) + "\n"
        for placeholder, text in parts.items():
            page = page.replace(placeholder, text)
        if "{{" in page:
            raise ValueError(f"{out_name} still has an unfilled placeholder")
        outputs[out_name] = page
    return outputs


def main(argv: list[str]) -> int:
    outputs = build()
    if "--check" in argv:
        stale = [
            n for n, text in outputs.items() if not (DIST / n).exists() or (DIST / n).read_text() != text
        ]
        if stale:
            print("out of date, run python scripts/build_demo.py:", ", ".join(stale))
            return 1
        print("dist/ is up to date")
        return 0
    DIST.mkdir(exist_ok=True)
    for name, text in outputs.items():
        (DIST / name).write_text(text, encoding="utf-8")
        print(f"wrote docs/demo/dist/{name} ({len(text) // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""Command-line interface.

    guardrail check "ignore previous instructions"
    guardrail check --direction output --json "Contact me at a@b.com"
    echo "some text" | guardrail check -
    guardrail serve --port 8000
"""

from __future__ import annotations

import argparse
import json
import sys

from guardrail.engine import Guardrail

_COLORS = {"allow": "\033[32m", "flag": "\033[36m", "redact": "\033[33m", "block": "\033[31m"}
_RESET = "\033[0m"


def _cmd_check(args: argparse.Namespace) -> int:
    text = sys.stdin.read() if args.text == "-" else args.text
    result = Guardrail(policy=args.policy).check(text, args.direction)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        color = _COLORS[result.action.value] if sys.stdout.isatty() else ""
        reset = _RESET if color else ""
        print(f"Verdict : {color}{result.action.value.upper()}{reset}  ({result.latency_ms:.2f} ms)")
        for f in result.findings:
            extra = f" score={f.score}" if f.score is not None else ""
            print(f"  - [{f.action.value}] {f.detector}/{f.category}: {f.message}{extra}")
        if result.text is not None and result.text != text:
            print(f"Output  : {result.text}")

    return 1 if result.action.value == "block" else 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import os

    import uvicorn

    if args.policy:
        os.environ["GUARDRAIL_POLICY"] = args.policy
    uvicorn.run("guardrail.api:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardrail", description="Mini Guardrail for LLM apps")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Check a piece of text")
    p_check.add_argument("text", help="Text to check, or '-' to read from stdin")
    p_check.add_argument("--direction", choices=["input", "output"], default="input")
    p_check.add_argument("--policy", help="Path to a policy YAML file")
    p_check.add_argument("--json", action="store_true", help="Print the full result as JSON")
    p_check.set_defaults(func=_cmd_check)

    p_serve = sub.add_parser("serve", help="Run the REST API and web playground")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--policy", help="Path to a policy YAML file")
    p_serve.add_argument("--reload", action="store_true")
    p_serve.set_defaults(func=_cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

import argparse
import json
import sys

from .scanner import GuardrailEngine


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan text for prompt injection or sensitive output")
    parser.add_argument("text", nargs="?", help="Text to scan; stdin is used when omitted")
    parser.add_argument("--output", action="store_true", help="Use sensitive-output rules")
    parser.add_argument("--canary")
    parser.add_argument("--no-redact", action="store_true")
    args = parser.parse_args()
    text = args.text if args.text is not None else sys.stdin.read()
    engine = GuardrailEngine()
    result = (
        engine.scan_output(text, canary=args.canary, redact=not args.no_redact)
        if args.output else engine.scan_input(text)
    )
    print(json.dumps(result.to_dict(), indent=2))
    if result.action == "block":
        raise SystemExit(2)


if __name__ == "__main__":
    main()


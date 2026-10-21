"""Mask private action inputs before analysis emits workflow commands."""
from __future__ import annotations

import os


def main() -> None:
    names = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "XAI_API_KEY",
             "TYPESAFE_API_KEY", "GITHUB_TOKEN", "SENTINELAYER_TOKEN", "INTENT_MODEL_PIN", "INTENT_POLICY")
    seen = set()
    for name in names:
        for key in (name, "INPUT_" + name):
            value = os.environ.get(key, "")
            if value and value not in seen:
                seen.add(value)
                encoded = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
                print("::add-mask::" + encoded, flush=True)


if __name__ == "__main__":
    main()

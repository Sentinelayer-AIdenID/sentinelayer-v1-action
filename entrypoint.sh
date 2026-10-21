#!/bin/sh
set -eu

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

# Map GitHub Actions inputs (INPUT_*) to expected environment variables
# Inputs come in as INPUT_OPENAI_API_KEY, INPUT_GITHUB_TOKEN, etc.
export OPENAI_API_KEY="${INPUT_OPENAI_API_KEY:-${OPENAI_API_KEY:-}}"
export ANTHROPIC_API_KEY="${INPUT_ANTHROPIC_API_KEY:-${ANTHROPIC_API_KEY:-}}"
export GOOGLE_API_KEY="${INPUT_GOOGLE_API_KEY:-${GOOGLE_API_KEY:-}}"
export XAI_API_KEY="${INPUT_XAI_API_KEY:-${XAI_API_KEY:-}}"
export TYPESAFE_API_KEY="${INPUT_TYPESAFE_API_KEY:-${TYPESAFE_API_KEY:-}}"
export INTENT_MODEL_PIN="${INPUT_INTENT_MODEL_PIN:-${INTENT_MODEL_PIN:-}}"
export INTENT_POLICY="${INPUT_INTENT_POLICY:-${INTENT_POLICY:-}}"
export SENTINELAYER_TOKEN="${INPUT_SENTINELAYER_TOKEN:-${SENTINELAYER_TOKEN:-}}"

mask_secret() {
  [ -n "$1" ] || return 0
  # Encode workflow-command control characters, including multiline JSON.
  printf '%s' "$1" | awk 'BEGIN { printf "::add-mask::" } { gsub(/%/, "%25"); gsub(/\r/, "%0D"); if (NR > 1) printf "%s", "%0A"; printf "%s", $0 } END { printf "\n" }'
}
for name in OPENAI_API_KEY ANTHROPIC_API_KEY GOOGLE_API_KEY XAI_API_KEY TYPESAFE_API_KEY INTENT_MODEL_PIN INTENT_POLICY SENTINELAYER_TOKEN; do
  value="$(printenv "$name" || true)"
  mask_secret "$value"
done

# GITHUB_TOKEN can come from env or input
if [ -z "${GITHUB_TOKEN:-}" ] && [ -n "${INPUT_GITHUB_TOKEN:-}" ]; then
  export GITHUB_TOKEN="${INPUT_GITHUB_TOKEN}"
fi
mask_secret "${GITHUB_TOKEN:-}"

required_envs="GITHUB_EVENT_PATH GITHUB_REPOSITORY GITHUB_OUTPUT"
for name in $required_envs; do
  value="$(printenv "$name" || true)"
  if [ -z "$value" ]; then
    echo "Missing required env var: $name" >&2
    exit 2
  fi
done

# The mounted workspace is attacker-controlled input.  Keep imports bound to the
# image-owned package even when the container starts in that workspace.
export PYTHONPATH="/app/src"
export PYTHONSAFEPATH=1


# Docker actions run in an ephemeral container. Running as root avoids all
# permission issues with GitHub-mounted volumes (workspace, file_commands,
# runner_temp). Dropping to non-root caused cascading issues: the host runner
# process lost write access to its own file_commands after our step.
if [ -n "${GITHUB_WORKSPACE:-}" ] && [ -d "$GITHUB_WORKSPACE" ]; then
  mkdir -p "$GITHUB_WORKSPACE/.sentinelayer/runs" "$GITHUB_WORKSPACE/.sentinelayer/artifacts" 2>/dev/null || true
fi

exec python -P -m omargate.main

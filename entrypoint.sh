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
export SENTINELAYER_TOKEN="${INPUT_SENTINELAYER_TOKEN:-${SENTINELAYER_TOKEN:-}}"

[ -n "${OPENAI_API_KEY:-}" ] && echo "::add-mask::$OPENAI_API_KEY"
[ -n "${ANTHROPIC_API_KEY:-}" ] && echo "::add-mask::$ANTHROPIC_API_KEY"
[ -n "${GOOGLE_API_KEY:-}" ] && echo "::add-mask::$GOOGLE_API_KEY"
[ -n "${XAI_API_KEY:-}" ] && echo "::add-mask::$XAI_API_KEY"
[ -n "${SENTINELAYER_TOKEN:-}" ] && echo "::add-mask::$SENTINELAYER_TOKEN"

# GITHUB_TOKEN can come from env or input
if [ -z "${GITHUB_TOKEN:-}" ] && [ -n "${INPUT_GITHUB_TOKEN:-}" ]; then
  export GITHUB_TOKEN="${INPUT_GITHUB_TOKEN}"
fi

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

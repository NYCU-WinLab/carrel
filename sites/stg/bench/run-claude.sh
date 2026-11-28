#!/bin/bash
# One bench run in the bench CT (#848). Prompt on stdin, stream-json on stdout.
# Each run starts from a clean Claude config, a clean work dir and only the agent's key pair.
set -e
set -a; . "$HOME/.claude.env"; set +a
export CLAUDE_CONFIG_DIR="$HOME/.bench-claude"
rm -rf "$CLAUDE_CONFIG_DIR" "$HOME/work"
mkdir -p "$CLAUDE_CONFIG_DIR" "$HOME/work"
find "$HOME/.ssh" -mindepth 1 ! -name id_ed25519 ! -name id_ed25519.pub -delete
cd "$HOME/work"
exec "$HOME/.local/bin/claude" -p --mcp-config "$HOME/mcp.json" --strict-mcp-config \
  --allowedTools "mcp__carrel-stg" Bash Read --permission-mode bypassPermissions --no-session-persistence \
  --output-format stream-json --verbose

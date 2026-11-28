#!/bin/bash
# One Codex bench run in the bench CT (#848). Prompt on stdin, JSON events on stdout.
# Keeps ~/.codex/auth.json (the ChatGPT sign-in, refreshed in place) and rewrites everything else,
# so each run starts from the same config with no history, a clean work dir and only the key pair.
set -e
export CODEX_HOME="$HOME/.codex"
find "$CODEX_HOME" -mindepth 1 -maxdepth 1 ! -name auth.json -exec rm -rf {} +
CARREL_TOKEN=$(cat "$HOME/carrel-token")
export CARREL_TOKEN
cat > "$CODEX_HOME/config.toml" <<TOML
[mcp_servers.carrel-stg]
url = "$(cat "$HOME/carrel-url")/mcp"
bearer_token_env_var = "CARREL_TOKEN"
TOML
rm -rf "$HOME/work"
mkdir -p "$HOME/work"
find "$HOME/.ssh" -mindepth 1 ! -name id_ed25519 ! -name id_ed25519.pub -delete
cd "$HOME/work"
# The CT is the sandbox: it reaches only the internet and the staging gateway, not the nodes.
exec "$HOME/.local/bin/codex" exec --json --ephemeral --skip-git-repo-check \
  --dangerously-bypass-approvals-and-sandbox -

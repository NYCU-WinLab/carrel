#!/bin/sh
# skill-bench --agent-cmd for the bench container (#848). Prompt on stdin, agent events on stdout.
# Hands the member token to the container, then runs one agent there as the unprivileged user agent.
#   $1          claude (default) or codex
#   BENCH_PVE   ssh target of the host that runs the container (anvil)
#   BENCH_CT    container id (1113)
#   CARREL_TOKEN_FILE, CARREL_URL as for bench.py
set -e
AGENT=${1:-claude}
PVE=${BENCH_PVE:-anvil}
CT=${BENCH_CT:-1113}
URL=${CARREL_URL:-https://carrel.zhanyongxiang.com}
case $AGENT in
claude)
  python3 -c 'import json,sys;t=open(sys.argv[1]).read().strip();print(json.dumps({"mcpServers":{"carrel-stg":{"type":"http","url":sys.argv[2]+"/mcp","headers":{"Authorization":"Bearer "+t}}}}))' "$CARREL_TOKEN_FILE" "$URL" \
    | ssh "$PVE" "pct exec $CT -- su agent -c 'umask 077; cat > /home/agent/mcp.json'"
  ;;
codex)
  tr -d '\n' < "$CARREL_TOKEN_FILE" | ssh "$PVE" "pct exec $CT -- su agent -c 'umask 077; cat > /home/agent/carrel-token'"
  printf %s "$URL" | ssh "$PVE" "pct exec $CT -- su agent -c 'cat > /home/agent/carrel-url'"
  ;;
*)
  echo "unknown agent $AGENT" >&2
  exit 2
  ;;
esac
exec ssh "$PVE" "pct exec $CT -- su - agent -c /home/agent/run-$AGENT.sh"

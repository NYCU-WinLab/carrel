#!/bin/sh
# skill-bench --agent-cmd for the bench container (#848). Prompt on stdin, stream-json on stdout.
# Hands the member token to the container, then runs one agent there as the unprivileged user agent.
#   BENCH_PVE   ssh target of the host that runs the container (anvil)
#   BENCH_CT    container id (1113)
#   CARREL_TOKEN_FILE, CARREL_URL as for bench.py
set -e
PVE=${BENCH_PVE:-anvil}
CT=${BENCH_CT:-1113}
URL=${CARREL_URL:-https://carrel.zhanyongxiang.com}
python3 -c 'import json,sys;t=open(sys.argv[1]).read().strip();print(json.dumps({"mcpServers":{"carrel-stg":{"type":"http","url":sys.argv[2]+"/mcp","headers":{"Authorization":"Bearer "+t}}}}))' "$CARREL_TOKEN_FILE" "$URL" \
  | ssh "$PVE" "pct exec $CT -- su agent -c 'umask 077; cat > /home/agent/mcp.json'"
exec ssh "$PVE" "pct exec $CT -- su - agent -c /home/agent/run-claude.sh"

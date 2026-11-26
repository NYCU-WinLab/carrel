#!/bin/sh
# Runs plugin.py as this process, not as a child: go-plugin kills only its
# direct child, and a launcher that forks (uv run) leaves the plugin behind.
# The venv comes from: uv venv python/.venv && uv pip install -p python/.venv grpcio==1.76.0 grpcio-health-checking==1.76.0
here=$(dirname "$0")
exec "$here/.venv/bin/python" "$here/plugin.py" "$@"

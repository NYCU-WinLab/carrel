#!/bin/sh
# Regenerates the plugin contract code from proto/plugin/v1/plugin.proto.
# Needs uv, protoc-gen-go v1.36.12 and protoc-gen-go-grpc v1.6.0 on PATH.
set -eu
cd "$(dirname "$0")/../.."
uvx --from grpcio-tools==1.76.0 python -m grpc_tools.protoc -Iproto/plugin/v1 \
  --go_out=internal/pluginpb --go_opt=paths=source_relative \
  --go-grpc_out=internal/pluginpb --go-grpc_opt=paths=source_relative \
  plugin.proto

#!/bin/sh
# carrel deploy for GitLab CI (issue #265): the counterpart of
# NYCU-WinLab/carrel-deploy for a GitLab job. It uploads a release with the
# job's ID token in CARREL_ID_TOKEN and waits until it is live or failed.
# Needs curl and jq. Served by carrel at /apps/v1/deploy.sh.
set -eu
url=@ORIGIN@
tenant= app= artifact= timeout=300
while [ $# -gt 0 ]; do
  case "$1" in
  --tenant) tenant=$2; shift 2 ;;
  --app) app=$2; shift 2 ;;
  --artifact) artifact=$2; shift 2 ;;
  --timeout) timeout=$2; shift 2 ;;
  *) echo "carrel: unknown argument $1" >&2; exit 2 ;;
  esac
done
if [ -z "${CARREL_ID_TOKEN:-}" ]; then
  echo "carrel: add id_tokens: CARREL_ID_TOKEN: aud: ${url#*://} to the job." >&2
  exit 1
fi
[ -n "$tenant" ] && [ -n "$app" ] || { echo "carrel: give --tenant and --app." >&2; exit 2; }
[ -f "$artifact" ] || { echo "carrel: artifact $artifact not found." >&2; exit 1; }
command -v jq >/dev/null || { echo "carrel: install jq in the job image, for example apk add --no-cache curl jq." >&2; exit 1; }

base="$url/apps/v1/$tenant/$app/releases"
echo "Uploading $artifact ($(wc -c <"$artifact" | tr -d ' ') bytes) to $tenant/$app"
response=$(curl -sS -X POST -w '\n%{http_code}' -H "Authorization: Bearer $CARREL_ID_TOKEN" \
  -H "Content-Type: application/gzip" --upload-file "$artifact" "$base")
code=$(printf '%s\n' "$response" | tail -n 1)
body=$(printf '%s\n' "$response" | sed '$d')
if [ "$code" != 200 ]; then
  echo "carrel: upload failed with HTTP $code: $(printf '%s' "$body" | jq -r '.error.message // .' 2>/dev/null || printf '%s' "$body")" >&2
  exit 1
fi
id=$(printf '%s' "$body" | jq -r .release.id)
echo "Release $id stored; waiting for the machine"

start=$(date +%s)
warned=
while :; do
  # A failed poll is retried: the release may be live already.
  if ! status=$(curl -fsS -H "Authorization: Bearer $CARREL_ID_TOKEN" "$base/$id"); then
    status='{"release":{}}'
  fi
  state=$(printf '%s' "$status" | jq -r .release.state)
  agent=$(printf '%s' "$status" | jq -r .release.agent)
  case "$state" in
  live) echo "$id is live."; exit 0 ;;
  superseded) echo "$id was stored, but a newer release went live first."; exit 0 ;;
  failed)
    echo "carrel: release $id failed: $(printf '%s' "$status" | jq -r '.release.error // "unknown"')" >&2
    printf '%s' "$status" | jq -r '.release.log // empty' >&2
    exit 1 ;;
  esac
  if [ "$agent" != connected ] && [ "$agent" != null ] && [ -z "$warned" ]; then
    echo "carrel: carrel-deployd on the machine is $agent; run the install line from app_link." >&2
    warned=1
  fi
  if [ $(( $(date +%s) - start )) -ge "$timeout" ]; then
    echo "carrel: release $id is still $state after ${timeout}s." >&2
    exit 1
  fi
  sleep 1
done

#!/usr/bin/env bash
# Play a manual CI job of a tag's pipeline and wait for it: scripts/release.sh ship uses it for the
# `reproducible` job. It runs with the maintainer's glab login; the job itself holds no secret.
#
#   scripts/run-ci-job.sh vX.Y.Z reproducible [MINUTES]     (default 90)
#
# Exit 0: the job succeeded. 1: it failed or was cancelled. 2: it could not be started or did not
# finish in time (nothing is concluded from that).
set -euo pipefail
cd "$(dirname "$0")/.."
REF="${1:-}"; JOB="${2:-}"; MINUTES="${3:-90}"
[ -n "$REF" ] && [ -n "$JOB" ] || { echo "usage: scripts/run-ci-job.sh REF JOB [MINUTES]" >&2; exit 2; }
command -v glab >/dev/null || { echo "glab is not installed" >&2; exit 2; }

# The newest pipeline of the ref, then the job by name.
PID=$(glab api "projects/:id/pipelines?ref=$REF&per_page=1" 2>/dev/null | python3 -c 'import json,sys
try: p=json.load(sys.stdin); print(p[0]["id"] if p else "")
except Exception: print("")')
[ -n "$PID" ] || { echo "no pipeline for $REF" >&2; exit 2; }
read -r JID STATUS < <(glab api "projects/:id/pipelines/$PID/jobs?per_page=100" 2>/dev/null | python3 -c 'import json,sys
name = sys.argv[1]
try:
    j = [x for x in json.load(sys.stdin) if x["name"] == name]
    print(j[0]["id"], j[0]["status"]) if j else print("", "")
except Exception: print("", "")' "$JOB") || true
[ -n "${JID:-}" ] || { echo "pipeline $PID of $REF has no job named $JOB (a tag from before it existed?)" >&2; exit 2; }

if [ "$STATUS" = manual ]; then
  glab api -X POST "projects/:id/jobs/$JID/play" >/dev/null || { echo "could not start job $JID" >&2; exit 2; }
  echo "started $JOB (job $JID, pipeline $PID)"
else
  echo "$JOB (job $JID) is already $STATUS"
fi
for _ in $(seq 1 $((MINUTES * 2))); do
  STATUS=$(glab api "projects/:id/jobs/$JID" 2>/dev/null | python3 -c 'import json,sys
try: print(json.load(sys.stdin)["status"])
except Exception: print("unknown")')
  case "$STATUS" in
    success) echo "$JOB: success"; exit 0 ;;
    failed|canceled|skipped) echo "$JOB: $STATUS (glab ci view, or job $JID on the pipeline page)" >&2; exit 1 ;;
  esac
  sleep 30
done
echo "$JOB did not finish within $MINUTES minutes (last: $STATUS)" >&2
exit 2

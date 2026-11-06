#!/usr/bin/env bash
# Mirage evaluation harness (step 8).
#
#   eval/run.sh [N] [mode]
#     N     number of campaigns to run (default 5)
#     mode  active (default) = containment on, measures time-to-contain
#           observe          = containment off, measures full-trail detection
#
# Each run resets the controller, fires one attack campaign plus benign user
# traffic, then records metrics. A summary (mean +/- sd) is written at the end.
# Needs Docker running and the lab built (docker compose build).
set -euo pipefail

N=${1:-5}
MODE=${2:-active}
cd "$(dirname "$0")/.."

API=${MIRAGE_API:-http://127.0.0.1:8000}
BENIGN_REQ=${BENIGN_REQUESTS:-40}
RESULTS="eval/results"
mkdir -p "$RESULTS"
stamp=$(date -u +%Y%m%d-%H%M%S)
PY=$([ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)

echo ">> bringing up the lab (response mode: $MODE)"
MIRAGE_RESPONSE_MODE="$MODE" docker compose up -d --build controller admin-panel ssh s3
MIRAGE_RESPONSE_MODE="$MODE" docker compose --profile eval up -d --build legit attacker benign

# Wait for the controller API.
for _ in $(seq 1 30); do curl -sf "$API/health" >/dev/null 2>&1 && break; sleep 1; done

for i in $(seq 1 "$N"); do
    echo ">> run $i/$N (mode=$MODE)"
    curl -s -X POST "$API/api/admin/reset" >/dev/null
    docker compose exec -T benign env LEGIT=10.66.0.30 REQUESTS="$BENIGN_REQ" /opt/benign.sh &
    benign_pid=$!
    docker compose exec -T attacker /opt/campaign.sh || true
    wait "$benign_pid" || true
    sleep 2
    "$PY" -I eval/metrics.py --api "$API" --attacker 10.66.0.50 \
        --benign 10.66.0.51 --benign-requests "$BENIGN_REQ" \
        --out "$RESULTS/$MODE-$stamp-run$i.json"
done

echo ">> summary ($MODE, $N runs)"
"$PY" -I eval/metrics.py --aggregate "$RESULTS/$MODE-$stamp-run"*.json | tee "$RESULTS/$MODE-$stamp-summary.txt"
echo ">> results in $RESULTS/$MODE-$stamp-*"

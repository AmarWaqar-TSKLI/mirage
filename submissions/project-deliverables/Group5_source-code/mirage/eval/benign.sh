#!/usr/bin/env bash
# Benign traffic generator: acts like a normal internal user hitting the real
# (non-decoy) internal site. A normal user has no reason to touch a decoy, so
# this should raise ZERO alerts on the controller, which is what makes the
# false-positive rate meaningful.
#
# Env: LEGIT=10.66.0.30  REQUESTS=40
set -u

LEGIT=${LEGIT:-10.66.0.30}
REQUESTS=${REQUESTS:-40}
PAGES=("/" "/index.html" "/about.html" "/status.html" "/assets/app.css")

echo "[benign] $REQUESTS requests against the legit site http://$LEGIT"
for i in $(seq 1 "$REQUESTS"); do
    page=${PAGES[$((RANDOM % ${#PAGES[@]}))]}
    curl -s -o /dev/null -w "%{http_code}" "http://$LEGIT$page" >/dev/null 2>&1 || true
    sleep 0.1
done
echo "[benign] done ($REQUESTS requests, none aimed at a decoy)"

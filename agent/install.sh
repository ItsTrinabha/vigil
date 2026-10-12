#!/usr/bin/env bash
# Install the Vigil agent as a systemd service on a Linux host.
#
#   curl -fsSLk https://SIEM:8443/agent/install.sh | sudo VIGIL_SERVER=https://SIEM:8443 \
#        VIGIL_ENROLL_TOKEN=... VIGIL_CA_SHA256=... bash
#
# The server's self-signed certificate is downloaded once and its SHA-256
# fingerprint is compared with VIGIL_CA_SHA256 (shown on the Agents page)
# before it is pinned. If the server uses a certificate from a public CA,
# leave VIGIL_CA_SHA256 unset and the system trust store is used.
set -euo pipefail

: "${VIGIL_SERVER:?set VIGIL_SERVER, e.g. https://siem.example.com:8443}"
: "${VIGIL_ENROLL_TOKEN:?set VIGIL_ENROLL_TOKEN (Agents page in the Vigil console)}"
VIGIL_SERVER="${VIGIL_SERVER%/}"
DIR=/opt/vigil-agent
CONF=/etc/vigil/agent.ini

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required (or run vigil_agent.py directly)"; exit 1; }

mkdir -p "$DIR" /etc/vigil /var/lib/vigil-agent
chmod 700 /var/lib/vigil-agent

fetch() { curl -fsSL ${CURL_K:-} "$VIGIL_SERVER/agent/$1" -o "$2"; }

CA_LINE=""
if [ -n "${VIGIL_CA_SHA256:-}" ]; then
  curl -fsSLk "$VIGIL_SERVER/agent/ca.crt" -o /etc/vigil/ca.crt
  got=$(openssl x509 -in /etc/vigil/ca.crt -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
  want=$(echo "$VIGIL_CA_SHA256" | tr -d ':' | tr 'A-F' 'a-f')
  if [ "$got" != "$want" ]; then
    echo "certificate fingerprint mismatch: expected $want, got $got. Aborting." >&2
    rm -f /etc/vigil/ca.crt
    exit 1
  fi
  echo "server certificate verified ($got)"
  CA_LINE="ca_file = /etc/vigil/ca.crt"
  CURL_K="--cacert /etc/vigil/ca.crt"
fi

fetch vigil_agent.py "$DIR/vigil_agent.py"
fetch vigil-agent.service /etc/systemd/system/vigil-agent.service

if [ ! -f "$CONF" ]; then
  umask 077
  cat > "$CONF" <<INI
[server]
url = $VIGIL_SERVER
enroll_token = $VIGIL_ENROLL_TOKEN
$CA_LINE

[agent]
state_dir = /var/lib/vigil-agent
# start_at = end        # "beginning" to also ship existing log history

[inputs]
# files = /var/log/auth.log, /var/log/nginx/access.log:web, /var/log/audit/audit.log:auditd
# journald = auto
# processes = true
INI
fi

systemctl daemon-reload
systemctl enable --now vigil-agent
sleep 2
systemctl --no-pager --lines=5 status vigil-agent || true
echo "Vigil agent installed. It should appear on the Agents page within a minute."

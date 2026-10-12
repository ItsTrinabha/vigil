#!/usr/bin/env bash
# Vigil SIEM control script.
#   ./vigil.sh up       build and start (creates .env with random secrets on first run)
#   ./vigil.sh demo     replay sample log activity so every detection type fires
#   ./vigil.sh status   show containers and health
#   ./vigil.sh logs     follow server and agent logs
#   ./vigil.sh down     stop (data is kept in Docker volumes)
#   ./vigil.sh reset    stop and delete all data
set -euo pipefail
cd "$(dirname "$0")"

compose() { docker compose "$@"; }
rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"; }

ensure_env() {
  if [ ! -f .env ]; then
    sed -e "s/^VIGIL_ADMIN_PASSWORD=.*/VIGIL_ADMIN_PASSWORD=$(rand 20)/" \
        -e "s/^VIGIL_ENROLLMENT_TOKEN=.*/VIGIL_ENROLLMENT_TOKEN=$(rand 32)/" .env.example > .env
    chmod 600 .env
    echo "Created .env with a random admin password and agent enrollment token."
  fi
  mkdir -p lab/logs
  chmod 777 lab/logs  # the agent container writes demo logs here
}

wait_healthy() {
  printf "Waiting for Vigil to become healthy"
  for _ in $(seq 1 90); do
    if [ "$(docker inspect -f '{{.State.Health.Status}}' vigil-server 2>/dev/null)" = "healthy" ]; then
      echo " ok"; return 0
    fi
    printf "."; sleep 2
  done
  echo; echo "server did not become healthy; see ./vigil.sh logs" >&2; exit 1
}

banner() {
  # shellcheck disable=SC1091
  . ./.env
  cat <<MSG

  Vigil SIEM is running.

    Console   ${VIGIL_PUBLIC_URL:-https://localhost:8443}
    User      ${VIGIL_ADMIN_USER:-admin}
    Password  ${VIGIL_ADMIN_PASSWORD}

  The certificate is self-signed, so the browser shows a warning the first time.
  Run ./vigil.sh demo to replay sample activity and see detections fire.

MSG
}

case "${1:-up}" in
  up)
    command -v docker >/dev/null || { echo "Docker is required: https://docs.docker.com/get-docker/"; exit 1; }
    ensure_env
    if [ -n "${VIGIL_NO_BUILD:-}" ]; then compose up -d --no-build; else compose up -d --build; fi
    wait_healthy
    banner ;;
  demo)
    ensure_env
    docker exec vigil-agent python lab_replay.py --dir /lab
    echo "Sample activity written to lab/logs. Alerts appear in the console within a few seconds." ;;
  status) compose ps ;;
  logs) compose logs -f --tail=100 ;;
  down) compose down ;;
  reset)
    read -r -p "Delete all Vigil data (events, alerts, users)? [y/N] " a
    [ "$a" = "y" ] && compose down -v && rm -rf lab/logs/* ;;
  *) sed -n '2,8p' "$0"; exit 1 ;;
esac

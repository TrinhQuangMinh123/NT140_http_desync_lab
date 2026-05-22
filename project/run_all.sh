#!/usr/bin/env bash
# run_all.sh — Orchestrate All Target Environments + Fuzzer
# ----------------------------------------------------------
# Usage:
#   bash run_all.sh              # Start all envs + fuzz all targets
#   bash run_all.sh --stop       # Stop all environments
#   bash run_all.sh --fuzz-only  # Skip docker startup, fuzz existing targets
# Optional env:
#   MUTATIONS=3 RANDOM_SEED=1337 REPEAT_COUNT=3 bash run_all.sh --fuzz-only

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGETS_DIR="$PROJECT_DIR/02_targets"
FUZZER="$PROJECT_DIR/04_fuzzer_engine/runner.py"
COLLECTOR="$PROJECT_DIR/01_data_prep/collector.py"

# ─── Target Matrix ─────────────────────────────────────────
declare -A TARGETS=(
  ["nginx_gunicorn"]="8888:9001"
  ["haproxy_flask"]="8890:9003"
  ["ats_gevent"]="8889:9002"
  ["apache_tomcat"]="8891:9004"
)
TARGET_ORDER=("nginx_gunicorn" "haproxy_flask" "ats_gevent" "apache_tomcat")

# 12 seeds x (1 original + 3 mutated variants) = 48 test cases per target.
MUTATIONS="${MUTATIONS:-3}"
RANDOM_SEED="${RANDOM_SEED:-1337}"
REPEAT_COUNT="${REPEAT_COUNT:-1}"

# ─── Color helpers ─────────────────────────────────────────
RED='\033[0;91m'; GREEN='\033[0;92m'; CYAN='\033[1;96m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*] $*${NC}"; }
success() { echo -e "${GREEN}[✓] $*${NC}"; }
warn()    { echo -e "${RED}[!] $*${NC}"; }

# ─── Regenerate Golden Seeds ────────────────────────────────
generate_seeds() {
  info "Generating Golden Seed Corpus..."
  python3 "$COLLECTOR"
  success "Seeds ready."
}

# ─── Start/Stop Docker environments ────────────────────────
start_targets() {
  for name in "${TARGET_ORDER[@]}"; do
    compose="$TARGETS_DIR/$name/docker-compose.yml"
    if [ -f "$compose" ]; then
      info "Starting environment: $name"
      docker compose -f "$compose" up -d --build 2>/dev/null && \
        success "$name is up." || warn "$name failed to start — skipping."
    fi
  done
  info "Waiting 5s for backends to warm up..."
  sleep 5
}

stop_targets() {
  for name in "${TARGET_ORDER[@]}"; do
    compose="$TARGETS_DIR/$name/docker-compose.yml"
    if [ -f "$compose" ]; then
      info "Stopping: $name"
      docker compose -f "$compose" down 2>/dev/null && success "$name stopped."
    fi
  done
}

# ─── Fuzzing Loop ──────────────────────────────────────────
fuzz_all() {
  echo ""
  echo "======================================================================"
  echo "  FUZZING ALL TARGET PAIRS"
  echo "======================================================================"
  
  for name in "${TARGET_ORDER[@]}"; do
    IFS=':' read -r proxy_port backend_port <<< "${TARGETS[$name]}"
    echo ""
    info "Fuzzing: $name  |  Proxy=127.0.0.1:$proxy_port  Backend=127.0.0.1:$backend_port  Seed=$RANDOM_SEED  Repeat=$REPEAT_COUNT"
    python3 "$FUZZER" \
      --proxy-port "$proxy_port" \
      --backend-port "$backend_port" \
      --mutations "$MUTATIONS" \
      --random-seed "$RANDOM_SEED" \
      --repeat "$REPEAT_COUNT" \
      --quiet \
      --label "$name" || warn "Fuzzer error on $name — continuing."
    success "Done fuzzing $name."
  done
}

# ─── Main ──────────────────────────────────────────────────
main() {
  echo "======================================================================"
  echo "  HTTP Desync Fuzzer — Full Target Matrix Run"
  echo "======================================================================"

  case "${1:-}" in
    --stop)
      stop_targets; exit 0 ;;
    --fuzz-only)
      generate_seeds; fuzz_all ;;
    *)
      generate_seeds
      start_targets
      fuzz_all
      ;;
  esac

  echo ""
  echo "======================================================================"
  echo "  All done! Run triage:"
  echo "  python3 05_analyzer/triage.py"
  echo "======================================================================"
}

main "$@"

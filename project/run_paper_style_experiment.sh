#!/usr/bin/env bash
# run_paper_style_experiment.sh — Paper-style full experiment runner
# ------------------------------------------------------------------
# Runs the full project workflow:
#   1. Generate request seeds
#   2. Start all 4 target environments
#   3. For each RNG seed:
#      - run request-side fuzzing on all 4 environments
#      - run response-side fuzzing on all 4 environments
#      - save reports into 05_analyzer/crash_reports_run_<seed>/
#      - run triage classification for that seed
#
# Default experiment:
#   4 environments × 5 RNG seeds
#   Request-side: 12 seeds × (1 original + 3 mutations) × 4 env × 5 seeds = 960 tests
#   Response-side: 5 seeds × (1 original + 3 mutations) × 4 env × 5 seeds = 400 tests
#
# Usage:
#   bash run_paper_style_experiment.sh
#
# Optional env:
#   RNG_SEEDS="1337 1338" MUTATIONS=3 RESTART_EVERY=1 bash run_paper_style_experiment.sh

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORTS_DIR="$PROJECT_DIR/05_analyzer/crash_reports"
TRIAGE="$PROJECT_DIR/05_analyzer/triage.py"
RUN_ALL="$PROJECT_DIR/run_all.sh"
RUNNER="$PROJECT_DIR/04_fuzzer_engine/runner.py"

RNG_SEEDS="${RNG_SEEDS:-1337 1338 1339 1340 1341}"
MUTATIONS="${MUTATIONS:-3}"
RESTART_EVERY="${RESTART_EVERY:-1}"

declare -A TARGETS=(
  ["nginx_gunicorn"]="8888:9001"
  ["haproxy_flask"]="8890:9003"
  ["ats_gevent"]="8889:9002"
  ["apache_tomcat"]="8891:9004"
)
TARGET_ORDER=("nginx_gunicorn" "haproxy_flask" "ats_gevent" "apache_tomcat")

info() { echo -e "\033[1;96m[*] $*\033[0m"; }
ok()   { echo -e "\033[0;92m[✓] $*\033[0m"; }

main() {
  mkdir -p "$REPORTS_DIR"

  info "Starting all target environments once..."
  bash "$RUN_ALL" --start-only

  for seed in $RNG_SEEDS; do
    run_dir="$PROJECT_DIR/05_analyzer/crash_reports_run_${seed}"
    triage_out="$PROJECT_DIR/05_analyzer/triage_run_${seed}.txt"

    info "RNG seed $seed: clearing old reports"
    rm -rf "$run_dir"
    mkdir -p "$run_dir"
    rm -f "$REPORTS_DIR"/discrepancy_*

    info "RNG seed $seed: request-side fuzzing, restart every $RESTART_EVERY test"
    MUTATIONS="$MUTATIONS" RANDOM_SEED="$seed" RESTART_EVERY="$RESTART_EVERY" bash "$RUN_ALL" --fuzz-only

    info "RNG seed $seed: response-side fuzzing"
    for name in "${TARGET_ORDER[@]}"; do
      IFS=':' read -r proxy_port backend_port <<< "${TARGETS[$name]}"
      compose_file="$PROJECT_DIR/02_targets/$name/docker-compose.yml"
      python3 "$RUNNER" \
        --proxy-port "$proxy_port" \
        --backend-port "$backend_port" \
        --mode response \
        --mutations "$MUTATIONS" \
        --random-seed "$seed" \
        --restart-every "$RESTART_EVERY" \
        --compose-file "$compose_file" \
        --label "$name" \
        --quiet
    done

    info "RNG seed $seed: archiving reports"
    shopt -s nullglob
    reports=("$REPORTS_DIR"/discrepancy_*)
    if ((${#reports[@]} > 0)); then
      mv "${reports[@]}" "$run_dir"/
    else
      echo "[!] No discrepancy reports generated for seed $seed"
    fi
    shopt -u nullglob

    info "RNG seed $seed: triage classification"
    python3 "$TRIAGE" --reports-dir "$run_dir" | tee "$triage_out"
    ok "Seed $seed done. Reports: $run_dir"
  done

  info "Combined triage over all crash_reports_run_* directories"
  python3 "$TRIAGE" --reports-dir "$PROJECT_DIR/05_analyzer" --recursive | tee "$PROJECT_DIR/05_analyzer/triage_all_runs.txt"
  ok "Full paper-style experiment complete."
}

main "$@"

#!/usr/bin/env bash
# Full-scale faithful run: 3 gunicorn-backed envs x 5 RNG seeds, request-side.
# Each (env,seed) = 12 golden seeds x (1 original + 3 mutations) = 48 logical cases.
# Total = 3 x 5 x 48 = 720 logical cases, every one with REAL Witcher coverage +
# HttpParam internal-state. (Tomcat=Java and gevent=C-ext are not faithful-capable;
# see RESULT_witcher_full.md §coverage-matrix.)
set -u
P=/home/m321/doAn/AnToanMang/project
RUNNER=$P/04_fuzzer_engine/runner.py
SEEDS="1337 1338 1339 1340 1341"
MUT=3
OUT=$P/05_analyzer
REPORTS=crash_reports_cov_full

# env_name : compose_base : compose_override : proxy_port : backend_port
ENVS=(
  "nginx_gunicorn|$P/02_targets/nginx_gunicorn/docker-compose.yml|$P/02_targets/nginx_gunicorn/docker-compose.witcher.yml|8888|9001"
  "haproxy_gunicorn|$P/02_targets/haproxy_flask/docker-compose.witcher.yml|$P/02_targets/haproxy_flask/docker-compose.witcher.override.yml|8890|9003"
  "ats_gunicorn|$P/02_targets/ats_gevent/docker-compose.witcher.yml|$P/02_targets/ats_gevent/docker-compose.witcher.override.yml|8889|9002"
)

for spec in "${ENVS[@]}"; do
  IFS='|' read -r name base ovr pport bport <<< "$spec"
  for s in $SEEDS; do
    echo "================ ENV=$name SEED=$s ================"
    python3 "$RUNNER" --witcher --witcher-no-build \
      --witcher-compose-base "$base" \
      --witcher-compose-override "$ovr" \
      --proxy-port "$pport" --backend-port "$bport" \
      --mutations "$MUT" --random-seed "$s" \
      --reports-dir "${REPORTS}_${name}" \
      --trace-log "$OUT/trace_full_${name}_${s}.jsonl" \
      --quiet 2>&1 | tail -3
  done
done
echo "=========== FULL RUN COMPLETE ==========="

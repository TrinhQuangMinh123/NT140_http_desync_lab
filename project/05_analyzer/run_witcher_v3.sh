#!/usr/bin/env bash
# Exhaustive faithful run v3 (B4b v2 instrumentation: consumed/body split + full
# HttpParam capture). 3 gunicorn-backed envs x 8 RNG seeds x mut=50.
#   per (env,seed) = 12 golden x (1 original + 50 mutations) = 612 logical cases.
#   total = 3 x 8 x 612 = 14,688 logical cases.
# The FIRST seed of each env rebuilds the backend image (vendor_py changed);
# the remaining seeds reuse it (--witcher-no-build).
# Output goes to trace_full_v3_* / crash_reports_cov_v3_* so v2 data is untouched.
set -u
P=/home/m321/doAn/AnToanMang/project
RUNNER=$P/04_fuzzer_engine/runner.py
SEEDS="1337 1338 1339 1340 1341 1342 1343 1344"
MUT=50
OUT=$P/05_analyzer
REPORTS=crash_reports_cov_v3

# env_name : compose_base : compose_override : proxy_port : backend_port
ENVS=(
  "nginx_gunicorn|$P/02_targets/nginx_gunicorn/docker-compose.yml|$P/02_targets/nginx_gunicorn/docker-compose.witcher.yml|8888|9001"
  "haproxy_gunicorn|$P/02_targets/haproxy_flask/docker-compose.witcher.yml|$P/02_targets/haproxy_flask/docker-compose.witcher.override.yml|8890|9003"
  "ats_gunicorn|$P/02_targets/ats_gevent/docker-compose.witcher.yml|$P/02_targets/ats_gevent/docker-compose.witcher.override.yml|8889|9002"
)

for spec in "${ENVS[@]}"; do
  IFS='|' read -r name base ovr pport bport <<< "$spec"
  first=1
  for s in $SEEDS; do
    echo "================ ENV=$name SEED=$s  (build=$first) ================"
    # First seed of each env rebuilds the image (vendor_py changed); rest reuse.
    if [ "$first" -eq 1 ]; then
      BUILD_FLAG=""        # omit --witcher-no-build => up --build
      first=0
    else
      BUILD_FLAG="--witcher-no-build"
    fi
    python3 "$RUNNER" --witcher $BUILD_FLAG \
      --witcher-compose-base "$base" \
      --witcher-compose-override "$ovr" \
      --proxy-port "$pport" --backend-port "$bport" \
      --mutations "$MUT" --random-seed "$s" \
      --reports-dir "${REPORTS}_${name}" \
      --trace-log "$OUT/trace_full_v3_${name}_${s}.jsonl" \
      --quiet 2>&1 | tail -3
  done
done
echo "=========== V3 EXHAUSTIVE RUN COMPLETE ==========="

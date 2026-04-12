# End-to-End Integration Test Guide

## Overview

This document describes the end-to-end integration tests for the HTTP Desync Lab system (Task 7).

## Test File

`test_e2e_integration.py` - Comprehensive end-to-end integration test covering all aspects of Task 7.

## Prerequisites

1. **Docker and Docker Compose** must be installed and running
2. **Python 3.x** with required dependencies
3. Port **9080** must be available on the host machine

## Test Coverage

### Task 7.1: Docker Compose Startup
- Verifies `docker compose up` in `pairs/ats_gevent/` starts successfully
- Confirms Proxy is accessible on port 9080
- Confirms Backend container is running (internal port 5000)
- Validates startup completes within 60 seconds

### Task 7.2: Attacker Script and Report Generation
- Runs `python tester/run_test.py --target ats_gevent`
- Verifies `output/ats_gevent/report.json` is created
- Validates report contains:
  - `vulnerability_status = "CRITICAL - Smuggling Successful"`
  - `proxy_recognized_requests = 1`
  - `backend_recognized_requests = 2`
  - `smuggled_path_accessed = "/path2"`

### Task 7.3: Raw Traffic Log Verification
- Verifies `output/ats_gevent/raw_traffic.log` exists
- Validates log contains:
  - Separator line with timestamp
  - `[SENT BYTES]` section with payload
  - `[RECEIVED BYTES FROM PROXY]` section with response
  - `[BACKEND STDOUT]` section with backend output
  - Complete payload structure (POST /path1, chunked encoding, GET /path2)

### Task 7.4: Proxy Access Control
- Tests direct access to `/path2` → expects 403 Forbidden
- Tests direct access to `/path1` → expects 200 OK
- Confirms proxy correctly enforces access control rules

## Running the Tests

### Quick Start

```bash
cd http-desync-lab
python3 test_e2e_integration.py
```

### Manual Step-by-Step

If you prefer to run tests manually:

```bash
# 1. Start Docker containers
cd pairs/ats_gevent
docker compose up -d --build
cd ../..

# Wait for containers to be ready (check with docker compose ps)

# 2. Run the attacker script
python3 tester/run_test.py --target ats_gevent

# 3. Verify outputs
cat output/ats_gevent/report.json
cat output/ats_gevent/raw_traffic.log

# 4. Test direct access to /path2 (should get 403)
curl -v http://localhost:9080/path2

# 5. Test direct access to /path1 (should get 200)
curl -v http://localhost:9080/path1

# 6. Cleanup
cd pairs/ats_gevent
docker compose down
```

## Expected Results

When all tests pass, you should see:

```
======================================================================
✓ ALL END-TO-END INTEGRATION TESTS PASSED!
======================================================================

Task 7 completed successfully:
  ✓ 7.1: Docker compose startup verified
  ✓ 7.2: Attacker script and report verified
  ✓ 7.3: Raw traffic log verified
  ✓ 7.4: Proxy access control verified
```

## Troubleshooting

### Docker Not Available

If you see:
```
[!] WARNING: Docker is not available
```

**Solution:** Install Docker and Docker Compose:
- Ubuntu/Debian: `sudo apt-get install docker.io docker-compose`
- macOS: Install Docker Desktop
- Windows: Install Docker Desktop

### Port 9080 Already in Use

**Solution:** Stop the service using port 9080 or modify the port in `pairs/ats_gevent/docker-compose.yml`

### Containers Fail to Start

**Solution:** Check Docker logs:
```bash
cd pairs/ats_gevent
docker compose logs proxy
docker compose logs backend
```

### Test Timeout

If tests timeout during Docker build:
- Increase timeout in `test_e2e_integration.py`
- Pre-build images: `cd pairs/ats_gevent && docker compose build`

## Test Architecture

The test file (`test_e2e_integration.py`) is structured as follows:

```
main()
├── check_docker_available()
├── test_7_1_docker_compose_startup()
│   ├── Stop existing containers
│   ├── Start containers with docker compose up
│   ├── Wait for proxy port 9080
│   └── Verify startup time < 60s
├── test_7_2_attacker_script_and_report()
│   ├── Clean output directory
│   ├── Run attacker script
│   ├── Verify report.json exists
│   └── Validate report content
├── test_7_3_raw_traffic_log()
│   ├── Verify log file exists
│   ├── Check separator and timestamp
│   ├── Verify [SENT BYTES] section
│   ├── Verify [RECEIVED BYTES] section
│   └── Verify [BACKEND STDOUT] section
├── test_7_4_proxy_access_control()
│   ├── Test direct /path2 access → 403
│   └── Test direct /path1 access → 200
└── cleanup()
    └── Stop Docker containers
```

## Integration with CI/CD

To integrate with CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run E2E Tests
  run: |
    cd http-desync-lab
    python3 test_e2e_integration.py
```

## Related Files

- `test_tester_implementation.py` - Unit/integration tests for tester components
- `attacker/tests/test_properties.py` - Property-based tests
- `pairs/ats_gevent/docker-compose.yml` - Docker configuration
- `attacker/main.py` - Main attacker script (also accessible via `tester/run_test.py`)
- `tester/payloads/trailer_smuggle.txt` - Exploit payload

## Notes

- Tests automatically clean up Docker containers after completion
- Each test is independent and can be run separately if needed
- The test validates the complete attack chain from payload delivery to vulnerability detection
- All assertions follow the requirements specified in the design document

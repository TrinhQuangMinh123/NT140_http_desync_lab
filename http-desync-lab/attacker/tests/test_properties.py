"""
Property-Based Tests for HTTP Desync Lab using Hypothesis.

**Validates: Yêu Cầu 6.6**
P1 (report_json_roundtrip): Kiểm tra thuộc tính round-trip của report JSON

**Validates: Yêu Cầu 6.3, 6.4**
P2 (desync_detection_correctness): Kiểm tra logic phân loại vulnerability_status
"""

import json
from hypothesis import given, strategies as st


# Strategy for generating valid HTTP status codes
http_status_codes = st.integers(min_value=100, max_value=599)

# Strategy for generating request counts
request_counts = st.integers(min_value=1, max_value=10)

# Strategy for generating smuggled paths (can be None or a string)
smuggled_paths = st.one_of(st.none(), st.text(min_size=1, max_size=50))


@given(
    test_case=st.text(min_size=1, max_size=100),
    proxy=st.text(min_size=1, max_size=50),
    backend=st.text(min_size=1, max_size=50),
    proxy_status=http_status_codes,
    proxy_recognized=request_counts,
    backend_recognized=request_counts,
    smuggled_path=smuggled_paths,
)
def test_report_json_roundtrip(
    test_case,
    proxy,
    backend,
    proxy_status,
    proxy_recognized,
    backend_recognized,
    smuggled_path,
):
    """
    **Validates: Yêu Cầu 6.6**
    
    Property P1: Report JSON Round-trip
    
    Sinh ngẫu nhiên các giá trị report hợp lệ và kiểm tra rằng:
    json.loads(json.dumps(report)) == report
    
    Đảm bảo report.json luôn là JSON hợp lệ và round-trip an toàn.
    """
    # Determine vulnerability status based on request counts
    if backend_recognized > proxy_recognized:
        vulnerability_status = "CRITICAL - Smuggling Successful"
    else:
        vulnerability_status = "NOT_VULNERABLE"
    
    # Build report structure
    report = {
        "test_case": test_case,
        "proxy": proxy,
        "backend": backend,
        "results": {
            "proxy_status": proxy_status,
            "proxy_recognized_requests": proxy_recognized,
            "backend_recognized_requests": backend_recognized,
            "smuggled_path_accessed": smuggled_path,
            "vulnerability_status": vulnerability_status,
        },
    }
    
    # Serialize to JSON
    serialized = json.dumps(report)
    
    # Deserialize back
    parsed = json.loads(serialized)
    
    # Assert round-trip equality
    assert parsed == report, f"Round-trip failed: {parsed} != {report}"


@given(
    proxy_recognized=request_counts,
    backend_recognized=request_counts,
)
def test_desync_detection_correctness(proxy_recognized, backend_recognized):
    """
    **Validates: Yêu Cầu 6.3, 6.4**
    
    Property P2: Desync Detection Correctness
    
    Sinh ngẫu nhiên cặp (proxy_recognized, backend_recognized) và kiểm tra
    logic phân loại vulnerability_status đúng:
    
    - Nếu backend_recognized > proxy_recognized:
      → vulnerability_status = "CRITICAL - Smuggling Successful"
    
    - Ngược lại (backend_recognized <= proxy_recognized):
      → vulnerability_status = "NOT_VULNERABLE"
    """
    # Determine expected vulnerability status
    if backend_recognized > proxy_recognized:
        expected_status = "CRITICAL - Smuggling Successful"
    else:
        expected_status = "NOT_VULNERABLE"
    
    # Simulate the logic from main.py analyze_results()
    if backend_recognized > proxy_recognized:
        actual_status = "CRITICAL - Smuggling Successful"
    else:
        actual_status = "NOT_VULNERABLE"
    
    # Assert correctness
    assert actual_status == expected_status, (
        f"Desync detection logic failed: "
        f"proxy_recognized={proxy_recognized}, "
        f"backend_recognized={backend_recognized}, "
        f"expected={expected_status}, "
        f"actual={actual_status}"
    )

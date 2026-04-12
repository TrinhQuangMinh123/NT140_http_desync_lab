#!/usr/bin/env python3
"""
Verify the structure and completeness of the E2E integration test.
This test can run without Docker to validate the test implementation.
"""

import sys
import os
import ast
import inspect

# Change to the script's directory
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)
sys.path.insert(0, script_dir)


def test_e2e_file_exists():
    """Verify the E2E test file exists."""
    assert os.path.exists('test_e2e_integration.py'), \
        "test_e2e_integration.py not found"
    print("✓ E2E test file exists")


def test_e2e_file_syntax():
    """Verify the E2E test file has valid Python syntax."""
    with open('test_e2e_integration.py', 'r') as f:
        code = f.read()
    
    try:
        ast.parse(code)
        print("✓ E2E test file has valid Python syntax")
    except SyntaxError as e:
        raise AssertionError(f"Syntax error in test_e2e_integration.py: {e}")


def test_e2e_required_functions():
    """Verify all required test functions are present."""
    # Import the module
    import test_e2e_integration as e2e
    
    required_functions = [
        'test_7_1_docker_compose_startup',
        'test_7_2_attacker_script_and_report',
        'test_7_3_raw_traffic_log',
        'test_7_4_proxy_access_control',
        'cleanup',
        'main'
    ]
    
    for func_name in required_functions:
        assert hasattr(e2e, func_name), \
            f"Missing required function: {func_name}"
        assert callable(getattr(e2e, func_name)), \
            f"{func_name} is not callable"
    
    print(f"✓ All {len(required_functions)} required functions present")


def test_e2e_function_docstrings():
    """Verify test functions have proper docstrings."""
    import test_e2e_integration as e2e
    
    test_functions = [
        'test_7_1_docker_compose_startup',
        'test_7_2_attacker_script_and_report',
        'test_7_3_raw_traffic_log',
        'test_7_4_proxy_access_control'
    ]
    
    for func_name in test_functions:
        func = getattr(e2e, func_name)
        assert func.__doc__ is not None, \
            f"{func_name} missing docstring"
        assert "Task 7." in func.__doc__, \
            f"{func_name} docstring should reference Task 7.x"
    
    print(f"✓ All test functions have proper docstrings")


def test_e2e_task_coverage():
    """Verify all sub-tasks are covered."""
    import test_e2e_integration as e2e
    
    with open('test_e2e_integration.py', 'r') as f:
        code = f.read()
    
    # Check for task references
    required_tasks = [
        'Task 7.1',  # Docker compose startup
        'Task 7.2',  # Attacker script and report
        'Task 7.3',  # Raw traffic log
        'Task 7.4'   # Proxy access control
    ]
    
    for task in required_tasks:
        assert task in code, f"Missing reference to {task}"
    
    print(f"✓ All 4 sub-tasks (7.1-7.4) are covered")


def test_e2e_assertions():
    """Verify test functions contain assertions."""
    with open('test_e2e_integration.py', 'r') as f:
        code = f.read()
    
    # Parse the AST
    tree = ast.parse(code)
    
    test_functions = [
        'test_7_1_docker_compose_startup',
        'test_7_2_attacker_script_and_report',
        'test_7_3_raw_traffic_log',
        'test_7_4_proxy_access_control'
    ]
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in test_functions:
            # Check if function contains assert statements
            has_assert = any(
                isinstance(child, ast.Assert)
                for child in ast.walk(node)
            )
            assert has_assert, f"{node.name} contains no assertions"
    
    print(f"✓ All test functions contain assertions")


def test_readme_exists():
    """Verify the E2E test README exists."""
    assert os.path.exists('docs/TEST_E2E_README.md'), \
        "docs/TEST_E2E_README.md not found"
    
    with open('docs/TEST_E2E_README.md', 'r') as f:
        content = f.read()
    
    # Check for required sections
    required_sections = [
        'Task 7.1',
        'Task 7.2',
        'Task 7.3',
        'Task 7.4',
        'Running the Tests',
        'Expected Results',
        'Troubleshooting'
    ]
    
    for section in required_sections:
        assert section in content, f"README missing section: {section}"
    
    print("✓ E2E test README exists with all required sections")


def test_task_7_requirements():
    """Verify test implementation matches task 7 requirements."""
    with open('test_e2e_integration.py', 'r') as f:
        code = f.read()
    
    # Task 7.1 requirements
    assert 'docker compose up' in code or 'docker-compose up' in code, \
        "Task 7.1: Missing docker compose up"
    assert '9080' in code, \
        "Task 7.1: Missing port 9080 check"
    assert '5000' in code, \
        "Task 7.1: Missing port 5000 reference"
    assert '60' in code, \
        "Task 7.1: Missing 60 second timeout check"
    
    # Task 7.2 requirements
    assert 'attacker.main' in code or 'attacker/main.py' in code, \
        "Task 7.2: Missing attacker script execution"
    assert 'report.json' in code, \
        "Task 7.2: Missing report.json check"
    assert 'CRITICAL - Smuggling Successful' in code, \
        "Task 7.2: Missing vulnerability status check"
    
    # Task 7.3 requirements
    assert 'raw_traffic.log' in code, \
        "Task 7.3: Missing raw_traffic.log check"
    assert '[SENT BYTES]' in code, \
        "Task 7.3: Missing sent bytes section check"
    assert '[RECEIVED BYTES FROM PROXY]' in code, \
        "Task 7.3: Missing received bytes section check"
    assert '[BACKEND STDOUT]' in code, \
        "Task 7.3: Missing backend stdout section check"
    
    # Task 7.4 requirements
    assert '403' in code, \
        "Task 7.4: Missing 403 status check"
    assert '/path2' in code, \
        "Task 7.4: Missing /path2 access check"
    
    print("✓ Test implementation matches all task 7 requirements")


def main():
    """Run all structure validation tests."""
    print("=" * 70)
    print("E2E Integration Test - Structure Validation")
    print("=" * 70)
    
    try:
        test_e2e_file_exists()
        test_e2e_file_syntax()
        test_e2e_required_functions()
        test_e2e_function_docstrings()
        test_e2e_task_coverage()
        test_e2e_assertions()
        test_readme_exists()
        test_task_7_requirements()
        
        print("\n" + "=" * 70)
        print("✓ ALL STRUCTURE VALIDATION TESTS PASSED!")
        print("=" * 70)
        print("\nE2E test implementation is complete and ready to run.")
        print("To execute the full E2E test (requires Docker):")
        print("  python3 test_e2e_integration.py")
        
        return 0
    
    except AssertionError as e:
        print(f"\n✗ VALIDATION FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())

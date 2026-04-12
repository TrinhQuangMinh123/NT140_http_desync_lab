#!/usr/bin/env python3
"""
Entry point alias for attacker/main.py
This script provides a convenient entry point in the tester/ directory
that delegates to the main attacker script.
"""

import sys
import os

# Add parent directory to path to import attacker module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from attacker.main import main

if __name__ == "__main__":
    main()

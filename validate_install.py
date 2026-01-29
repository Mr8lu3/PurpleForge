#!/usr/bin/env python3
"""
PurpleForge Installation Validation Script

This script checks that PurpleForge is correctly installed and configured.
Run this after installation to verify everything is working.
"""

import sys
from pathlib import Path


def check_python_version():
    """Check Python version is 3.11+."""
    print("Checking Python version...", end=" ")
    if sys.version_info < (3, 11):
        print("FAIL")
        print(f"  Python 3.11+ required, found {sys.version_info.major}.{sys.version_info.minor}")
        return False
    print(f"OK (Python {sys.version_info.major}.{sys.version_info.minor})")
    return True


def check_imports():
    """Check all required imports."""
    print("Checking imports...", end=" ")
    try:
        import typer
        import pydantic
        import rich
        import yaml
        import requests
        import jinja2
        print("OK")
        return True
    except ImportError as e:
        print("FAIL")
        print(f"  Missing dependency: {e}")
        return False


def check_purpleforge_import():
    """Check PurpleForge package can be imported."""
    print("Checking PurpleForge package...", end=" ")
    try:
        import purpleforge
        print(f"OK (version {purpleforge.__version__})")
        return True
    except ImportError as e:
        print("FAIL")
        print(f"  Cannot import purpleforge: {e}")
        return False


def check_modules():
    """Check all PurpleForge modules can be imported."""
    print("Checking modules...", end=" ")
    try:
        from purpleforge.cli import main
        from purpleforge.config import Config
        from purpleforge.scenarios import Scenario
        from purpleforge.verification import verify_target_ownership
        from purpleforge.workspace import WorkspaceManager
        from purpleforge.runners import WebRunner
        from purpleforge.correlation import CorrelationEngine
        from purpleforge.reporting import ReportGenerator
        print("OK")
        return True
    except ImportError as e:
        print("FAIL")
        print(f"  Cannot import module: {e}")
        return False


def check_cli_command():
    """Check CLI command is available."""
    print("Checking CLI command...", end=" ")
    import shutil
    if shutil.which("purpleforge"):
        print("OK")
        return True
    else:
        print("FAIL")
        print("  'purpleforge' command not found in PATH")
        print("  Try: pip install -e .")
        return False


def check_sample_scenario():
    """Check sample scenario exists and is valid."""
    print("Checking sample scenario...", end=" ")
    scenario_path = Path("scenarios/sample-web-assess.yml")
    if not scenario_path.exists():
        print("FAIL")
        print(f"  Sample scenario not found: {scenario_path}")
        return False

    try:
        from purpleforge.scenarios import load_scenario
        scenario = load_scenario(scenario_path)
        print(f"OK ({scenario.name})")
        return True
    except Exception as e:
        print("FAIL")
        print(f"  Cannot load scenario: {e}")
        return False


def check_templates():
    """Check report templates exist."""
    print("Checking report templates...", end=" ")
    template_path = Path("purpleforge/reporting/templates/incident_report.md.j2")
    if not template_path.exists():
        print("FAIL")
        print(f"  Template not found: {template_path}")
        return False
    print("OK")
    return True


def main():
    """Run all validation checks."""
    print("=" * 60)
    print("PurpleForge Installation Validation")
    print("=" * 60)
    print()

    checks = [
        check_python_version,
        check_imports,
        check_purpleforge_import,
        check_modules,
        check_cli_command,
        check_sample_scenario,
        check_templates,
    ]

    results = []
    for check in checks:
        try:
            result = check()
            results.append(result)
        except Exception as e:
            print(f"ERROR: {e}")
            results.append(False)
        print()

    # Summary
    print("=" * 60)
    passed = sum(results)
    total = len(results)

    if all(results):
        print(f"SUCCESS: All {total} checks passed!")
        print()
        print("PurpleForge is correctly installed and ready to use.")
        print()
        print("Next steps:")
        print("  1. Run: purpleforge init")
        print("  2. Run: purpleforge validate scenarios/sample-web-assess.yml")
        print("  3. See SETUP_GUIDE.md for full walkthrough")
        return 0
    else:
        print(f"FAILED: {passed}/{total} checks passed")
        print()
        print("Please fix the errors above and try again.")
        print("See SETUP_GUIDE.md for installation instructions.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

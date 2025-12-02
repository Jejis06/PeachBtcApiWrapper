"""
Pytest configuration for Peach Bitcoin API Wrapper tests.
"""

import pytest


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", 
        "slow: marks tests as slow (creates real offers - deselect with '-m \"not slow\"')"
    )


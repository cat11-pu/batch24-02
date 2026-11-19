import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import pytest

import signature_guard as sg


@pytest.fixture(autouse=True)
def _reset_replay_cache():
    sg.reset()
    yield
    sg.reset()

import pytest

import signature_guard as sg

PARAMS = [("b", "2"), ("a", "1")]
SORTED = [("a", "1"), ("b", "2")]
SECRET = "correct horse battery staple"


def test_1_valid_unsorted_params_are_accepted():
    timestamp = 1000
    signature = sg.sign(PARAMS, SECRET, timestamp)
    assert sg.verify(PARAMS, SECRET, signature, timestamp, now=timestamp) is True


def test_2_empty_signature_is_rejected():
    timestamp = 1000
    signature = sg.sign(SORTED, SECRET, timestamp)
    with pytest.raises(ValueError):
        sg.verify(SORTED, SECRET, "", timestamp, now=timestamp)


def test_3_missing_signature_is_rejected():
    timestamp = 1000
    with pytest.raises(ValueError):
        sg.verify(SORTED, SECRET, None, timestamp, now=timestamp)


def test_4_empty_secret_is_rejected():
    timestamp = 1000
    with pytest.raises(ValueError):
        sg.verify(SORTED, "", "deadbeef", timestamp, now=timestamp)


def test_5_short_secret_is_rejected():
    timestamp = 1000
    with pytest.raises(ValueError):
        sg.verify(SORTED, "x", "deadbeef", timestamp, now=timestamp)


def test_6_expired_timestamp_is_rejected():
    timestamp = 1000
    signature = sg.sign(SORTED, SECRET, timestamp)
    with pytest.raises(ValueError):
        sg.verify(SORTED, SECRET, signature, timestamp, now=2000, max_age=300)


def test_7_future_timestamp_is_rejected():
    timestamp = 2000
    signature = sg.sign(SORTED, SECRET, timestamp)
    with pytest.raises(ValueError):
        sg.verify(SORTED, SECRET, signature, timestamp, now=1000)


def test_8_replayed_signature_is_rejected():
    timestamp = 1000
    signature = sg.sign(SORTED, SECRET, timestamp)
    assert sg.verify(SORTED, SECRET, signature, timestamp, now=timestamp) is True
    with pytest.raises(ValueError):
        sg.verify(SORTED, SECRET, signature, timestamp, now=timestamp)


def test_9_missing_timestamp_is_rejected():
    signature = sg.sign(SORTED, SECRET, None)
    with pytest.raises(ValueError):
        sg.verify(SORTED, SECRET, signature, None, now=1000)


def test_10_non_integer_timestamp_is_rejected():
    signature = sg.sign(SORTED, SECRET, "abc")
    with pytest.raises(ValueError):
        sg.verify(SORTED, SECRET, signature, "abc", now=1000)


def test_11_duplicate_param_keys_are_rejected():
    params = [("a", "1"), ("a", "2")]
    timestamp = 1000
    signature = sg.sign(params, SECRET, timestamp)
    with pytest.raises(ValueError):
        sg.verify(params, SECRET, signature, timestamp, now=timestamp)


def test_12_mapping_params_are_rejected():
    timestamp = 1000
    with pytest.raises(TypeError):
        sg.verify({"a": "1"}, SECRET, "deadbeef", timestamp, now=timestamp)


def test_13_bytes_signature_is_rejected():
    timestamp = 1000
    with pytest.raises(TypeError):
        sg.verify(SORTED, SECRET, b"deadbeef", timestamp, now=timestamp)


def test_14_non_string_secret_is_rejected():
    timestamp = 1000
    with pytest.raises(TypeError):
        sg.verify(SORTED, 123, "deadbeef", timestamp, now=timestamp)


def test_15_none_params_are_rejected():
    timestamp = 1000
    with pytest.raises(ValueError):
        sg.verify(None, SECRET, "deadbeef", timestamp, now=timestamp)

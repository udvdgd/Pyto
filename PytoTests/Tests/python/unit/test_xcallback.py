"""Tests for ``Lib/xcallback.py``."""

from urllib.parse import parse_qs, urlparse

import pytest


class CallbackHelper:
    """A fake ``PyCallbackHelper`` answering with the given URL."""

    url = None


@pytest.fixture
def opened():
    return []


@pytest.fixture
def xcallback(monkeypatch, fake_pyto, lib_module, opened):
    fake_pyto.PyCallbackHelper = CallbackHelper
    CallbackHelper.url = None

    module = lib_module("xcallback")
    monkeypatch.setattr(module.webbrowser, "open", opened.append)
    return module


def answer(url):
    CallbackHelper.url = url


def test_open_url_is_not_supported_without_the_main_app(fake_pyto, lib_module):
    fake_pyto.PyCallbackHelper = None
    module = lib_module("xcallback")

    with pytest.raises(NotImplementedError):
        module.open_url("bear://x-callback-url/open-note")


def test_open_url_adds_the_callback_params(xcallback, opened):
    answer("pyto://callback/?result=ok")
    xcallback.open_url("bear://x-callback-url/open-note?id=1")

    params = parse_qs(urlparse(opened[0]).query)
    assert params["id"] == ["1"]
    assert params["x-source"] == ["Pyto"]
    for key in ("x-success", "x-cancel", "x-error"):
        assert params[key] == ["pyto://callback/"]


def test_open_url_returns_the_result(xcallback):
    answer("pyto://callback/?result=some%20text")
    assert xcallback.open_url("bear://x-callback-url/open-note") == "some text"


def test_open_url_resets_the_pending_url(xcallback):
    answer("pyto://callback/?result=ok")
    xcallback.open_url("bear://x-callback-url/open-note")
    assert CallbackHelper.url is None


def test_open_url_returns_the_only_param_when_there_is_no_result(xcallback):
    answer("pyto://callback/?note=content")
    assert xcallback.open_url("bear://x-callback-url/open-note") == "content"


def test_open_url_raises_the_error_message(xcallback):
    answer("pyto://callback/?errorMessage=something%20failed")

    with pytest.raises(RuntimeError, match="something failed"):
        xcallback.open_url("bear://x-callback-url/open-note")


def test_open_url_exits_when_cancelled(xcallback):
    answer("pyto://callback/")

    with pytest.raises(SystemExit):
        xcallback.open_url("bear://x-callback-url/open-note")


def test_open_url_exits_when_several_params_are_returned(xcallback):
    answer("pyto://callback/?first=1&second=2")

    with pytest.raises(SystemExit):
        xcallback.open_url("bear://x-callback-url/open-note")


def test_open_url_keeps_semicolons_in_the_result(xcallback):
    answer("pyto://callback/?result=a;b")
    assert xcallback.open_url("bear://x-callback-url/open-note") == "a;b"

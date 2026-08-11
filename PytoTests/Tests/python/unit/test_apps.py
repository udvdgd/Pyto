"""Tests for ``Lib/apps.py``."""

from urllib.parse import parse_qs, urlparse

import pytest


@pytest.fixture
def apps(monkeypatch, fake_pyto, lib_module):
    module = lib_module("apps")
    module.opened = []
    module.callbacks = []
    monkeypatch.setattr(module.webbrowser, "open", module.opened.append)
    monkeypatch.setattr(
        module.xcallback,
        "open_url",
        lambda url: module.callbacks.append(url) or "result",
    )
    return module


def test_url_with_params_of_an_empty_dict(apps):
    assert apps.url_with_params("blackbox://", {}) == "blackbox://"


def test_url_with_params_adds_a_query_string(apps):
    url = apps.url_with_params("workflow://open-workflow", {"name": "My Workflow"})
    assert urlparse(url).query == "name=My%20Workflow"


def test_url_with_params_separates_params_with_an_ampersand(apps):
    url = apps.url_with_params("pricetag://search", {"key": "a", "p": "2"})
    assert parse_qs(urlparse(url).query) == {"key": ["a"], "p": ["2"]}


def test_url_with_params_skips_none_values(apps):
    url = apps.url_with_params("pricetag://search", {"key": "a", "p": None})
    assert url == "pricetag://search?key=a"


def test_url_with_params_only_skipped_values_gives_an_empty_query(apps):
    assert apps.url_with_params("pricetag://search", {"p": None}) == "pricetag://search"


def test_url_with_params_escapes_special_characters(apps):
    url = apps.url_with_params("bear://create", {"text": "a&b=c?d"})
    assert parse_qs(urlparse(url).query) == {"text": ["a&b=c?d"]}


def test_action_without_result_opens_the_url(apps):
    apps.Blackbox().open()
    assert apps.opened == ["blackbox://"]
    assert apps.callbacks == []


def test_action_with_a_result_uses_an_x_callback_url(apps):
    assert apps.Bear().open_note(id="1") == "result"
    assert apps.opened == []
    assert len(apps.callbacks) == 1

    parsed = urlparse(apps.callbacks[0])
    assert parsed.scheme == "bear"
    assert parsed.path == "/open-note"
    assert parse_qs(parsed.query) == {"id": ["1"]}


def test_optional_arguments_are_not_sent(apps):
    apps.Terminology().lookup("word")
    assert parse_qs(urlparse(apps.callbacks[0]).query) == {"text": ["word"]}


def test_optional_arguments_are_sent_when_given(apps):
    apps.Terminology().lookup("word", action="define")
    assert parse_qs(urlparse(apps.callbacks[0]).query) == {
        "text": ["word"],
        "action": ["define"],
    }

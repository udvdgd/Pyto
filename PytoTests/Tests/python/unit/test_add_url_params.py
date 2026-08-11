"""Tests for ``Lib/_add_url_params.py``."""

from urllib.parse import parse_qs, urlparse

from _add_url_params import add_url_params


def query(url):
    return parse_qs(urlparse(url).query)


def test_adds_params_to_url_without_query():
    url = add_url_params("http://example.com/test", {"a": "1"})
    assert urlparse(url).path == "/test"
    assert query(url) == {"a": ["1"]}


def test_keeps_existing_params():
    url = add_url_params("http://example.com/test?answers=true", {"data": "value"})
    assert query(url) == {"answers": ["true"], "data": ["value"]}


def test_overrides_existing_params():
    url = add_url_params("http://example.com/test?answers=true", {"answers": "false"})
    assert query(url) == {"answers": ["false"]}


def test_encodes_lists_as_repeated_params():
    url = add_url_params("http://example.com/test", {"data": ["some", "values"]})
    assert query(url) == {"data": ["some", "values"]}


def test_encodes_booleans_as_json():
    url = add_url_params("http://example.com/test", {"answers": False})
    assert query(url) == {"answers": ["false"]}


def test_encodes_dicts_as_json():
    url = add_url_params("http://example.com/test", {"data": {"key": 1}})
    assert query(url) == {"data": ['{"key": 1}']}


def test_keeps_scheme_netloc_and_fragment():
    url = add_url_params("https://example.com/a/b#frag", {"a": "1"})
    parsed = urlparse(url)
    assert (parsed.scheme, parsed.netloc, parsed.path, parsed.fragment) == (
        "https",
        "example.com",
        "/a/b",
        "frag",
    )


def test_unquotes_the_original_url():
    url = add_url_params("http://example.com/test?text=hello%20world", {"a": "1"})
    assert query(url)["text"] == ["hello world"]


def test_supports_custom_schemes():
    url = add_url_params("bear://x-callback-url/create", {"title": "Note"})
    assert url.startswith("bear://x-callback-url/create?")
    assert query(url) == {"title": ["Note"]}


def test_no_params_keeps_url_unchanged():
    assert add_url_params("http://example.com/test?a=1", {}) == "http://example.com/test?a=1"

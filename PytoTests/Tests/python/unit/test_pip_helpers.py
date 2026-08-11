"""Tests for the helpers of ``Lib/_pip.py``."""

import os
import sys

import pytest


@pytest.fixture
def site_packages(tmp_path):
    """A directory containing a dist-info and an egg-info package."""

    dist_info = tmp_path / "requests-2.31.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n", encoding="utf-8"
    )

    egg_info = tmp_path / "legacy.egg-info"
    egg_info.mkdir()
    (egg_info / "PKG-INFO").write_text("Name: legacy\n", encoding="utf-8")

    return tmp_path


@pytest.fixture
def _pip(monkeypatch, lib_module, tmp_path):
    """The ``_pip`` module, imported with a controlled ``sys.path``.

    ``_pip`` looks for the installed packages of every ``sys.path`` entry while
    being imported, so the search path is replaced by an empty directory.
    """

    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(sys, "path", [str(empty)])
    return lib_module("_pip")


def test_default_index_without_mirror(monkeypatch, _pip):
    monkeypatch.delenv("PYPI_MIRROR", raising=False)
    assert _pip.default_index() == "https://pypi.python.org/pypi"


def test_default_index_strips_the_simple_endpoint(monkeypatch, _pip):
    monkeypatch.setenv("PYPI_MIRROR", "https://pypi.tuna.tsinghua.edu.cn/simple")
    assert _pip.default_index() == "https://pypi.tuna.tsinghua.edu.cn/pypi"


def test_default_index_strips_a_trailing_slash(monkeypatch, _pip):
    monkeypatch.setenv("PYPI_MIRROR", "https://pypi.tuna.tsinghua.edu.cn/simple/")
    assert _pip.default_index() == "https://pypi.tuna.tsinghua.edu.cn/pypi"


def test_default_index_of_a_mirror_without_simple_endpoint(monkeypatch, _pip):
    monkeypatch.setenv("PYPI_MIRROR", "https://mirror.example.com")
    assert _pip.default_index() == "https://mirror.example.com/pypi"


def test_bundled_modules_are_read_while_importing(_pip):
    assert _pip.BUNDLED_MODULES == ["rubicon-objc", "toga"]


def test_get_modules_reads_dist_info_and_egg_info(monkeypatch, _pip, site_packages):
    monkeypatch.setattr(sys, "path", [str(site_packages)])
    modules = _pip._get_modules()
    assert "requests" in modules
    assert "legacy" in modules


def test_get_modules_always_includes_the_bundled_dependencies(monkeypatch, _pip, tmp_path):
    monkeypatch.setattr(sys, "path", [str(tmp_path / "empty")])
    assert _pip._get_modules() == ["rubicon-objc", "toga"]


def test_get_modules_ignores_zipped_paths(monkeypatch, _pip, tmp_path):
    archive = tmp_path / "python310.zip"
    archive.write_bytes(b"")
    monkeypatch.setattr(sys, "path", [str(archive)])
    assert _pip._get_modules() == ["rubicon-objc", "toga"]


def test_get_modules_ignores_missing_paths(monkeypatch, _pip, tmp_path):
    monkeypatch.setattr(sys, "path", [str(tmp_path / "does-not-exist")])
    assert _pip._get_modules() == ["rubicon-objc", "toga"]


def test_bundled_only_skips_writable_paths(monkeypatch, _pip, site_packages):
    monkeypatch.setattr(sys, "path", [str(site_packages)])
    assert os.access(str(site_packages), os.W_OK)
    assert _pip._get_modules(bundled_only=True) == ["rubicon-objc", "toga"]


def test_bundled_only_reads_read_only_paths(monkeypatch, _pip, site_packages):
    monkeypatch.setattr(sys, "path", [str(site_packages)])
    monkeypatch.setattr(_pip.os, "access", lambda path, mode: False)
    assert "requests" in _pip._get_modules(bundled_only=True)

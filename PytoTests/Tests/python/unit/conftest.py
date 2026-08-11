"""
Shared configuration for the host runnable unit tests.

The modules in ``Lib`` are written for iOS and some of them import modules
provided by the app at runtime. The fixtures below install fake versions of
those modules so that the pure Python logic can be tested on a desktop.
"""

import importlib.util
import os
import sys
import types

import pytest

LIB_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "Lib")
)

if LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)


def _install(monkeypatch, name, module):
    monkeypatch.setitem(sys.modules, name, module)
    return module


@pytest.fixture
def fake_rubicon(monkeypatch):
    """Installs a ``rubicon.objc`` package returning ``None`` for every class."""

    rubicon = types.ModuleType("rubicon")
    objc = types.ModuleType("rubicon.objc")
    api = types.ModuleType("rubicon.objc.api")

    def ObjCClass(class_name):
        return None

    class NSString:
        pass

    for module in (objc, api):
        module.ObjCClass = ObjCClass
        module.NSString = NSString

    rubicon.objc = objc
    objc.api = api

    _install(monkeypatch, "rubicon", rubicon)
    _install(monkeypatch, "rubicon.objc", objc)
    _install(monkeypatch, "rubicon.objc.api", api)
    return objc


@pytest.fixture
def fake_pyto(monkeypatch, fake_rubicon):
    """Installs a ``pyto`` module with every helper class set to ``None``."""

    pyto = types.ModuleType("pyto")

    helpers = (
        "PyCallbackHelper",
        "PyInputHelper",
        "PyOutputHelper",
        "PySharingHelper",
        "Python",
        "QuickLookHelper",
    )
    for helper in helpers:
        setattr(pyto, helper, None)

    pyto.__Class__ = lambda name: None
    pyto.__isMainApp__ = lambda: False
    pyto.__is_appex__ = lambda: False
    pyto.ignored_threads_on_crash = []

    return _install(monkeypatch, "pyto", pyto)


@pytest.fixture
def fake_userkeys(monkeypatch):
    """Installs a ``userkeys`` module backed by an in memory dictionary."""

    userkeys = types.ModuleType("userkeys")
    storage = {}

    def get(key):
        return storage[key]

    def set_(value, key):
        storage[key] = value

    def delete(key):
        del storage[key]

    userkeys.get = get
    userkeys.set = set_
    userkeys.delete = delete
    userkeys.storage = storage

    return _install(monkeypatch, "userkeys", userkeys)


class FakeFilePicker:
    """Records the configuration set by the module under test."""

    def __init__(self):
        self.file_types = []
        self.file_extensions = []
        self.mime_types = []
        self.allows_multiple_selection = False


@pytest.fixture
def fake_sharing(monkeypatch):
    """Installs a ``sharing`` module with a file picker returning fake paths."""

    sharing = types.ModuleType("sharing")
    sharing.FilePicker = FakeFilePicker
    sharing.picked = []
    sharing.pickers = []

    def pick_documents(picker):
        sharing.pickers.append(picker)

    sharing.pick_documents = pick_documents
    sharing.picked_files = lambda: list(sharing.picked)
    sharing.shared = []
    sharing.share_items = sharing.shared.append

    _install(monkeypatch, "sharing", sharing)
    _install(monkeypatch, "_sharing", sharing)
    return sharing


def _forget_lib_modules():
    """Removes the modules imported from ``Lib`` from the module cache."""

    for name, module in list(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if path is not None and os.path.dirname(os.path.abspath(path)) == LIB_DIR:
            del sys.modules[name]


@pytest.fixture
def lib_module():
    """Imports a module from ``Lib`` by path, ignoring the module cache.

    Modules from ``Lib`` read their dependencies at import time, so a module has
    to be imported again once the fakes above are installed.
    """

    def _lib_module(name):
        _forget_lib_modules()
        spec = importlib.util.spec_from_file_location(
            name, os.path.join(LIB_DIR, name + ".py")
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    yield _lib_module
    _forget_lib_modules()

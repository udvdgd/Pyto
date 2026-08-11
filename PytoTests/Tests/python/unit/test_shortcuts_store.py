"""Tests for ``Lib/__shortcuts_store__.py``."""

import pytest

import __shortcuts_store__ as store


@pytest.fixture(autouse=True)
def empty_store():
    store.objects.clear()
    yield
    store.objects.clear()


class Parameter:
    """A fake Shortcuts parameter."""

    def __init__(self, string_value=None, address=None):
        self.stringValue = string_value
        self.address = address


def test_random_string_has_the_requested_length():
    assert len(store.get_random_string(10)) == 10


def test_random_string_only_contains_digits():
    assert store.get_random_string(30).isdigit()


def test_import_module_stores_the_module():
    identifier, description = store.import_module("json")

    import json

    assert store.objects[identifier] is json
    assert description == str(json)


def test_import_script_executes_and_stores_the_script(tmp_path):
    script = tmp_path / "my_script.py"
    script.write_text("value = 42\n", encoding="utf-8")

    identifier, _ = store.import_script(str(script))

    assert store.objects[identifier].value == 42


def test_get_property_stores_the_attribute():
    module_id, _ = store.import_module("json")
    identifier, description = store.get_property("dumps", module_id)

    import json

    assert store.objects[identifier] is json.dumps
    assert description == str(json.dumps)


def test_get_property_of_an_unknown_object_raises():
    with pytest.raises(KeyError):
        store.get_property("dumps", "unknown")


def test_get_property_of_a_missing_attribute_raises():
    module_id, _ = store.import_module("json")
    with pytest.raises(AttributeError):
        store.get_property("does_not_exist", module_id)


def test_call_function_with_string_parameters():
    store.objects["callable"] = lambda text: text.upper()

    identifier, description = store.call_function("callable", [Parameter("hello")])

    assert store.objects[identifier] == "HELLO"
    assert description == "HELLO"


def test_call_function_with_a_stored_object_as_parameter():
    store.objects["value"] = [1, 2, 3]
    store.objects["callable"] = len

    identifier, _ = store.call_function("callable", [Parameter(address="value")])

    assert store.objects[identifier] == 3


def test_call_function_with_a_plain_parameter():
    store.objects["callable"] = lambda text: text + "!"

    identifier, _ = store.call_function("callable", ["hello"])

    assert store.objects[identifier] == "hello!"


def test_call_function_with_several_parameters_keeps_their_order():
    store.objects["callable"] = lambda first, second: first + second

    identifier, _ = store.call_function(
        "callable", [Parameter("a"), Parameter("b")]
    )

    assert store.objects[identifier] == "ab"


def test_call_function_ignores_empty_parameters():
    store.objects["callable"] = lambda *args: len(args)

    identifier, _ = store.call_function("callable", [Parameter()])

    assert store.objects[identifier] == 0

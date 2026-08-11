"""Tests for ``Lib/__check_type__.py``."""

from enum import Enum, IntFlag

import pytest

from __check_type__ import check, func


class Color(Enum):
    RED = "red"


class Options(IntFlag):
    NONE = 0
    FIRST = 1


def test_accepts_matching_type():
    check("value", "name", [str])


def test_accepts_any_of_the_given_types():
    check(1, "name", [str, int])


def test_accepts_subclasses():
    class Sub(Exception):
        pass

    check(Sub(), "name", [Exception])


def test_none_is_translated_to_the_none_type():
    check(None, "name", [str, None])


def test_rejects_none_when_not_allowed():
    with pytest.raises(TypeError):
        check(None, "name", [str])


def test_rejects_wrong_type():
    with pytest.raises(TypeError):
        check(1.5, "name", [str, int])


def test_error_message_contains_the_parameter_name_and_types():
    with pytest.raises(TypeError) as error:
        check(1.5, "duration", [str])

    message = str(error.value)
    assert "'duration'" in message
    assert "str" in message


def test_callables_are_accepted_when_a_function_type_is_expected():
    check(lambda: None, "name", [func])
    check(check, "name", [func])


def test_non_callables_are_rejected_when_a_function_type_is_expected():
    with pytest.raises(TypeError):
        check("not callable", "name", [func])


@pytest.mark.xfail(
    reason="check() returns None, so the Enum branch of check() never succeeds",
    raises=TypeError,
    strict=True,
)
def test_enum_values_are_unwrapped():
    check(Color.RED, "name", [str])


def test_int_flag_values_are_unwrapped():
    check(Options.FIRST, "name", [int])


def test_enum_with_an_unexpected_value_is_rejected():
    with pytest.raises(TypeError):
        check(Color.RED, "name", [int])


def test_objects_looking_like_a_pytoui_view_are_accepted():
    class View:
        pass

    View.__module__ = "pyto_ui"

    class CustomView:
        __py_view__ = object()

    check(CustomView(), "view", [View])


def test_objects_not_looking_like_a_pytoui_view_are_rejected():
    class View:
        pass

    View.__module__ = "pyto_ui"

    with pytest.raises(TypeError):
        check(object(), "view", [View])

"""Tests for ``Lib/outputredirector.py``."""

import io
import sys

import pytest

import outputredirector
from outputredirector import InputReader, Reader, isatty


@pytest.fixture
def written():
    return []


@pytest.fixture
def reader(written):
    return Reader(written.append)


def test_isatty_is_true_outside_of_shortcuts(monkeypatch):
    monkeypatch.delattr(sys, "__is_shortcut__", raising=False)
    assert isatty() is True


def test_isatty_is_false_inside_shortcuts(monkeypatch):
    monkeypatch.setattr(sys, "__is_shortcut__", True, raising=False)
    assert isatty() is False


def test_reader_passes_strings_to_the_handler(reader, written):
    reader.write("hello")
    assert written == ["hello"]


def test_reader_decodes_bytes(reader, written):
    reader.write("héllo".encode("utf-8"))
    assert written == ["héllo"]


def test_reader_ignores_other_types(reader, written):
    reader.write(42)
    assert written == []


def test_reader_is_writable_but_not_readable(reader):
    assert reader.writable() is True
    assert reader.readable() is False
    assert reader.closed is False
    assert reader.encoding == "utf-8"


def test_reader_read_raises(reader):
    with pytest.raises(io.UnsupportedOperation):
        reader.read()

    with pytest.raises(io.UnsupportedOperation):
        reader.readline()


def test_reader_detach_returns_itself(reader):
    assert reader.detach() is reader


def test_reader_close_flush_and_seek_do_nothing(reader, written):
    reader.flush()
    reader.seek(0)
    reader.close()
    assert reader.closed is False
    assert written == []


def test_reader_can_be_used_as_stdout(monkeypatch, reader, written):
    monkeypatch.setattr(sys, "stdout", reader)
    print("printed", end="")
    assert "printed" in "".join(written)


def test_input_reader_reads_from_input(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "typed")
    input_reader = InputReader()
    assert input_reader.read() == "typed"
    assert input_reader.readline() == "typed"


def test_input_reader_is_readable_but_not_writable():
    input_reader = InputReader()
    assert input_reader.readable() is True
    assert input_reader.writable() is False
    assert input_reader.closed is False
    assert input_reader.encoding == "utf-8"
    assert input_reader.detach() is input_reader


def test_input_reader_write_raises():
    with pytest.raises(io.UnsupportedOperation):
        InputReader().write("text")


def test_only_the_readers_are_exported():
    assert outputredirector.__all__ == ["Reader", "InputReader"]

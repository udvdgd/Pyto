"""Tests for ``Lib/file_system.py``."""

import os

import pytest


@pytest.fixture
def file_system(fake_pyto, fake_userkeys, fake_sharing, lib_module):
    return lib_module("file_system")


def picker(fake_sharing):
    assert len(fake_sharing.pickers) == 1
    return fake_sharing.pickers[0]


def test_import_file_returns_the_picked_file(file_system, fake_sharing):
    fake_sharing.picked = ["/tmp/file.txt"]
    assert file_system.import_file() == "/tmp/file.txt"


def test_import_file_returns_a_list_with_multiple_selection(file_system, fake_sharing):
    fake_sharing.picked = ["/tmp/a.txt", "/tmp/b.txt"]
    assert file_system.import_file(multiple_selection=True) == [
        "/tmp/a.txt",
        "/tmp/b.txt",
    ]
    assert picker(fake_sharing).allows_multiple_selection is True


def test_import_file_raises_when_nothing_is_picked(file_system, fake_sharing):
    fake_sharing.picked = []
    with pytest.raises(file_system.FilePickerCancellation):
        file_system.import_file()


def test_import_file_wraps_a_single_extension_in_a_list(file_system, fake_sharing):
    fake_sharing.picked = ["/tmp/file.txt"]
    file_system.import_file(file_extension="txt")
    assert picker(fake_sharing).file_extensions == ["txt"]


def test_import_file_keeps_a_list_of_extensions(file_system, fake_sharing):
    fake_sharing.picked = ["/tmp/file.txt"]
    file_system.import_file(file_extension=["txt", "md"])
    assert picker(fake_sharing).file_extensions == ["txt", "md"]


def test_import_file_wraps_a_single_mime_type_in_a_list(file_system, fake_sharing):
    fake_sharing.picked = ["/tmp/file.txt"]
    file_system.import_file(mime_type="text/plain")
    assert picker(fake_sharing).mime_types == ["text/plain"]


@pytest.mark.xfail(
    reason="import_file() assigns 'list(mime_type)' to 'type_identifier'",
    strict=True,
)
def test_import_file_forwards_the_type_identifiers(file_system, fake_sharing):
    fake_sharing.picked = ["/tmp/file.txt"]
    file_system.import_file(type_identifier="public.image")
    assert picker(fake_sharing).file_types == ["public.image"]


def test_pick_directory_returns_the_picked_directory(file_system, fake_sharing):
    fake_sharing.picked = ["/tmp/directory"]
    assert file_system.pick_directory() == "/tmp/directory"
    assert picker(fake_sharing).file_types == ["public.folder"]


def test_pick_directory_raises_when_nothing_is_picked(file_system, fake_sharing):
    fake_sharing.picked = []
    with pytest.raises(file_system.FilePickerCancellation):
        file_system.pick_directory()


def test_open_directory_changes_the_working_directory(file_system, fake_sharing, tmp_path):
    fake_sharing.picked = [str(tmp_path)]
    cwd = os.getcwd()

    with file_system.open_directory() as directory:
        assert directory == str(tmp_path)
        assert os.path.realpath(os.getcwd()) == os.path.realpath(str(tmp_path))

    assert os.getcwd() == cwd


def test_open_directory_yields_none_when_cancelled(file_system, fake_sharing):
    fake_sharing.picked = []
    cwd = os.getcwd()

    with file_system.open_directory() as directory:
        assert directory is None
        assert os.getcwd() == cwd

    assert os.getcwd() == cwd


def test_open_directory_restores_the_working_directory_on_error(
    file_system, fake_sharing, tmp_path
):
    fake_sharing.picked = [str(tmp_path)]
    cwd = os.getcwd()

    with pytest.raises(ValueError):
        with file_system.open_directory():
            raise ValueError()

    assert os.getcwd() == cwd


def test_share_text_shares_every_string(file_system, fake_sharing):
    file_system.share_text("first", "second")
    assert fake_sharing.shared == [["first", "second"]]


def test_quick_look_rejects_non_string_paths(file_system):
    with pytest.raises(TypeError):
        file_system.quick_look(1)


def test_stored_bookmark_cannot_be_used_directly(file_system):
    with pytest.raises(NotImplementedError):
        file_system.StoredBookmark()


def test_bookmark_without_name_stores_an_absolute_path(file_system, tmp_path):
    bookmark = file_system.FileBookmark(path=str(tmp_path / "file.txt"))
    assert bookmark.path == os.path.abspath(str(tmp_path / "file.txt"))


def test_bookmark_without_name_picks_a_file(file_system, fake_sharing):
    fake_sharing.picked = ["/tmp/file.txt"]
    bookmark = file_system.FileBookmark()
    assert bookmark.path == "/tmp/file.txt"
    assert picker(fake_sharing).file_types == ["public.item"]


def test_folder_bookmark_picks_a_folder(file_system, fake_sharing):
    fake_sharing.picked = ["/tmp/directory"]
    file_system.FolderBookmark()
    assert picker(fake_sharing).file_types == ["public.folder"]
    assert picker(fake_sharing).allows_multiple_selection is False


def test_bookmark_without_name_raises_when_nothing_is_picked(file_system, fake_sharing):
    fake_sharing.picked = []
    with pytest.raises(ValueError):
        file_system.FileBookmark()


def test_bookmark_rejects_non_string_arguments(file_system):
    with pytest.raises(TypeError):
        file_system.FileBookmark(name=1)

    with pytest.raises(TypeError):
        file_system.FileBookmark(path=1)


def test_bookmarks_are_initialized_on_disk(file_system, fake_userkeys):
    assert fake_userkeys.storage[file_system.__key__] == {}


def test_delete_from_disk_removes_the_bookmark(file_system, fake_userkeys, tmp_path):
    fake_userkeys.storage[file_system.__key__] = {"name": "bookmark-data"}

    bookmark = file_system.FileBookmark(path=str(tmp_path))
    bookmark.__bookmark_name__ = "name"
    bookmark.delete_from_disk()

    assert fake_userkeys.storage[file_system.__key__] == {}

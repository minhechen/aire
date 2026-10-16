import hashlib
import json
import plistlib
import stat
import zipfile

import pytest
from test_macho import macho_fixture

from aire.platforms.ios.importer import ImportLimits, IPAImportError, inspect_ipa


def write_ipa(path, extra=None):
    info = {
        "CFBundleExecutable": "Example",
        "CFBundleIdentifier": "org.example.bookmarks",
        "CFBundleDisplayName": "Bookmarks",
        "MinimumOSVersion": "16.0",
    }
    entries = {
        "Payload/Example.app/Info.plist": plistlib.dumps(info),
        "Payload/Example.app/Example": macho_fixture(),
        "Payload/Example.app/en.lproj/Localizable.strings": b'"favorite" = "Save bookmark";\n',
        "Payload/Example.app/zh-Hans.lproj/Localizable.strings": '"favorite" = "收藏";\n'.encode(
            "utf-16"
        ),
        "Payload/Example.app/config.json": json.dumps(
            {"storage": {"database": "favorites.sqlite"}}
        ).encode(),
        "Payload/Example.app/Frameworks/Storage.framework/Storage": macho_fixture(encrypted=True),
        "Payload/Example.app/PlugIns/Share.appex/Share": macho_fixture(),
    }
    entries.update(extra or {})
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)


def test_imports_realistic_bundle_and_preserves_source(tmp_path):
    ipa = tmp_path / "Example.ipa"
    write_ipa(ipa)
    original_hash = hashlib.sha256(ipa.read_bytes()).hexdigest()
    result = inspect_ipa(ipa, tmp_path / "staging")
    assert result.app_name == "Bookmarks"
    assert result.bundle_id == "org.example.bookmarks"
    assert result.input_sha256 == original_hash == hashlib.sha256(ipa.read_bytes()).hexdigest()
    assert {image.details["role"] for image in result.images} == {"main", "framework", "extension"}
    assert any(image.encrypted for image in result.images)
    assert any(e.kind == "resource" and e.value == "favorites.sqlite" for e in result.entities)
    assert any(e.kind == "resource" and "收藏" in e.value for e in result.entities)
    assert all(not image.path.startswith("/") for image in result.images)
    assert result.metadata["frameworks"] == ["Storage.framework"]
    again = inspect_ipa(ipa, tmp_path / "again")
    assert [e.id for e in result.entities] == [e.id for e in again.entities]


@pytest.mark.parametrize(
    "name",
    [
        "../outside",
        "/tmp/outside",
        "Payload/../outside",
        "Payload\\outside",
        "C:/outside",
        "Payload//outside",
    ],
)
def test_unsafe_archive_rejected_before_any_extraction(tmp_path, name):
    ipa = tmp_path / "unsafe.ipa"
    write_ipa(ipa, {name: b"forbidden"})
    destination = tmp_path / "staging"
    with pytest.raises(IPAImportError, match="Unsafe archive path"):
        inspect_ipa(ipa, destination)
    assert not destination.exists()


def test_symlink_archive_is_rejected_before_extraction(tmp_path):
    ipa = tmp_path / "symlink.ipa"
    link = zipfile.ZipInfo("Payload/Example.app/link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr(link, "../../outside")
    with pytest.raises(IPAImportError, match="symlink"):
        inspect_ipa(ipa, tmp_path / "staging")
    assert not (tmp_path / "staging").exists()


def test_case_collisions_and_file_parent_conflicts_are_rejected(tmp_path):
    for extras, message in [
        ({"Payload/Example.app/CONFIG.JSON": b"{}"}, "case-colliding"),
        (
            {"Payload/Example.app/file": b"x", "Payload/Example.app/file/child": b"y"},
            "parent directory",
        ),
    ]:
        ipa = tmp_path / "collision.ipa"
        write_ipa(ipa, extras)
        with pytest.raises(IPAImportError, match=message):
            inspect_ipa(ipa, tmp_path / "staging")
        assert not (tmp_path / "staging").exists()


def test_declared_size_limits_and_existing_destinations_are_enforced(tmp_path):
    ipa = tmp_path / "Example.ipa"
    write_ipa(ipa)
    with pytest.raises(IPAImportError, match="file size limit"):
        inspect_ipa(ipa, tmp_path / "size", ImportLimits(max_file_bytes=100))
    with pytest.raises(IPAImportError, match="entry limit"):
        inspect_ipa(ipa, tmp_path / "count", ImportLimits(max_files=2))
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep").write_text("keep")
    with pytest.raises(IPAImportError, match="empty directory"):
        inspect_ipa(ipa, occupied)
    assert (occupied / "keep").read_text() == "keep"


def test_specialized_runtime_assets_are_reported_honestly(tmp_path):
    ipa = tmp_path / "Example.ipa"
    write_ipa(ipa, {"Payload/Example.app/flutter_assets/AssetManifest.json": b"{}"})
    result = inspect_ipa(ipa, tmp_path / "staging")
    assert result.metadata["unsupported_runtimes"] == ["Flutter"]
    assert any("does not explain all application logic" in warning for warning in result.warnings)


def test_bad_zip_and_non_application_archive_return_actionable_errors(tmp_path):
    ipa = tmp_path / "bad.ipa"
    ipa.write_bytes(b"not a zip")
    with pytest.raises(IPAImportError, match="Unable to extract"):
        inspect_ipa(ipa, tmp_path / "bad-staging")
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr("readme.txt", "no payload")
    with pytest.raises(IPAImportError, match="Payload/.*app"):
        inspect_ipa(ipa, tmp_path / "missing-app")


def test_malformed_xml_resources_do_not_abort_package_inventory(tmp_path):
    ipa = tmp_path / "MalformedResource.ipa"
    write_ipa(ipa, {"Payload/Example.app/broken.plist": b'<?xml version="1.0"?><plist><dict>'})
    result = inspect_ipa(ipa, tmp_path / "staging")
    assert result.app_name == "Bookmarks"
    assert len(result.images) == 3

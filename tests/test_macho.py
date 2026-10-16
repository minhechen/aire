import struct

import pytest

from aire.platforms.ios.macho import MachOFormatError, inspect_macho


def macho_fixture(*, encrypted=False, cpu=0x100000C):
    """A linked-layout arm64 image with symbols, resources and ObjC metadata."""
    imagebase = 0x100000000
    result = bytearray(0x1000)
    sections = [
        (b"__text", 0x300, 16, 0x80000400),
        (b"__cstring", 0x400, 64, 2),
        (b"__objc_methname", 0x500, 64, 2),
        (b"__objc_classname", 0x580, 32, 2),
        (b"__objc_classlist", 0x600, 8, 0),
        (b"__objc_data", 0x700, 0x280, 0),
    ]
    segment_size = 72 + 80 * len(sections)
    segment = bytearray(
        struct.pack(
            "<II16sQQQQiiII",
            0x19,
            segment_size,
            b"__TEXT",
            imagebase,
            0x1000,
            0,
            0x1000,
            7,
            5,
            len(sections),
            0,
        )
    )
    for name, offset, size, flags in sections:
        segment += struct.pack(
            "<16s16sQQIIIIIIII",
            name,
            b"__TEXT",
            imagebase + offset,
            size,
            offset,
            0,
            0,
            0,
            flags,
            0,
            0,
            0,
        )
    dependency = b"/System/Library/Frameworks/UIKit.framework/UIKit\0"
    dylib_size = (24 + len(dependency) + 7) // 8 * 8
    dylib = struct.pack("<IIIIII", 0xC, dylib_size, 24, 0, 0, 0)
    dylib += dependency.ljust(dylib_size - 24, b"\0")
    commands = [bytes(segment), struct.pack("<IIIIII", 2, 24, 0xA00, 2, 0xB00, 64), dylib]
    if encrypted:
        commands.append(struct.pack("<IIIIII", 0x2C, 24, 0x400, 64, 1, 0))
    command_bytes = b"".join(commands)
    result[:32] = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, cpu, 0, 2, len(commands), len(command_bytes), 0, 0
    )
    result[32 : 32 + len(command_bytes)] = command_bytes
    result[0x300:0x310] = b"\xc0\x03\x5f\xd6" * 4
    strings = b"favorites.sqlite\0Offline bookmark\0"
    result[0x400 : 0x400 + len(strings)] = strings
    result[0x500 : 0x500 + 14] = b"saveFavorite:\0"
    result[0x580 : 0x580 + 14] = b"FavoriteStore\0"
    struct.pack_into("<Q", result, 0x600, imagebase + 0x700)
    struct.pack_into("<QQQQQ", result, 0x700, 0, 0, 0, 0, imagebase + 0x780)
    struct.pack_into("<Q", result, 0x780 + 24, imagebase + 0x580)
    struct.pack_into("<Q", result, 0x780 + 32, imagebase + 0x800)
    struct.pack_into("<IIQQQ", result, 0x800, 24, 1, imagebase + 0x500, 0, imagebase + 0x300)
    struct.pack_into("<IBBHQ", result, 0xA00, 1, 0xF, 1, 0, imagebase + 0x300)
    struct.pack_into("<IBBHQ", result, 0xA10, 7, 1, 0, 0, 0)
    names = b"\0_save\0_objc_msgSend\0"
    result[0xB00 : 0xB00 + len(names)] = names
    return bytes(result)


def test_inventory_links_objc_ownership_without_claiming_dispatch(tmp_path):
    binary = tmp_path / "Example"
    binary.write_bytes(macho_fixture())
    images, entities, warnings = inspect_macho(binary, "Payload/Example.app/Example", "main")
    assert len(images) == 1
    image = images[0]
    assert image.architecture == "arm64" and image.status == "ready"
    assert image.imagebase == 0x100000000
    assert image.details["role"] == "main"
    assert "UIKit.framework" in image.details["dependencies"][0]
    assert any(e.kind == "import" and e.name == "_objc_msgSend" for e in entities)
    assert any(e.kind == "function" and e.name == "_save" for e in entities)
    assert any(e.kind == "string" and e.name == "favorites.sqlite" for e in entities)
    method = next(e for e in entities if e.kind == "method")
    assert method.name == "-[FavoriteStore saveFavorite:]"
    assert method.address == 0x100000300
    assert method.metadata["dispatch"] == "declaration_not_call_edge"
    assert not warnings


def test_encrypted_bytes_never_become_string_evidence(tmp_path):
    binary = tmp_path / "Encrypted"
    binary.write_bytes(macho_fixture(encrypted=True))
    images, entities, warnings = inspect_macho(binary)
    assert images[0].status == "encrypted"
    assert images[0].encryption_ranges == [
        {"offset": 0x400, "size": 64, "cryptid": 1, "relative_offset": 0x400}
    ]
    assert not any("favorites.sqlite" in e.name for e in entities)
    assert any(e.name == "saveFavorite:" for e in entities)
    assert any("encrypted ranges are excluded" in warning for warning in warnings)


def test_universal_inventory_retains_per_slice_offsets_and_cpu(tmp_path):
    arm, simulator = macho_fixture(encrypted=True), macho_fixture(cpu=0x1000007)
    archive = bytearray(0x4000)
    struct.pack_into(">II", archive, 0, 0xCAFEBABE, 2)
    struct.pack_into(">iiIII", archive, 8, 0x100000C, 0, 0x1000, len(arm), 12)
    struct.pack_into(">iiIII", archive, 28, 0x1000007, 0, 0x3000, len(simulator), 12)
    archive[0x1000 : 0x1000 + len(arm)] = arm
    archive[0x3000 : 0x3000 + len(simulator)] = simulator
    binary = tmp_path / "Universal"
    binary.write_bytes(archive)
    images, entities, warnings = inspect_macho(binary)
    assert [(image.architecture, image.status) for image in images] == [
        ("arm64", "encrypted"),
        ("x86_64", "unsupported"),
    ]
    assert images[0].encryption_ranges[0]["offset"] == 0x1400
    assert images[1].details["slice_offset"] == 0x3000
    simulator_string = next(
        e for e in entities if e.image_id == images[1].id and e.name == "favorites.sqlite"
    )
    assert simulator_string.file_offset == 0x3400
    assert warnings


def test_rejects_overlapping_universal_slices(tmp_path):
    binary = tmp_path / "Overlap"
    data = bytearray(0x3000)
    struct.pack_into(">II", data, 0, 0xCAFEBABE, 2)
    struct.pack_into(">iiIII", data, 8, 0x100000C, 0, 0x1000, 0x1000, 12)
    struct.pack_into(">iiIII", data, 28, 0x100000C, 0, 0x1000, 0x1000, 12)
    binary.write_bytes(data)
    with pytest.raises(MachOFormatError, match="overlap"):
        inspect_macho(binary)


@pytest.mark.parametrize("mutation", ["truncated", "command_overflow", "section_overflow"])
def test_malformed_offsets_do_not_index_arbitrary_bytes(tmp_path, mutation):
    data = bytearray(macho_fixture())
    if mutation == "truncated":
        data = data[:16]
    elif mutation == "command_overflow":
        struct.pack_into("<I", data, 20, 0xFFFFFFFF)
    else:
        struct.pack_into("<Q", data, 32 + 72 + 40, 0xFFFFFF)
    binary = tmp_path / mutation
    binary.write_bytes(data)
    with pytest.raises(MachOFormatError):
        inspect_macho(binary)


def test_relative_objc_methods_resolve_declared_implementation(tmp_path):
    data = bytearray(macho_fixture())
    base = 0x100000000
    struct.pack_into(
        "<IIiii",
        data,
        0x800,
        0xC000000C,
        1,
        (base + 0x500) - (base + 0x808),
        0,
        (base + 0x300) - (base + 0x810),
    )
    binary = tmp_path / "Relative"
    binary.write_bytes(data)
    _, entities, _ = inspect_macho(binary)
    method = next(e for e in entities if e.kind == "method")
    assert method.name == "-[FavoriteStore saveFavorite:]"
    assert method.address == base + 0x300

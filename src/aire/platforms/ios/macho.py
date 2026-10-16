"""Bounded Mach-O inventory. This module never executes an input binary.

Offsets in returned evidence and encryption ranges are absolute file offsets,
including the container offset for universal (fat) binaries. Virtual addresses
are unslid addresses. This is an inventory, not a disassembler or a call graph.
"""

from __future__ import annotations

import hashlib
import mmap
import struct
from pathlib import Path

from aire.models import Entity, Image


class MachOFormatError(ValueError):
    """The file claims to be Mach-O but is truncated or structurally invalid."""


MAGICS = {
    b"\xce\xfa\xed\xfe": ("<", False),
    b"\xcf\xfa\xed\xfe": ("<", True),
    b"\xfe\xed\xfa\xce": (">", False),
    b"\xfe\xed\xfa\xcf": (">", True),
}
FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
MAX_COMMANDS = 65536
MAX_SYMBOLS = 500000
MAX_STRING_BYTES = 16 * 1024 * 1024
MAX_ENTITIES = 100000


def stable_id(*parts: object) -> str:
    return hashlib.sha256("\0".join(map(str, parts)).encode()).hexdigest()[:24]


def is_macho(magic: bytes) -> bool:
    return magic in MAGICS or magic in FAT_MAGICS


def _architecture(cpu: int, subtype: int) -> str:
    cpu &= 0xFFFFFFFF
    if cpu == 0x0100000C:
        return "arm64e" if (subtype & 0xFFFFFF) == 2 else "arm64"
    return {12: "arm", 7: "x86", 0x01000007: "x86_64", 18: "ppc", 0x01000012: "ppc64"}.get(
        cpu, f"unknown-{cpu:x}"
    )


def _name(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def inspect_macho(
    path: Path, relative_path: str | None = None, role: str = "binary"
) -> tuple[list[Image], list[Entity], list[str]]:
    """Inventory every Mach-O slice, retaining independent encryption status.

    Malformed slice tables raise ``MachOFormatError``. A bad slice within a
    structurally sound universal container becomes an ``invalid`` Image, so
    other slices remain inspectable.
    """
    path = Path(path)
    relative_path = relative_path or path.name
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
        if handle.tell() < 4:
            raise MachOFormatError("Mach-O header is truncated")
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            magic = data[:4]
            slices: list[tuple[int, int, int | None, int | None]] = []
            if magic in FAT_MAGICS:
                endian, wide = FAT_MAGICS[magic]
                count = struct.unpack_from(endian + "I", data, 4)[0] if len(data) >= 8 else 0
                entry_size = 32 if wide else 20
                if not 0 < count <= 64 or 8 + count * entry_size > len(data):
                    raise MachOFormatError("Invalid universal Mach-O slice table")
                table_end = 8 + count * entry_size
                for index in range(count):
                    values = struct.unpack_from(
                        endian + ("iiQQII" if wide else "iiIII"),
                        data,
                        8 + index * entry_size,
                    )
                    cpu, subtype, offset, size, alignment = values[:5]
                    if size < 28 or offset < table_end or offset + size > len(data):
                        raise MachOFormatError("Universal Mach-O slice is outside the file")
                    if alignment > 63 or offset % (1 << alignment):
                        raise MachOFormatError("Universal Mach-O slice has invalid alignment")
                    if any(
                        offset < old + length and old < offset + size
                        for old, length, _, _ in slices
                    ):
                        raise MachOFormatError("Universal Mach-O slices overlap")
                    slices.append((offset, size, cpu, subtype))
            elif magic in MAGICS:
                slices.append((0, len(data), None, None))
            else:
                raise MachOFormatError("Not a Mach-O binary")
            images, entities, warnings = [], [], []
            for offset, size, expected_cpu, expected_subtype in slices:
                try:
                    image, found, notes = _inspect_slice(
                        data,
                        relative_path,
                        digest.hexdigest(),
                        offset,
                        size,
                        role,
                        expected_cpu,
                        expected_subtype,
                    )
                    images.append(image)
                    entities.extend(found)
                    warnings.extend(notes)
                except (MachOFormatError, struct.error) as error:
                    if len(slices) == 1 and magic not in FAT_MAGICS:
                        raise MachOFormatError(str(error)) from error
                    architecture = _architecture(expected_cpu or 0, expected_subtype or 0)
                    images.append(
                        Image(
                            id=stable_id(relative_path, digest.hexdigest(), offset),
                            path=relative_path,
                            sha256=digest.hexdigest(),
                            architecture=architecture,
                            status="invalid",
                            details={
                                "slice_offset": offset,
                                "slice_size": size,
                                "role": role,
                                "error": str(error),
                            },
                        )
                    )
                    warnings.append(f"{relative_path} ({architecture}): invalid slice: {error}")
            return images, entities, warnings


def _inspect_slice(data, path, digest, base, size, role, expected_cpu, expected_subtype):
    magic = data[base : base + 4]
    if magic not in MAGICS:
        raise MachOFormatError("Slice has no Mach-O header")
    endian, wide = MAGICS[magic]
    header_size = 32 if wide else 28
    if size < header_size:
        raise MachOFormatError("Mach-O header is truncated")
    header = struct.unpack_from(endian + ("IiiIIIII" if wide else "IiiIIII"), data, base)
    _, cpu, subtype, filetype, count, commands_size, flags = header[:7]
    if expected_cpu is not None and (cpu != expected_cpu or subtype != expected_subtype):
        raise MachOFormatError("Slice CPU does not match universal header")
    if count > MAX_COMMANDS or commands_size > size - header_size:
        raise MachOFormatError("Load command table is outside the slice")
    architecture = _architecture(cpu, subtype)
    supported = architecture in {"arm64", "arm64e"}
    image_id = stable_id(path, digest, base)
    image = Image(
        image_id, path, digest, architecture, status="ready" if supported else "unsupported"
    )
    warnings, entities, sections, dependencies, encryptions = [], [], [], [], []
    symtab, entry_offset, image_uuid = None, None, None
    position, command_end = base + header_size, base + header_size + commands_size
    for _ in range(count):
        if position + 8 > command_end:
            raise MachOFormatError("Load command header is truncated")
        command, command_size = struct.unpack_from(endian + "II", data, position)
        if command_size < 8 or command_size % 4 or position + command_size > command_end:
            raise MachOFormatError("Invalid load command size")
        if command in {0x1, 0x19}:
            segment_wide = command == 0x19
            segment_size, section_size = (72, 80) if segment_wide else (56, 68)
            if command_size < segment_size:
                raise MachOFormatError("Segment command is truncated")
            segment = struct.unpack_from(
                endian + ("II16sQQQQiiII" if segment_wide else "II16sIIIIiiII"),
                data,
                position,
            )
            segment_name = _name(segment[2])
            vmaddr, _vmsize, fileoff, filesize = segment[3:7]
            nsects = segment[9]
            if fileoff + filesize > size or segment_size + nsects * section_size > command_size:
                raise MachOFormatError("Segment or section table is outside the slice")
            if segment_name == "__TEXT":
                image.imagebase = vmaddr
            for index in range(nsects):
                section = struct.unpack_from(
                    endian + ("16s16sQQIIIIIIII" if segment_wide else "16s16sIIIIIIIII"),
                    data,
                    position + segment_size + index * section_size,
                )
                name, segment_name = _name(section[0]), _name(section[1])
                address, length, file_offset, section_flags = (
                    section[2],
                    section[3],
                    section[4],
                    section[8],
                )
                # Zero-fill sections occupy VM space but have no file bytes.
                zero_fill = (section_flags & 0xFF) in {1, 12, 18}
                if not zero_fill and file_offset + length > size:
                    raise MachOFormatError("Section bytes are outside the slice")
                sections.append(
                    {
                        "name": name,
                        "segment": segment_name,
                        "address": address,
                        "size": length,
                        "offset": base + file_offset,
                        "flags": section_flags,
                        "zerofill": zero_fill,
                    }
                )
        elif command in {0x21, 0x2C}:
            if command_size < (24 if command == 0x2C else 20):
                raise MachOFormatError("Encryption command is truncated")
            cryptoff, cryptsize, cryptid = struct.unpack_from(endian + "III", data, position + 8)
            if cryptoff + cryptsize > size:
                raise MachOFormatError("Encryption range is outside the slice")
            if cryptid and cryptsize:
                encryptions.append(
                    {
                        "offset": base + cryptoff,
                        "size": cryptsize,
                        "cryptid": cryptid,
                        "relative_offset": cryptoff,
                    }
                )
        elif command == 0x2:
            if command_size < 24:
                raise MachOFormatError("Symbol command is truncated")
            symtab = struct.unpack_from(endian + "IIII", data, position + 8)
        elif command == 0x1B:
            if command_size < 24:
                raise MachOFormatError("UUID command is truncated")
            import uuid

            image_uuid = str(uuid.UUID(bytes=data[position + 8 : position + 24]))
        elif command == 0x80000028:
            if command_size < 24:
                raise MachOFormatError("Entry point command is truncated")
            entry_offset = struct.unpack_from(endian + "Q", data, position + 8)[0]
        elif command in {0xC, 0xD, 0x18, 0x80000018, 0x8000001F, 0x80000023, 0x20}:
            if command_size < 24:
                raise MachOFormatError("Dylib command is truncated")
            name_offset = struct.unpack_from(endian + "I", data, position + 8)[0]
            if not 24 <= name_offset < command_size:
                raise MachOFormatError("Dylib name is outside its command")
            dependency = _name(data[position + name_offset : position + command_size])
            if command != 0xD:
                dependencies.append(dependency)
        position += command_size
    if position != command_end:
        raise MachOFormatError("Load command count and size disagree")
    image.encrypted, image.encryption_ranges, image.uuid = (
        bool(encryptions),
        encryptions,
        image_uuid,
    )
    if image.encrypted and supported:
        image.status = "encrypted"
    if image.encrypted:
        warnings.append(
            f"{path} ({architecture}): encrypted ranges are excluded from indexing; code analysis is limited"
        )
    if not supported:
        warnings.append(
            f"{path}: {architecture} is inventoried but unsupported for the iOS arm64 investigation backend"
        )

    def readable(offset, length):
        return (
            length >= 0
            and base <= offset <= base + size - length
            and all(
                offset + length <= e["offset"] or offset >= e["offset"] + e["size"]
                for e in encryptions
            )
        )

    def address_offset(address):
        for section in sections:
            if (
                not section["zerofill"]
                and section["address"] <= address < section["address"] + section["size"]
            ):
                return section["offset"] + address - section["address"]
        return None

    entity_ids = set()

    def emit(kind, name, offset=None, address=None, value=None, metadata=None):
        if len(entities) >= MAX_ENTITIES or not name:
            return
        entity_id = stable_id(image_id, kind, offset, address, name)
        if entity_id in entity_ids:
            return
        entity_ids.add(entity_id)
        entities.append(
            Entity(
                entity_id,
                kind,
                name,
                image_id=image_id,
                address=address,
                file_offset=offset,
                path=path,
                value=value,
                metadata=metadata or {},
            )
        )

    string_budget = MAX_STRING_BYTES
    for section in sections:
        if section["zerofill"]:
            continue
        section_type = section["flags"] & 0xFF
        name = section["name"]
        if section_type != 2 and name not in {
            "__cstring",
            "__objc_methname",
            "__objc_classname",
            "__objc_methtype",
        }:
            continue
        if string_budget <= 0:
            break
        length = min(section["size"], string_budget)
        # Do not join fragments across encryption boundaries or budget cuts.
        start, end = section["offset"], section["offset"] + length
        intervals = [(start, end)]
        for encryption in encryptions:
            low, high = encryption["offset"], encryption["offset"] + encryption["size"]
            intervals = [(a, min(b, low)) for a, b in intervals if a < min(b, low)] + [
                (max(a, high), b) for a, b in intervals if max(a, high) < b
            ]
        for low, high in sorted(intervals):
            if low > start:  # The first fragment may begin inside a string.
                first_end = data.find(b"\0", low, high)
                low = first_end + 1 if first_end >= 0 else high
            cursor = low
            while cursor < high and len(entities) < MAX_ENTITIES:
                terminator = data.find(b"\0", cursor, high)
                if terminator < 0:
                    break
                raw = data[cursor:terminator]
                if 2 <= len(raw) <= 8192:
                    try:
                        text = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        text = ""
                    if text and all(c.isprintable() or c in "\t\r\n" for c in text):
                        kind = "selector" if name == "__objc_methname" else "string"
                        if name == "__objc_classname":
                            kind = "class_name"
                        emit(
                            kind,
                            text,
                            cursor,
                            section["address"] + cursor - section["offset"],
                            text,
                            {"section": name, "source": "section_cstring"},
                        )
                cursor = terminator + 1
        string_budget -= length

    if symtab:
        symbol_offset, symbol_count, strings_offset, strings_size = symtab
        nlist_size = 16 if wide else 12
        if symbol_offset + symbol_count * nlist_size > size or strings_offset + strings_size > size:
            raise MachOFormatError("Symbol or string table is outside the slice")
        symbol_count_limit = min(symbol_count, MAX_SYMBOLS)
        if symbol_count > symbol_count_limit:
            warnings.append(f"{path}: symbol inventory truncated at {MAX_SYMBOLS} entries")
        for index in range(symbol_count_limit):
            if len(entities) >= MAX_ENTITIES:
                break
            offset = base + symbol_offset + index * nlist_size
            if not readable(offset, nlist_size):
                continue
            string_index, ntype, nsect, _description, address = struct.unpack_from(
                endian + ("IBBHQ" if wide else "IBBHI"),
                data,
                offset,
            )
            if ntype & 0xE0 or not 0 < string_index < strings_size:
                continue
            name_offset = base + strings_offset + string_index
            end = min(base + strings_offset + strings_size, name_offset + 8193)
            terminator = data.find(b"\0", name_offset, end)
            if terminator < 0 or not readable(name_offset, terminator + 1 - name_offset):
                continue
            symbol_name = _name(data[name_offset:terminator])
            kind = "import" if (ntype & 0x0E) == 0 else "symbol"
            target = sections[nsect - 1] if 0 < nsect <= len(sections) else None
            if kind == "symbol" and target and target["flags"] & 0x80000400:
                kind = "function"
            emit(
                kind,
                symbol_name,
                name_offset,
                address or None,
                metadata={
                    "source": "symbol_table",
                    "external": bool(ntype & 1),
                    "section_index": nsect,
                    "symbol_entry_offset": offset,
                },
            )

    # Recover conservative ObjC method ownership from class_ro_t, rather than
    # treating all methods with the same selector as definite call targets.
    if wide and supported:

        def pointer(address):
            offset = address_offset(address)
            if offset is None or not readable(offset, 8):
                return None
            return struct.unpack_from(endian + "Q", data, offset)[0]

        def cstring(address):
            offset = address_offset(address)
            if offset is None:
                return None
            boundary = next(
                (
                    s["offset"] + s["size"]
                    for s in sections
                    if s["offset"] <= offset < s["offset"] + s["size"] and not s["zerofill"]
                ),
                offset,
            )
            end = data.find(b"\0", offset, min(boundary, offset + 4096))
            if end < 0 or not readable(offset, end + 1 - offset):
                return None
            try:
                return data[offset:end].decode("utf-8")
            except UnicodeDecodeError:
                return None

        for section in sections:
            if section["name"] not in {"__objc_classlist", "__objc_nlclslist"}:
                continue
            for index in range(min(section["size"] // 8, 20000)):
                if len(entities) >= MAX_ENTITIES:
                    break
                offset = section["offset"] + index * 8
                if not readable(offset, 8):
                    continue
                class_address = struct.unpack_from(endian + "Q", data, offset)[0]
                bits = pointer(class_address + 32)
                if not bits:
                    continue
                ro_address = bits & ~7
                class_name_pointer = pointer(ro_address + 24)
                class_name = cstring(class_name_pointer) if class_name_pointer else None
                if not class_name or len(class_name) > 512:
                    continue
                emit(
                    "class",
                    class_name,
                    address_offset(class_address),
                    class_address,
                    metadata={"source": "objc_class_ro", "ro_address": ro_address},
                )
                owners = [(class_address, "-")]
                metaclass = pointer(class_address)
                if metaclass and metaclass != class_address:
                    owners.append((metaclass, "+"))
                for owner_address, prefix in owners:
                    owner_bits = pointer(owner_address + 32)
                    methods_address = pointer((owner_bits & ~7) + 32) if owner_bits else None
                    list_offset = address_offset(methods_address) if methods_address else None
                    if list_offset is None or not readable(list_offset, 8):
                        continue
                    method_flags, method_count = struct.unpack_from(
                        endian + "II", data, list_offset
                    )
                    relative = bool(method_flags & 0x80000000)
                    entry_size = method_flags & 0xFFFF
                    minimum = 12 if relative else 24
                    if entry_size < minimum or entry_size > 1024 or method_count > 100000:
                        continue
                    for method_index in range(min(method_count, 20000)):
                        if len(entities) >= MAX_ENTITIES:
                            break
                        method_address = methods_address + 8 + method_index * entry_size
                        method_offset = address_offset(method_address)
                        if method_offset is None or not readable(method_offset, minimum):
                            continue
                        if relative:
                            name_delta, _, imp_delta = struct.unpack_from(
                                endian + "iii", data, method_offset
                            )
                            name_address = method_address + name_delta
                            if not method_flags & 0x40000000:
                                name_address = pointer(name_address)
                            implementation = method_address + 8 + imp_delta
                        else:
                            name_address, _, implementation = struct.unpack_from(
                                endian + "QQQ", data, method_offset
                            )
                        selector = cstring(name_address) if name_address else None
                        if selector:
                            emit(
                                "method",
                                f"{prefix}[{class_name} {selector}]",
                                method_offset,
                                implementation,
                                metadata={
                                    "source": "objc_method_list",
                                    "class": class_name,
                                    "selector": selector,
                                    "method_kind": prefix,
                                    "dispatch": "declaration_not_call_edge",
                                },
                            )

    runtime = []
    names = " ".join(dependencies + [s["name"] for s in sections]).lower()
    if "swift" in names:
        runtime.append("swift")
    if "objc" in names:
        runtime.append("objective-c")
    for framework, marker in (
        ("flutter", "flutter"),
        ("unity", "unity"),
        ("react-native", "hermes"),
    ):
        if marker in names:
            runtime.append(framework)
            warnings.append(
                f"{path}: {framework} runtime detected; its application code needs a specialized backend"
            )
    if "swift" in runtime:
        warnings.append(
            f"{path}: Swift metadata is inventoried only partially; dynamic dispatch and closures may remain unresolved"
        )
    if string_budget <= 0 or len(entities) >= MAX_ENTITIES:
        warnings.append(f"{path}: inventory reached its bounded indexing limit")
    image.details = {
        "slice_offset": base,
        "slice_size": size,
        "header_size": header_size,
        "endianness": "little" if endian == "<" else "big",
        "filetype": filetype,
        "flags": flags,
        "role": role,
        "dependencies": dependencies,
        "sections": sections,
        "runtime": runtime,
        "entrypoint_file_offset": base + entry_offset if entry_offset is not None else None,
        "inventory_only": True,
    }
    for dependency in dependencies:
        emit("dependency", dependency, metadata={"source": "load_command"})
    return image, entities, warnings

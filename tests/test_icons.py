"""The icon files: made by tools/build_icons.py, valid ICO, ICNS and PNG files."""

import importlib.util
import struct
from pathlib import Path

from vigie.icons import ICONS_DIR

ROOT = Path(__file__).parent.parent


def load_build_script():
    spec = importlib.util.spec_from_file_location("build_icons", ROOT / "tools" / "build_icons.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_ico(data):
    reserved, kind, count = struct.unpack("<HHH", data[:6])
    assert (reserved, kind) == (0, 1)
    entries = []
    for n in range(count):
        width, height, _, _, planes, bits, size, offset = struct.unpack(
            "<BBBBHHII", data[6 + 16 * n : 22 + 16 * n]
        )
        entries.append((width or 256, height or 256, planes, bits, data[offset : offset + size]))
    return entries


def read_icns(data):
    assert data[:4] == b"icns"
    assert struct.unpack(">I", data[4:8])[0] == len(data)
    chunks, at = [], 8
    while at < len(data):
        kind, length = data[at : at + 4].decode(), struct.unpack(">I", data[at + 4 : at + 8])[0]
        chunks.append((kind, data[at + 8 : at + length]))
        at += length
    assert at == len(data)
    return chunks


def test_packers_round_trip():
    script = load_build_script()
    images = {16: script.solid_png(16, (1, 2, 3, 255)), 256: script.solid_png(256, (0, 0, 0, 0))}
    entries = read_ico(script.pack_ico(images))
    assert [(w, h, planes, bits) for w, h, planes, bits, _ in entries] == [
        (16, 16, 1, 32),
        (256, 256, 1, 32),
    ]
    assert [png for *_, png in entries] == [images[16], images[256]]
    chunks = read_icns(script.pack_icns([("icp4", images[16]), ("ic08", images[256])]))
    assert chunks == [("icp4", images[16]), ("ic08", images[256])]
    assert script.png_size(images[256]) == (256, 256)


def test_shipped_icons_are_complete():
    script = load_build_script()
    assert (ICONS_DIR / "vigie.svg").read_text(encoding="utf-8").startswith("<svg")
    for size in script.PNG_SIZES:
        assert script.png_size((ICONS_DIR / f"vigie-{size}.png").read_bytes()) == (size, size)
    entries = read_ico((ICONS_DIR / "vigie.ico").read_bytes())
    assert sorted(w for w, *_ in entries) == list(script.ICO_SIZES)
    assert all(script.png_size(png) == (w, h) for w, h, _, _, png in entries)
    chunks = dict(read_icns((ICONS_DIR / "vigie.icns").read_bytes()))
    for kind, size in script.ICNS_TYPES:
        assert script.png_size(chunks[kind]) == (size, size), kind

"""Build Vigie's icon files from ``src/vigie/icons/vigie.svg``.

Writes, next to the SVG:

* ``vigie-<size>.png`` for 64, 128, 256 and 512 pixels (Linux desktop entry, the app's tab);
* ``vigie.ico`` (Windows shortcut), with 16 to 256 pixel images;
* ``vigie.icns`` (macOS app bundle), with 16 to 1024 pixel images.

The SVG is rasterized by a headless Chromium through Playwright, the only part
that needs something beyond the standard library (``pip install playwright``
and ``playwright install chromium``). ICO and ICNS files are packed here with
``struct``: both formats can hold PNG images as they are.

Usage::

    python tools/build_icons.py
"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path

ICONS = Path(__file__).resolve().parent.parent / "src" / "vigie" / "icons"
PNG_SIZES = (64, 128, 256, 512)
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)
# ICNS chunk types holding PNG data, and the pixel size of each.
ICNS_TYPES = (
    ("icp4", 16),
    ("icp5", 32),
    ("icp6", 64),
    ("ic07", 128),
    ("ic08", 256),
    ("ic09", 512),
    ("ic10", 1024),
    ("ic11", 32),
    ("ic12", 64),
    ("ic13", 256),
    ("ic14", 512),
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--svg", type=Path, default=ICONS / "vigie.svg")
    parser.add_argument("--out", type=Path, default=ICONS)
    args = parser.parse_args(argv)

    svg = args.svg.read_text(encoding="utf-8")
    # macOS icons keep the margin of Apple's icon grid; elsewhere the tile fills more
    # of the square, as Windows and Linux icons do.
    images = rasterize(
        svg.replace('viewBox="0 0 1024 1024"', 'viewBox="76 76 872 872"'),
        sorted({*PNG_SIZES, *ICO_SIZES}),
    )
    apple = rasterize(svg, sorted({size for _, size in ICNS_TYPES}))
    args.out.mkdir(parents=True, exist_ok=True)
    for size in PNG_SIZES:
        (args.out / f"vigie-{size}.png").write_bytes(images[size])
    (args.out / "vigie.ico").write_bytes(pack_ico({size: images[size] for size in ICO_SIZES}))
    (args.out / "vigie.icns").write_bytes(
        pack_icns([(kind, apple[size]) for kind, size in ICNS_TYPES])
    )
    print(f"icons written to {args.out}", file=sys.stderr)
    return 0


def rasterize(svg: str, sizes: list[int]) -> dict[int, bytes]:
    """PNG images of ``svg`` at each size, with a transparent background."""
    from playwright.sync_api import sync_playwright

    images = {}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        for size in sizes:
            page.set_viewport_size({"width": size, "height": size})
            page.set_content(
                "<!doctype html><style>html,body{margin:0;background:transparent}"
                f"svg{{display:block;width:{size}px;height:{size}px}}</style>{svg}"
            )
            images[size] = page.screenshot(omit_background=True, type="png")
        browser.close()
    for size, data in images.items():
        if png_size(data) != (size, size):
            raise SystemExit(f"rasterized image is {png_size(data)}, expected {size}x{size}")
    return images


def png_size(data: bytes) -> tuple[int, int]:
    if data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise ValueError("not a PNG image")
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def pack_ico(images: dict[int, bytes]) -> bytes:
    """An ICO file holding ``images`` (size -> PNG data), PNG-compressed entries."""
    entries, blobs = [], []
    offset = 6 + 16 * len(images)
    for size, data in sorted(images.items()):
        dimension = 0 if size >= 256 else size  # 0 means 256 in the ICO directory
        entries.append(
            struct.pack("<BBBBHHII", dimension, dimension, 0, 0, 1, 32, len(data), offset)
        )
        blobs.append(data)
        offset += len(data)
    return struct.pack("<HHH", 0, 1, len(images)) + b"".join(entries) + b"".join(blobs)


def pack_icns(chunks: list[tuple[str, bytes]]) -> bytes:
    """An ICNS file: a big-endian header, then one (type, length, PNG) chunk per image."""
    body = b"".join(
        kind.encode("ascii") + struct.pack(">I", 8 + len(data)) + data for kind, data in chunks
    )
    return b"icns" + struct.pack(">I", 8 + len(body)) + body


def solid_png(size: int, rgba: tuple[int, int, int, int]) -> bytes:
    """A one-color PNG, written with zlib only (for tests of the packers)."""
    row = b"\x00" + bytes(rgba) * size
    raw = zlib.compress(row * size)

    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(kind + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", raw) + chunk(b"IEND", b"")


if __name__ == "__main__":
    raise SystemExit(main())

# PyInstaller spec of the standalone Vigie program, which needs no Python:
# the Vigie folder with Vigie.exe on Windows, Vigie.app on macOS.
#
# Build it from the root of the repository, with Vigie and PyInstaller installed
# (pip install . pyinstaller):
#
#     pyinstaller --noconfirm --clean packaging/vigie.spec
#
# The result is in dist/. .github/workflows/apps.yml builds and tests it.

import re
import sys
import sysconfig
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

import vigie
from vigie.standalone import BUNDLE_ID

ROOT = Path(SPECPATH).parent  # SPECPATH: set by PyInstaller
ICONS = Path(vigie.__file__).parent / "icons"
VERSION = vigie.__version__

# The rules, the report and app templates, the ATT&CK and ATLAS data, the sample
# logs and the icons: every file of the package, where Vigie looks for them.
datas = collect_data_files("vigie")
# The licenses travel with the program, Python's (and the libraries it bundles) included.
datas += [(str(ROOT / "LICENSE"), "."), (str(ROOT / "THIRD_PARTY_NOTICES.md"), ".")]
python_license = next(
    (
        candidate
        for candidate in (
            Path(sys.base_prefix) / "LICENSE.txt",
            Path(sysconfig.get_path("stdlib")) / "LICENSE.txt",
        )
        if candidate.is_file()
    ),
    None,
)
if python_license is None:
    raise SystemExit("Python's LICENSE.txt was not found, and the app must carry it")
datas.append((str(python_license), "python-license"))
if sys.platform == "win32":
    datas += collect_data_files("tzdata")  # Windows has no time zone database of its own

a = Analysis(
    [str(ROOT / "packaging" / "launch.py")],
    datas=datas,
    hiddenimports=collect_submodules("vigie"),
    excludes=["tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)

version_info = None
if sys.platform == "win32":
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo,
        StringFileInfo,
        StringStruct,
        StringTable,
        VarFileInfo,
        VarStruct,
        VSVersionInfo,
    )

    numbers = tuple(int(part) for part in re.findall(r"\d+", VERSION)[:3])
    numbers = (*numbers, *(0,) * (4 - len(numbers)))
    version_info = VSVersionInfo(
        ffi=FixedFileInfo(filevers=numbers, prodvers=numbers),
        kids=[
            StringFileInfo(
                [
                    StringTable(
                        "040904B0",
                        [
                            # The name Task Manager and the file's properties show.
                            StringStruct("FileDescription", "Vigie"),
                            StringStruct("FileVersion", VERSION),
                            StringStruct("InternalName", "Vigie"),
                            StringStruct("LegalCopyright", "MIT License"),
                            StringStruct("OriginalFilename", "Vigie.exe"),
                            StringStruct("ProductName", "Vigie"),
                            StringStruct("ProductVersion", VERSION),
                        ],
                    )
                ]
            ),
            VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
        ],
    )

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Vigie",
    console=False,  # no console window: Vigie opens in the browser
    icon=str(ICONS / ("vigie.icns" if sys.platform == "darwin" else "vigie.ico")),
    version=version_info,
    upx=False,  # packed programs look suspicious to antivirus software
    argv_emulation=False,
    codesign_identity=None,  # macOS: ad hoc signature
)

coll = COLLECT(exe, a.binaries, a.datas, name="Vigie", upx=False)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="Vigie.app",
        icon=str(ICONS / "vigie.icns"),
        bundle_identifier=BUNDLE_ID,
        version=VERSION,
        info_plist={
            "CFBundleName": "Vigie",
            "CFBundleDisplayName": "Vigie",
            "CFBundleVersion": VERSION,
            # Apple silicon Macs run macOS 11 or later.
            "LSMinimumSystemVersion": "11.0",
            # Vigie opens in the browser: no Dock icon or menu bar of its own.
            "LSUIElement": True,
            "NSHighResolutionCapable": True,
        },
    )

import gzip
import json
import os
import shutil
import zipfile
from pathlib import Path

import pytest

from vigie import collect as collect_module
from vigie.collect import collect, detect_format

FIXTURES = Path(os.path.dirname(__file__)) / "fixtures"
AUTH_LOG = FIXTURES / "authlog" / "auth.log"
SYSMON_EVTX = FIXTURES / "evtx" / "sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx"
OTRF_JSON = FIXTURES / "winjson" / "cmd_bitsadmin_download_psh_script_excerpt.json"


# A fixed copy of some fixtures, so these tests do not change when fixtures are added.
TREE = [
    "authlog/auth.log",
    "authlog/auth_rfc3339.log",
    "evtx/DE_Fake_ComputerAccount_4720.evtx",
    "evtx/LM_Remote_Service02_7045.evtx",
    "evtx/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx",
    "evtx/LICENSE.GPL",
    "winjson/cmd_bitsadmin_download_psh_script_excerpt.json",
    "README.md",
]


@pytest.fixture
def tree(tmp_path):
    for relative in TREE:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(FIXTURES / relative, target)
    return tmp_path


def test_collect_fixture_tree(tree):
    result = collect(tree, year=2024)
    formats = {report.path: report.format for report in result.files}
    assert formats == {
        "authlog/auth.log": "authlog",
        "authlog/auth_rfc3339.log": "authlog",
        "evtx/DE_Fake_ComputerAccount_4720.evtx": "evtx",
        "evtx/LM_Remote_Service02_7045.evtx": "evtx",
        "evtx/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx": "evtx",
        "winjson/cmd_bitsadmin_download_psh_script_excerpt.json": "winjson",
    }
    assert result.skipped == [
        "README.md (unsupported format)",
        "evtx/LICENSE.GPL (unsupported format)",
    ]
    assert len(result.events) == sum(report.events for report in result.files)
    assert len(result.events) == 29 + 3 + 2 + 3 + 1 + 10


def test_events_are_sorted_across_files(tree):
    result = collect(tree, year=2024)
    stamps = [event.timestamp for event in result.events]
    assert stamps == sorted(stamps)
    assert {event.source for event in result.events} == {"auth", "security", "system", "sysmon"}


def test_whole_fixture_folder_is_readable():
    result = collect(FIXTURES, year=2024)
    assert result.files
    assert all(report.events > 0 for report in result.files)
    assert all(not path.endswith((".evtx", ".json", ".log")) for path in result.skipped)


def test_file_warnings_are_kept(tree):
    result = collect(tree, year=2024)
    (auth,) = [report for report in result.files if report.path == "authlog/auth.log"]
    assert auth.events == 29
    assert auth.warnings == ["auth.log:30: unrecognized syslog line"]


def test_single_file_root():
    result = collect(SYSMON_EVTX)
    assert [report.path for report in result.files] == [SYSMON_EVTX.name]
    assert len(result.events) == 1


def test_missing_root():
    with pytest.raises(FileNotFoundError):
        collect(FIXTURES / "does-not-exist")


def test_hidden_files_and_folders_are_ignored(tmp_path):
    (tmp_path / ".git").mkdir()
    shutil.copy(AUTH_LOG, tmp_path / ".git" / "auth.log")
    shutil.copy(AUTH_LOG, tmp_path / ".auth.log")
    result = collect(tmp_path)
    assert result.files == []
    assert result.skipped == []


def test_parser_crash_is_reported_not_raised(tmp_path, monkeypatch):
    shutil.copy(AUTH_LOG, tmp_path / "auth.log")

    def boom(*_args, **_kwargs):
        raise RuntimeError("bug")

    monkeypatch.setattr(collect_module.authlog, "parse", boom)
    result = collect(tmp_path)
    (report,) = result.files
    assert report.events == 0
    assert report.warnings == ["parser failed: RuntimeError('bug')"]


def test_unreadable_file_is_skipped(tmp_path, monkeypatch):
    (tmp_path / "locked.log").write_text("x")

    def deny(_path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(collect_module, "detect_format", deny)
    result = collect(tmp_path)
    assert result.skipped == ["locked.log (unreadable: Permission denied)"]


class TestDetectFormat:
    def test_evtx_by_magic_bytes_whatever_the_name(self, tmp_path):
        renamed = tmp_path / "DC01-export.bin"
        shutil.copy(SYSMON_EVTX, renamed)
        assert detect_format(renamed) == "evtx"

    def test_otrf_json(self):
        assert detect_format(OTRF_JSON) == "winjson"

    def test_otrf_zip(self, tmp_path):
        archive = tmp_path / "dataset.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.write(OTRF_JSON, "dataset.json")
        assert detect_format(archive) == "winjson"

    def test_zip_without_json(self, tmp_path):
        archive = tmp_path / "capture.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("capture.pcap", b"\x00")
        assert detect_format(archive) is None

    def test_broken_zip(self, tmp_path):
        archive = tmp_path / "broken.zip"
        archive.write_text("nope")
        assert detect_format(archive) is None

    @pytest.mark.parametrize(
        "content",
        ['{"message": "not a windows event"}\n', "{not json\n", "\n\n", '["a list"]\n'],
    )
    def test_other_json_is_not_supported(self, tmp_path, content):
        path = tmp_path / "other.json"
        path.write_text(content)
        assert detect_format(path) is None

    def test_json_detection_skips_leading_blank_lines(self, tmp_path):
        path = tmp_path / "events.jsonl"
        path.write_text("\n" + json.dumps({"Channel": "Security", "EventID": 4625}) + "\n")
        assert detect_format(path) == "winjson"

    @pytest.mark.parametrize("name", ["auth.log", "auth.log.1", "secure", "secure-20240310"])
    def test_authlog_by_name(self, tmp_path, name):
        path = tmp_path / name
        path.write_text("")
        assert detect_format(path) == "authlog"

    def test_authlog_by_content(self, tmp_path):
        path = tmp_path / "web01-logs.txt"
        shutil.copy(AUTH_LOG, path)
        assert detect_format(path) == "authlog"

    def test_rotated_gzip_authlog(self, tmp_path):
        path = tmp_path / "auth.log.2.gz"
        with gzip.open(path, "wb") as handle:
            handle.write(AUTH_LOG.read_bytes())
        assert detect_format(path) == "authlog"

    def test_gzip_renamed_is_sniffed(self, tmp_path):
        path = tmp_path / "server.gz"
        with gzip.open(path, "wb") as handle:
            handle.write(AUTH_LOG.read_bytes())
        assert detect_format(path) == "authlog"

    def test_corrupted_gzip(self, tmp_path):
        path = tmp_path / "server.gz"
        path.write_bytes(b"not gzip")
        assert detect_format(path) is None

    def test_syslog_without_auth_programs(self, tmp_path):
        path = tmp_path / "kern.log"
        path.write_text("Mar 10 09:00:00 web01 kernel: [    0.000000] Linux version 6.1\n")
        assert detect_format(path) is None

    def test_binary_file(self, tmp_path):
        path = tmp_path / "image.png"
        path.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 10)
        assert detect_format(path) is None

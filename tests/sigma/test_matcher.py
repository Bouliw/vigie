import pytest

from vigie.sigma.matcher import (
    SigmaError,
    compile_field,
    compile_selection,
    wildcard_to_regex,
)


def matches(spec, rule_value, event_value):
    return compile_field(spec, rule_value).matches(event_value)


class TestEquals:
    def test_exact_and_case_insensitive(self):
        assert matches("User", "Admin", "admin")
        assert matches("User", "Admin", "ADMIN")
        assert not matches("User", "Admin", "administrator")

    def test_numbers_compare_as_text(self):
        assert matches("EventID", 4625, "4625")
        assert not matches("EventID", 4625, "46250")

    def test_booleans(self):
        assert matches("Signed", True, "true")
        assert matches("Signed", False, "False")

    def test_list_means_any(self):
        assert matches("EventID", [4624, 4625], "4625")
        assert not matches("EventID", [4624, 4625], "4634")

    def test_missing_field_does_not_match(self):
        assert not matches("User", "admin", None)

    def test_multi_valued_field_matches_any_item(self):
        assert matches("Data", "b", ("a", "b"))
        assert not matches("Data", "c", ("a", "b"))


class TestWildcards:
    def test_star_and_question_mark(self):
        assert matches("Image", "*\\cmd.exe", "C:\\Windows\\System32\\cmd.exe")
        # Per the Sigma spec, a backslash before a wildcard must itself be escaped.
        assert matches("Image", "C:\\Windows\\\\*.exe", "C:\\Windows\\notepad.exe")
        assert not matches("Image", "C:\\Windows\\*.exe", "C:\\Windows\\notepad.exe")
        assert matches("Image", "C:\\Windows\\*.exe", "C:\\Windows*.exe")
        assert matches("User", "adm?n", "admin")
        assert not matches("User", "adm?n", "admiin")

    def test_escaped_wildcards_are_literal(self):
        assert matches("Value", "100\\*", "100*")
        assert not matches("Value", "100\\*", "1000")
        assert matches("Value", "what\\?", "what?")

    def test_escaped_backslash_before_wildcard(self):
        # "\\*" is a literal backslash followed by a real wildcard.
        assert matches("Path", "C:\\\\*", "C:\\anything")

    def test_single_backslash_is_literal(self):
        assert matches("Image", "\\lsass.exe", "\\lsass.exe")

    def test_regex_characters_are_not_special(self):
        assert matches("CommandLine", "a.b(c)", "a.b(c)")
        assert not matches("CommandLine", "a.b(c)", "axb(c)")

    def test_wildcard_to_regex(self):
        assert wildcard_to_regex("a*b?c") == "a.*b.c"
        assert wildcard_to_regex("\\*") == "\\*"


class TestStringModifiers:
    def test_contains(self):
        assert matches("CommandLine|contains", "-enc", "powershell.exe -EncodedCommand ZQB4AA==")
        assert matches("CommandLine|contains", "-ENC", "powershell -enc abc")
        assert not matches("CommandLine|contains", "-enc", "powershell -nop")

    def test_startswith_endswith(self):
        assert matches("Image|startswith", "C:\\Users\\", "C:\\Users\\bob\\evil.exe")
        assert matches("TargetImage|endswith", "\\lsass.exe", "C:\\Windows\\system32\\lsass.exe")
        assert not matches("TargetImage|endswith", "\\lsass.exe", "C:\\lsass.exe.bak")

    def test_contains_spans_newlines(self):
        assert matches("CommandLine|contains", "IEX", "line one\nIEX (New-Object)")

    def test_all(self):
        spec = "CommandLine|contains|all"
        assert matches(spec, ["bitsadmin", "/transfer"], "bitsadmin.exe /transfer job http://x")
        assert not matches(spec, ["bitsadmin", "/transfer"], "bitsadmin.exe /list")

    def test_all_on_multi_valued_field(self):
        assert matches("Data|all", ["a", "b"], ("a", "b"))

    def test_cased(self):
        assert matches("CommandLine|contains|cased", "IEX", "iex; IEX")
        assert not matches("CommandLine|contains|cased", "IEX", "iex only")

    def test_windash(self):
        spec = "CommandLine|contains|windash"
        for command in ("net user /add", "net user -add", "net user \u2013add"):
            assert matches(spec, " -add", command), command
        # Only a dash starting a word is expanded.
        assert not matches("CommandLine|contains|windash", "a-b", "a/b")


class TestOtherModifiers:
    def test_regex_is_case_sensitive_and_unanchored(self):
        assert matches("CommandLine|re", r"-e(nc|ncodedcommand)\s", "ps -enc AAA")
        assert not matches("CommandLine|re", r"-enc\s", "ps -ENC AAA")
        assert matches("CommandLine|re|i", r"-enc\s", "ps -ENC AAA")

    def test_regex_flags(self):
        assert matches("Script|re|m", r"^Invoke", "first\nInvoke-Mimikatz")
        assert matches("Script|re|s", r"a.b", "a\nb")
        assert not matches("Script|re", r"a.b", "a\nb")

    def test_invalid_regex(self):
        with pytest.raises(SigmaError, match="invalid regular expression"):
            compile_field("CommandLine|re", "(unclosed")

    def test_cidr(self):
        spec = "src_ip|cidr"
        assert matches(spec, "203.0.113.0/24", "203.0.113.45")
        assert not matches(spec, "203.0.113.0/24", "198.51.100.7")
        assert matches(spec, ["10.0.0.0/8", "2001:db8::/32"], "2001:db8::1")
        assert not matches(spec, "10.0.0.0/8", "not-an-ip")

    def test_invalid_cidr(self):
        with pytest.raises(SigmaError, match="invalid network"):
            compile_field("src_ip|cidr", "999.0.0.0/8")

    @pytest.mark.parametrize(
        ("modifier", "limit", "value", "expected"),
        [
            ("gt", 3, "4", True),
            ("gt", 3, "3", False),
            ("gte", 3, "3", True),
            ("lt", 3, "2.5", True),
            ("lte", 3, "3", True),
            ("lte", 3, "4", False),
            ("gt", 3, "abc", False),
        ],
    )
    def test_numeric(self, modifier, limit, value, expected):
        assert matches(f"attempts|{modifier}", limit, value) is expected

    def test_numeric_needs_number(self):
        with pytest.raises(SigmaError, match="expects a number"):
            compile_field("attempts|gt", "3")

    def test_exists(self):
        assert matches("CommandLine|exists", True, "")
        assert not matches("CommandLine|exists", True, None)
        assert matches("CommandLine|exists", False, None)
        with pytest.raises(SigmaError, match="true or false"):
            compile_field("CommandLine|exists", "yes")

    def test_null(self):
        assert matches("ParentImage", None, None)
        assert matches("ParentImage", None, "")
        assert not matches("ParentImage", None, "C:\\x.exe")
        assert matches("ParentImage", [None, "*\\explorer.exe"], "C:\\Windows\\explorer.exe")
        with pytest.raises(SigmaError, match="null"):
            compile_field("ParentImage|contains", None)


class TestInvalidSpecs:
    @pytest.mark.parametrize(
        ("spec", "message"),
        [
            ("CommandLine|base64offset|contains", "unsupported modifier"),
            ("CommandLine|contains|endswith", "conflicting modifiers"),
            ("CommandLine|contains|i", "only apply to the re modifier"),
            ("|all", "without a field"),
        ],
    )
    def test_rejected(self, spec, message):
        with pytest.raises(SigmaError, match=message):
            compile_field(spec, "x")

    def test_empty_list(self):
        with pytest.raises(SigmaError, match="empty value list"):
            compile_field("User", [])


def lookup_from(fields):
    return fields.get


class TestSelection:
    def test_map_is_and(self):
        selection = compile_selection("sel", {"EventID": 10, "TargetImage|endswith": "\\lsass.exe"})
        event = {"EventID": "10", "TargetImage": "C:\\Windows\\system32\\lsass.exe"}
        assert selection.matches(lookup_from(event), "")
        assert not selection.matches(lookup_from({**event, "EventID": "1"}), "")

    def test_list_of_maps_is_or(self):
        selection = compile_selection("sel", [{"User": "root"}, {"User": "admin"}])
        assert selection.matches(lookup_from({"User": "admin"}), "")
        assert not selection.matches(lookup_from({"User": "guest"}), "")

    def test_keywords_search_raw_text(self):
        selection = compile_selection("keywords", ["Failed password", "Invalid user*from"])
        assert selection.matches(lookup_from({}), "sshd: invalid user bob from 192.0.2.1")
        assert not selection.matches(lookup_from({}), "Accepted publickey")

    def test_single_keyword(self):
        selection = compile_selection("keywords", "mimikatz")
        assert selection.matches(lookup_from({}), "C:\\tools\\MIMIKATZ.exe")

    @pytest.mark.parametrize(
        ("definition", "message"),
        [
            ({}, "empty map"),
            ([], "empty or has an invalid type"),
            (None, "empty or has an invalid type"),
            (["keyword", {"User": "x"}], "mixes keywords and field maps"),
        ],
    )
    def test_invalid(self, definition, message):
        with pytest.raises(SigmaError, match=message):
            compile_selection("sel", definition)

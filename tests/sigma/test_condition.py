import pytest

from vigie.sigma.condition import And, Not, Or, Ref, parse_condition
from vigie.sigma.matcher import SigmaError

NAMES = ["selection", "selection_img", "selection_cli", "filter", "filter_main", "_helper"]


def evaluate(condition, true_names, names=NAMES):
    node = parse_condition(condition, names)
    return node.evaluate(lambda name: name in true_names)


class TestStructure:
    def test_single_name(self):
        assert parse_condition("selection", NAMES) == Ref("selection")

    def test_precedence_not_and_or(self):
        node = parse_condition("selection or selection_img and not filter", NAMES)
        assert node == Or((Ref("selection"), And((Ref("selection_img"), Not(Ref("filter"))))))

    def test_chains_are_flattened(self):
        node = parse_condition("selection and selection_img and selection_cli", NAMES)
        assert node == And((Ref("selection"), Ref("selection_img"), Ref("selection_cli")))

    def test_parentheses(self):
        node = parse_condition("(selection or selection_img) and not filter", NAMES)
        assert node == And((Or((Ref("selection"), Ref("selection_img"))), Not(Ref("filter"))))

    def test_one_of_pattern(self):
        node = parse_condition("1 of selection_*", NAMES)
        assert node == Or((Ref("selection_img"), Ref("selection_cli")))

    def test_all_of_pattern(self):
        node = parse_condition("all of selection_*", NAMES)
        assert node == And((Ref("selection_img"), Ref("selection_cli")))

    def test_them_skips_underscore_names(self):
        node = parse_condition("1 of them", NAMES)
        assert Ref("_helper") not in node.items
        assert len(node.items) == 5

    def test_quantifier_with_single_match(self):
        assert parse_condition("all of filter_*", NAMES) == Ref("filter_main")

    def test_keywords_are_case_insensitive(self):
        node = parse_condition("selection AND NOT filter", NAMES)
        assert node == And((Ref("selection"), Not(Ref("filter"))))

    def test_list_of_conditions_means_or(self):
        node = parse_condition(["selection", "selection_img and filter"], NAMES)
        assert node == Or((Ref("selection"), And((Ref("selection_img"), Ref("filter")))))


class TestEvaluation:
    @pytest.mark.parametrize(
        ("true_names", "expected"),
        [
            ({"selection"}, True),
            ({"selection", "filter"}, False),
            ({"selection", "filter_main"}, False),
            (set(), False),
        ],
    )
    def test_selection_minus_filters(self, true_names, expected):
        assert evaluate("selection and not 1 of filter*", true_names) is expected

    def test_all_of_them(self):
        names = ["a", "b"]
        assert evaluate("all of them", {"a", "b"}, names)
        assert not evaluate("all of them", {"a"}, names)

    def test_double_negation(self):
        assert evaluate("not not selection", {"selection"})

    def test_short_circuit(self):
        calls = []

        def resolve(name):
            calls.append(name)
            return name == "selection"

        parse_condition("selection or filter", NAMES).evaluate(resolve)
        assert calls == ["selection"]


class TestErrors:
    @pytest.mark.parametrize(
        ("condition", "message"),
        [
            ("", "empty condition"),
            ("   ", "empty condition"),
            ("unknown", "unknown selection 'unknown'"),
            ("selection and", "ends unexpectedly"),
            ("selection filter", "unexpected 'filter'"),
            ("(selection", "ends unexpectedly"),
            ("(selection filter)", "missing '\\)'"),
            ("selection)", "unexpected '\\)'"),
            (")", "unexpected '\\)'"),
            ("and selection", "unexpected 'and'"),
            ("1 of nothing_*", "matches no selection"),
            ("1 of (selection)", "needs a name pattern"),
            ("selection | count() > 5", "correlation rule"),
        ],
    )
    def test_rejected(self, condition, message):
        with pytest.raises(SigmaError, match=message):
            parse_condition(condition, NAMES)

    @pytest.mark.parametrize("condition", [[], [1], 3, None])
    def test_invalid_type(self, condition):
        with pytest.raises(SigmaError, match="string or a list"):
            parse_condition(condition, NAMES)

    def test_base_node_is_abstract(self):
        from vigie.sigma.condition import Node

        with pytest.raises(NotImplementedError):
            Node().evaluate(lambda _name: True)

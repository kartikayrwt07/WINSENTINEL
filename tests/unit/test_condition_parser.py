"""Unit tests for AST condition tokenizer, nodes, and recursive-descent parser."""

from unittest.mock import Mock

import pytest

from app.detection.ast_parser import (
    AndNode,
    ASTNode,
    ConditionParser,
    ConditionTokenizer,
    IdentifierNode,
    NotNode,
    OrNode,
    QuantifierNode,
    RuleSyntaxError,
    TokenType,
)


def test_tokenizer_basic_tokens():
    """Verify ConditionTokenizer recognizes all core tokens and case variants."""
    expr = "(selection_1 AND NOT filter_1) or 1 of selection* or ALL OF sel_*"
    tokenizer = ConditionTokenizer()
    tokens = tokenizer.tokenize(expr)

    expected_types = [
        TokenType.LPAREN,
        TokenType.IDENTIFIER,
        TokenType.AND,
        TokenType.NOT,
        TokenType.IDENTIFIER,
        TokenType.RPAREN,
        TokenType.OR,
        TokenType.QUANTIFIER_OF,
        TokenType.IDENTIFIER,
        TokenType.OR,
        TokenType.QUANTIFIER_OF,
        TokenType.IDENTIFIER,
        TokenType.EOF,
    ]
    assert [t.type for t in tokens] == expected_types
    assert tokens[7].value.lower() == "1 of"
    assert tokens[10].value.lower() == "all of"


def test_identifier_node_evaluation():
    """Verify IdentifierNode evaluates to context.get(name, False)."""
    node = IdentifierNode(name="selection_proc")
    assert node.evaluate({"selection_proc": True}) is True
    assert node.evaluate({"selection_proc": False}) is False
    assert node.evaluate({"other_key": True}) is False


def test_not_node_evaluation():
    """Verify NotNode negates its operand."""
    node = NotNode(operand=IdentifierNode("filter_benign"))
    assert node.evaluate({"filter_benign": True}) is False
    assert node.evaluate({"filter_benign": False}) is True
    assert node.evaluate({}) is True


def test_and_node_short_circuit():
    """Verify AndNode short-circuits evaluation when left branch is False."""
    mock_right = Mock(spec=ASTNode)
    node = AndNode(left=IdentifierNode("sel_a"), right=mock_right)

    # Left evaluates to False -> right should NOT be called
    result = node.evaluate({"sel_a": False})
    assert result is False
    mock_right.evaluate.assert_not_called()

    # Left evaluates to True -> right SHOULD be called
    mock_right.evaluate.return_value = True
    result = node.evaluate({"sel_a": True})
    assert result is True
    mock_right.evaluate.assert_called_once()


def test_or_node_short_circuit():
    """Verify OrNode short-circuits evaluation when left branch is True."""
    mock_right = Mock(spec=ASTNode)
    node = OrNode(left=IdentifierNode("sel_a"), right=mock_right)

    # Left evaluates to True -> right should NOT be called
    result = node.evaluate({"sel_a": True})
    assert result is True
    mock_right.evaluate.assert_not_called()

    # Left evaluates to False -> right SHOULD be called
    mock_right.evaluate.return_value = False
    result = node.evaluate({"sel_a": False})
    assert result is False
    mock_right.evaluate.assert_called_once()


def test_quantifier_node_one_of():
    """Verify QuantifierNode with '1 of' returns True if ANY matching key is True."""
    node = QuantifierNode(quantifier="1 of", pattern="selection*")
    ctx = {
        "selection_1": False,
        "selection_2": True,
        "selection_3": False,
        "filter_1": True,
    }
    assert node.evaluate(ctx) is True

    # No match among pattern keys
    ctx_false = {
        "selection_1": False,
        "selection_2": False,
        "filter_1": True,
    }
    assert node.evaluate(ctx_false) is False

    # Empty matching keys
    assert node.evaluate({"unrelated": True}) is False


def test_quantifier_node_all_of():
    """Verify QuantifierNode with 'all of' returns True only if ALL matching keys are True."""
    node = QuantifierNode(quantifier="all of", pattern="selection*")
    assert node.evaluate({"selection_1": True, "selection_2": True}) is True
    assert node.evaluate({"selection_1": True, "selection_2": False}) is False
    assert node.evaluate({"selection_1": False, "selection_2": False}) is False
    # No matching keys -> False
    assert node.evaluate({}) is False


def test_quantifier_node_them():
    """Verify QuantifierNode with 'them' evaluates all context keys except 'filter*'."""
    node = QuantifierNode(quantifier="1 of", pattern="them")
    ctx = {
        "filter_admin": True,
        "selection_a": False,
        "selection_b": True,
    }
    assert node.evaluate(ctx) is True

    ctx_only_filters = {
        "filter_admin": True,
        "filter_system": True,
    }
    # No non-filter keys are present
    assert node.evaluate(ctx_only_filters) is False


def test_parser_operator_precedence():
    """Verify ConditionParser enforces precedence: not > and > or."""
    parser = ConditionParser()
    # "sel_a or sel_b and sel_c" should parse as "sel_a or (sel_b and sel_c)"
    ast = parser.parse("sel_a or sel_b and sel_c")
    assert isinstance(ast, OrNode)
    assert isinstance(ast.left, IdentifierNode)
    assert ast.left.name == "sel_a"
    assert isinstance(ast.right, AndNode)
    assert ast.right.left.name == "sel_b"
    assert ast.right.right.name == "sel_c"

    # Evaluation test
    # sel_a=False, sel_b=True, sel_c=False -> False
    assert ast.evaluate({"sel_a": False, "sel_b": True, "sel_c": False}) is False
    # sel_a=False, sel_b=True, sel_c=True -> True
    assert ast.evaluate({"sel_a": False, "sel_b": True, "sel_c": True}) is True


def test_parser_parentheses_grouping():
    """Verify ConditionParser respects explicit grouping parentheses."""
    parser = ConditionParser()
    ast = parser.parse("(sel_a or sel_b) and not filt")
    assert isinstance(ast, AndNode)
    assert isinstance(ast.left, OrNode)
    assert isinstance(ast.right, NotNode)

    # (True or False) and not (False) -> True
    assert ast.evaluate({"sel_a": True, "sel_b": False, "filt": False}) is True
    # (True or False) and not (True) -> False
    assert ast.evaluate({"sel_a": True, "sel_b": False, "filt": True}) is False


def test_parser_syntax_errors():
    """Verify ConditionParser raises RuleSyntaxError on malformed inputs."""
    parser = ConditionParser()

    with pytest.raises(RuleSyntaxError, match="Empty condition"):
        parser.parse("")

    with pytest.raises(RuleSyntaxError, match="Empty condition"):
        parser.parse("   ")

    with pytest.raises(RuleSyntaxError):
        parser.parse("(sel_a and sel_b")  # Unbalanced (

    with pytest.raises(RuleSyntaxError):
        parser.parse("sel_a and sel_b)")  # Unbalanced )

    with pytest.raises(RuleSyntaxError):
        parser.parse("sel_a and")  # Trailing operator

    with pytest.raises(RuleSyntaxError):
        parser.parse("1 of")  # Missing pattern after quantifier

    with pytest.raises(RuleSyntaxError):
        parser.parse("sel_a @ sel_b")  # Invalid character


def test_zero_eval_guarantee():
    """Verify ast_parser does not import or invoke eval or exec."""
    import inspect
    from app.detection import ast_parser

    source = inspect.getsource(ast_parser)
    assert "eval(" not in source
    assert "exec(" not in source
    assert "literal_eval" not in source

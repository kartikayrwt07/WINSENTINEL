# Phase 4 Plan 01: Detection Rule Schema, AST Condition Parser & Rule Loader Summary

**Plan ID:** `04-01`  
**Phase:** `WINSENTINEL-04-detection-rule-engine-sysmon-core-library`  
**Completed At:** 2026-11-04  
**Status:** Completed  

---

## 1. Executive Summary

Plan `04-01` establishes the foundational data schemas, zero-eval recursive-descent boolean AST condition parser, and YAML directory rule loader for the WinSentinel Detection Engine.

All components adhere strictly to Pydantic v2 strict typing, guarantee zero dynamic evaluation (`eval()` / `exec()` / `literal_eval()`), enforce deterministic boolean operator precedence (`not` > `and` > `or`), handle complex Sigma quantifiers (`1 of selection*`, `all of selection*`, `1 of them`), and provide idempotent SQLite synchronization into the `detection_rules` table with duplicate ID collision protection.

---

## 2. Implemented Components

### 2.1 Pydantic v2 Rule Schema (`app/models/rule.py`)
- **`RuleSeverity(str, Enum)`**: Case-insensitive enumeration supporting `informational`, `low`, `medium`, `high`, `critical`.
- **`RuleStatus(str, Enum)`**: Case-insensitive enumeration supporting `active`, `testing`, `deprecated`.
- **`LogSource(BaseModel)`**: Normalizes category, product (defaulting to `"windows"`), service, and event IDs (coercing single ints, string ints, lists, or CSV strings).
- **`DetectionBlock(BaseModel)`**: Validates non-empty `condition` string while dynamically capturing selection and filter dictionaries via `model_validator(mode="before")`.
- **`DetectionRule(BaseModel)`**: Validates core metadata (`id`, `title`, `description`, `author`, `severity`, `status`, `logsource`, `detection`), captures MITRE ATT&CK techniques (including extracting from Sigma `tags`), tracks investigation guidance, and preserves the original `raw_yaml` text. Supports `DetectionRule.from_yaml(content)`.

### 2.2 Zero-Eval Recursive-Descent Boolean AST Parser (`app/detection/ast_parser.py`)
- **`RuleSyntaxError(ValueError)`**: Diagnostic exception providing token details and character offsets.
- **`TokenType(str, Enum)` & `Token`**: Lexical tokens for `LPAREN`, `RPAREN`, `AND`, `OR`, `NOT`, `QUANTIFIER_OF`, `IDENTIFIER`, `EOF`.
- **`ConditionTokenizer`**: Regex scanner identifying grouping parentheses, boolean keywords, quantifiers (`1 of`, `all of`), and wildcard patterns.
- **AST Node Hierarchy (`ASTNode`)**:
  - `IdentifierNode`: Resolves context boolean flags (`context.get(name, False)`).
  - `NotNode`: Inverts operand truth value.
  - `AndNode`: Evaluates operands with left-to-right short-circuiting.
  - `OrNode`: Evaluates operands with left-to-right short-circuiting.
  - `QuantifierNode`: Evaluates globs using `fnmatch.fnmatch` or matches all non-filter keys for `them`. Supports arbitrary count thresholds and `all of`.
- **`ConditionParser`**: Recursive-descent grammar enforcing precedence:
  $$\text{Parentheses} > \text{Quantifiers} > \text{NOT} > \text{AND} > \text{OR}$$
  Guarantees 100% zero dynamic code execution (`eval` / `exec`).

### 2.3 YAML Rule Loader & Database Synchronizer (`app/detection/loader.py`)
- **`RuleLoader`**:
  - `load_rule_from_yaml`: Parses YAML with `yaml.safe_load`, validates schema, and validates condition syntax.
  - `load_rule_from_file`: Resolves paths and loads single rules.
  - `load_rules_from_directory`: Recursively traverses directories, filters `.yml`/`.yaml` files, enforces unique rule IDs via `DuplicateRuleIdError`, and supports strict/lenient validation modes.
  - `sync_rules_to_database` / `sync_rules_to_db`: Idempotently upserts loaded rules into the SQLite `detection_rules` table using `INSERT INTO detection_rules ... ON CONFLICT(id) DO UPDATE`.

---

## 3. Verification & Test Execution Results

- **Unit Tests Added:**
  - `tests/unit/test_rule_schema.py` (10 tests, 100% passed)
  - `tests/unit/test_condition_parser.py` (12 tests, 100% passed)
  - `tests/unit/test_rule_loader.py` (8 tests, 100% passed)
- **Full Regression Test Suite:**
  - 178 tests passed, 0 failures, 0 warnings.
  - Full backward compatibility verified across ingestion, normalizers, database repositories, and process tree analyzers.

---

## 4. Modified & Created Files

- `app/models/rule.py` (Created)
- `app/models/__init__.py` (Updated to export rule models)
- `app/detection/__init__.py` (Created)
- `app/detection/ast_parser.py` (Created)
- `app/detection/loader.py` (Created)
- `tests/unit/test_rule_schema.py` (Created)
- `tests/unit/test_condition_parser.py` (Created)
- `tests/unit/test_rule_loader.py` (Created)
- `.planning/phases/WINSENTINEL-04-detection-rule-engine-sysmon-core-library/04-01-SUMMARY.md` (Created)

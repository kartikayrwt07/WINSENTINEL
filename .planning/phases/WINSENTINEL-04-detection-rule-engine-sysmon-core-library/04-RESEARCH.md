# Phase 4: Detection Rule Engine & Sysmon Core Library - Research

**Date:** 2026-11-04  
**Status:** Completed  
**Author:** Antigravity Research Agent  
**Context:** WinSentinel Phase 4 Architecture & Design Research

---

## 1. Executive Summary & Phase Scope

Phase 4 implements the core detection logic of WinSentinel: a Sigma-inspired YAML detection rule loader, validator, AST-based condition evaluator, field matcher, and an out-of-the-box library of 16+ high-fidelity Sysmon detection rules producing forensic, explainable alerts.

### Requirements Addressed
- **RULE-01:** YAML-based Sigma-inspired rule schema parser with strict validation (rule metadata, event selection, conditions, severity, exclusions).
- **RULE-02:** Field-matching engine supporting exact match, case-insensitive match, substring contains, regex patterns, and wildcards.
- **RULE-03:** Rule exclusion filtering to eliminate known benign administrative baselines.
- **RULE-04:** Detection match output containing matched rule ID, matched event records, exact matching field/value pairs, detection explanation, and investigation guidance.
- **RULE-05:** Core rule library for process execution, privilege escalation, credential dumping access (EID 10 targeting LSASS), and lateral movement indicators.

### Key Architectural Tenets
1. **Zero-Eval Safety:** No dynamic Python execution (`eval()`, `exec()`, `ast.literal_eval()`) for condition evaluation. Expressions are parsed into an explicit AST via a recursive-descent parser with strict operator precedence.
2. **Deterministic Explainability:** Detections are never opaque booleans. Every match constructs a `DetectionMatch` containing exact triggering fields, values, condition modifiers, and human-readable forensic explanations.
3. **High-Throughput Dispatch ($O(1)$ Indexing):** Rules are indexed in-memory by `(provider, event_id)`, bypassing irrelevant rules during bulk event ingestion.
4. **Resilient Field Resolution:** Handles PascalCase Sigma naming conventions (`CommandLine`, `Image`, `TargetFilename`) seamlessly alongside WinSentinel's snake_case schema (`command_line`, `image`, `target_filename`) and dynamically queries `extra_fields` when needed.

---

## 2. Architecture & Component Breakdown

```
                    ┌────────────────────────────────────────┐
                    │        YAML Rule Files (.yml)          │
                    │      (rules/sysmon/<category>/)        │
                    └───────────────────┬────────────────────┘
                                        │
                                        ▼
                    ┌────────────────────────────────────────┐
                    │              RuleLoader                │
                    │   - Directory recursive scan           │
                    │   - Pydantic v2 Schema Validation      │
                    │   - Duplicate ID detection             │
                    │   - SQLite detection_rules sync        │
                    └───────────────────┬────────────────────┘
                                        │
                                        ▼
                    ┌────────────────────────────────────────┐
                    │          CompiledRule / Engine         │
                    │   - Pre-parsed AST Condition           │
                    │   - Pre-compiled regular expressions   │
                    │   - (provider, event_id) fast index    │
                    └───────────────────┬────────────────────┘
                                        │
NormalizedEvent ───────────────────────►│  Engine.evaluate_event()
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
              ┌────────────────────┐        ┌────────────────────┐
              │    FieldMatcher    │        │    ASTEvaluator    │
              │  - Case-folding    │        │  - and / or / not  │
              │  - Modifiers       │        │  - 1 of sel_*      │
              │  - Implicit OR     │        │  - all of sel_*    │
              │  - Evidence collect│        │  - Parentheses     │
              └──────────┬─────────┘        └──────────┬─────────┘
                         │                             │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                    ┌────────────────────────────────────────┐
                    │             DetectionMatch             │
                    │  - rule_id, severity, timestamp        │
                    │  - matched_evidence (field/value pairs)│
                    │  - human forensic explanation          │
                    │  - MITRE tactics & techniques          │
                    │  - investigation steps                 │
                    └───────────────────┬────────────────────┘
                                        │
                                        ▼
                    ┌────────────────────────────────────────┐
                    │            AlertRepository             │
                    │   - alerts table                       │
                    │   - alert_evidence table               │
                    └────────────────────────────────────────┘
```

---

### 2.1 Rule AST Tokenizer & Recursive-Descent Parser

Sigma condition expressions permit arbitrary boolean combinations, grouping parentheses, and pattern-based aggregations:
- `selection`
- `selection and not filter`
- `(sel_a or sel_b) and not (filt_c or filt_d)`
- `1 of selection*`
- `all of selection*`
- `1 of selection* and not filter`
- `1 of them`

#### Grammar Specification (EBNF)
```ebnf
Expression      ::= OrExpression ;
OrExpression    ::= AndExpression ( ('or' | 'OR') AndExpression )* ;
AndExpression   ::= NotExpression ( ('and' | 'AND') NotExpression )* ;
NotExpression   ::= ('not' | 'NOT') NotExpression | PrimaryExpression ;
PrimaryExpression ::= '(' Expression ')' 
                    | QuantifierExpression 
                    | IdentifierExpression ;
QuantifierExpression ::= ('1 of' | 'all of') Pattern ;
Pattern         ::= [a-zA-Z0-9_*]+ ;
IdentifierExpression ::= [a-zA-Z0-9_]+ ;
```

#### Token Definitions
- `LPAREN`: `(`
- `RPAREN`: `)`
- `AND`: `and`, `AND`
- `OR`: `or`, `OR`
- `NOT`: `not`, `NOT`
- `QUANTIFIER`: `1 of`, `all of`
- `IDENTIFIER`: Valid selection or filter key (e.g., `selection_1`, `filter_sys`)
- `PATTERN`: Wildcard identifier (e.g., `selection*`, `sel_*`, `them`)

#### AST Node Hierarchy
```python
class ASTNode(ABC):
    @abstractmethod
    def evaluate(self, context: dict[str, bool]) -> bool:
        """Evaluate node against a dictionary of named selection match results."""
        pass

class IdentifierNode(ASTNode):
    name: str
    def evaluate(self, context: dict[str, bool]) -> bool:
        return context.get(self.name, False)

class NotNode(ASTNode):
    operand: ASTNode
    def evaluate(self, context: dict[str, bool]) -> bool:
        return not self.operand.evaluate(context)

class AndNode(ASTNode):
    left: ASTNode
    right: ASTNode
    def evaluate(self, context: dict[str, bool]) -> bool:
        # Short-circuiting evaluation
        return self.left.evaluate(context) and self.right.evaluate(context)

class OrNode(ASTNode):
    left: ASTNode
    right: ASTNode
    def evaluate(self, context: dict[str, bool]) -> bool:
        # Short-circuiting evaluation
        return self.left.evaluate(context) or self.right.evaluate(context)

class QuantifierNode(ASTNode):
    quantifier: Literal["1 of", "all of"]
    pattern: str  # e.g., "selection*" or "them"
    def evaluate(self, context: dict[str, bool]) -> bool:
        if self.pattern == "them":
            # Match all keys except those starting with 'filter'
            matched_keys = [k for k in context if not k.startswith("filter")]
        else:
            matched_keys = [k for k in context if fnmatch.fnmatch(k, self.pattern)]
            
        if not matched_keys:
            return False
            
        if self.quantifier == "1 of":
            return any(context[k] for k in matched_keys)
        elif self.quantifier == "all of":
            return all(context[k] for k in matched_keys)
        return False
```

#### Evaluation Guarantees
- **No Python Eval:** Fully deterministic tree traversal.
- **Short-circuiting:** `AndNode` and `OrNode` short-circuit on the left branch, minimizing unnecessary evaluation.
- **Syntax Error Safety:** Unbalanced parentheses, trailing operators, or unknown tokens raise custom `RuleSyntaxError` with line and token offsets.

---

### 2.2 Field Matcher & Modifier Pipeline

The field matcher evaluates individual selection blocks against a `NormalizedEvent`.

#### Field Extraction & Normalization
Sigma rules frequently use PascalCase (`CommandLine`, `Image`, `TargetFilename`), while WinSentinel's `NormalizedEvent` uses snake_case (`command_line`, `image`, `target_filename`).
Furthermore, some fields have aliases:
- `TargetObject` ➔ `registry_target_object`
- `Details` ➔ `registry_details`
- `NewName` ➔ `registry_new_name`
- `DestinationIp` / `DestinationIP` ➔ `destination_ip`
- `SourceIp` / `SourceIP` ➔ `source_ip`
- `Hashes` ➔ `hashes` (dict search or string representation)

**Resolution Hierarchy:**
1. Check direct attribute on `NormalizedEvent` via exact snake_case name.
2. Check alias mapping table.
3. Check `event.extra_fields` dictionary.
4. If field does not exist or value is `None`, the match evaluates to `False` (unless explicit null check).

#### Modifier Pipeline
Field names in YAML selections can append pipe-delimited modifiers:
`field|modifier1|modifier2` (e.g., `image|endswith`, `command_line|contains|all`, `command_line|re`).

Supported Modifiers:
- **Default (no modifier):** Exact match, case-insensitive string equality (or integer equality if numeric).
- **`|contains`:** Substring inclusion, case-insensitive (`needle.lower() in haystack.lower()`).
- **`|startswith`:** Prefix match, case-insensitive (`haystack.lower().startswith(prefix.lower())`).
- **`|endswith`:** Suffix match, case-insensitive (`haystack.lower().endswith(suffix.lower())`).
- **`|re`:** Regular expression search using pre-compiled regex (`re.compile(pattern, re.IGNORECASE)`).
- **`|all`:** Used with a list of values. Requires **all** values in the list to match the field.
- **Implicit OR:** By default, if the rule provides a list of values without `|all`, the condition is satisfied if **any** value matches.

```python
@dataclass(frozen=True)
class FieldCriterion:
    field_name: str
    match_type: Literal["exact", "contains", "startswith", "endswith", "re"]
    is_all: bool
    patterns: list[str | int | float | None]
    compiled_regexes: list[re.Pattern] = field(default_factory=list)
```

---

### 2.3 Pydantic v2 Rule Schema

Rules are defined in YAML and validated via Pydantic v2 models.

```python
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field, field_validator

class RuleSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class RuleStatus(str, Enum):
    ACTIVE = "active"
    TESTING = "testing"
    DEPRECATED = "deprecated"

class LogSource(BaseModel):
    model_config = ConfigDict(extra="ignore")
    category: str | None = None
    product: str | None = "windows"
    service: str | None = None
    event_id: int | list[int] | None = None

class DetectionBlock(BaseModel):
    model_config = ConfigDict(extra="allow")
    condition: str
    # Selections and filters are captured dynamically from extra fields

class DetectionRule(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(..., description="Unique UUID or slug identifier (e.g. WS-SYS-001)")
    title: str = Field(..., min_length=5, description="Descriptive rule title")
    description: str = Field(..., description="Detection purpose and threat context")
    author: str = Field(default="WinSentinel Team")
    severity: RuleSeverity = RuleSeverity.MEDIUM
    status: RuleStatus = RuleStatus.ACTIVE
    logsource: LogSource = Field(default_factory=LogSource)
    detection: DetectionBlock
    mitre_attack: list[str] = Field(default_factory=list, description="ATT&CK IDs e.g. T1059.001")
    references: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)
    investigation_steps: list[str] = Field(default_factory=list)
    raw_yaml: str = Field(default="", description="Preserved YAML text for database persistence")

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Rule ID cannot be empty")
        return clean
```

---

### 2.4 Match Explainability & Evidence Schema

Whenever a rule condition evaluates to `True`, the engine produces a `DetectionMatch` containing full provenance.

```python
@dataclass(frozen=True)
class EvidenceItem:
    field: str
    actual_value: Any
    matched_pattern: Any
    modifier: str

@dataclass
class DetectionMatch:
    rule_id: str
    rule_title: str
    severity: str
    event_id: int
    event_record_id: int | None
    event_db_id: int | None
    computer: str
    timestamp_utc: datetime
    process_guid: str | None
    user: str | None
    matched_evidence: list[EvidenceItem]
    explanation: str
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    investigation_steps: list[str]
```

#### Alert Repository Bridge
The `DetectionMatch` maps cleanly to `AlertRepository.create_alert()` and `AlertRepository.link_alert_evidence()`:
1. `create_alert`:
   - `rule_id = match.rule_id`
   - `title = match.rule_title`
   - `severity = match.severity`
   - `computer = match.computer`
   - `user = match.user`
   - `process_guid = match.process_guid`
   - `first_seen = match.timestamp_utc`
   - `last_seen = match.timestamp_utc`
   - `description = match.explanation`
   - `mitre_tactics = match.mitre_tactics`
   - `mitre_techniques = match.mitre_techniques`
2. `link_alert_evidence`:
   - `alert_id = alert_id`
   - `event_id = match.event_db_id`
   - `matched_field = json.dumps([e.field for e in match.matched_evidence])`
   - `matched_value = json.dumps([str(e.actual_value) for e in match.matched_evidence])`
   - `explanation = match.explanation`

---

### 2.5 Rule Engine Indexing ($O(1)$ Dispatch)

In high-volume log streams (10,000+ events/sec), evaluating every rule against every event degrades performance.
The engine builds an in-memory index keyed by `(provider, event_id)`:

```python
class DetectionEngine:
    def __init__(self):
        # Key: (provider_normalized, event_id) -> list[CompiledRule]
        self._index: dict[tuple[str, int], list[CompiledRule]] = defaultdict(list)
        # Wildcard rules (rules that match across any event ID or provider)
        self._universal_rules: list[CompiledRule] = []

    def register_rule(self, rule: DetectionRule) -> None:
        compiled = self._compile_rule(rule)
        target_eids = self._extract_target_event_ids(rule)
        provider = (rule.logsource.service or rule.logsource.product or "").lower()

        if not target_eids:
            self._universal_rules.append(compiled)
        else:
            for eid in target_eids:
                self._index[(provider, eid)].append(compiled)

    def evaluate_event(self, event: NormalizedEvent, event_db_id: int | None = None) -> list[DetectionMatch]:
        provider = event.provider.lower()
        # Find candidates matching (provider, event_id)
        candidates = self._index.get((provider, event.event_id), [])
        # Also check without provider or universal rules
        rules_to_run = candidates + self._universal_rules

        matches = []
        for rule in rules_to_run:
            match = rule.match(event, event_db_id=event_db_id)
            if match is not None:
                matches.append(match)
        return matches
```

---

### 2.6 Sysmon Core Rule Library (16 Rules)

The table below outlines the 16 core detection rules to be authored and validated in `rules/sysmon/<category>/`:

| # | Rule ID | Title | EID | MITRE ID | Threat Description & Detection Criteria |
|---|---------|-------|-----|----------|-----------------------------------------|
| 1 | `WS-SYS-001` | Suspicious Certutil Download | 1 | T1105 | `image\|endswith: '\certutil.exe'` AND `command_line\|contains: ['-urlcache', '-split']` |
| 2 | `WS-SYS-002` | Suspicious Mshta Remote Execution | 1 | T1218.005 | `image\|endswith: '\mshta.exe'` AND `command_line\|contains: ['http://', 'https://', 'javascript:', 'vbscript:']` |
| 3 | `WS-SYS-003` | BITSAdmin Job Download | 1 | T1197 | `image\|endswith: '\bitsadmin.exe'` AND `command_line\|contains: ['/transfer', '/create', '/addfile']` |
| 4 | `WS-SYS-004` | UAC Bypass via Fodhelper | 1 | T1548.002 | `parent_image\|endswith: '\fodhelper.exe'` AND `image\|endswith: ['\cmd.exe', '\powershell.exe', '\pwsh.exe']` |
| 5 | `WS-SYS-005` | Rundll32 Suspicious Execution | 1 | T1218.011 | `image\|endswith: '\rundll32.exe'` AND `command_line\|contains: ['\AppData\Local\Temp', '\Users\Public\', 'javascript:']` |
| 6 | `WS-SYS-006` | Whoami Reconnaissance | 1 | T1033 | `image\|endswith: '\whoami.exe'` AND `command_line\|contains: ['/priv', '/all', '/groups']` |
| 7 | `WS-SYS-007` | Regsvr32 Squiblydoo Remote Script | 1 | T1218.010 | `image\|endswith: '\regsvr32.exe'` AND `command_line\|contains: ['/s', '/u', '/i:http', 'scrobj.dll']` |
| 8 | `WS-SYS-008` | Remote Thread Injection into LSASS | 8 | T1055, T1003.001 | `target_image\|endswith: '\lsass.exe'` AND NOT `source_image\|endswith: ['\csrss.exe']` |
| 9 | `WS-SYS-009` | Remote Thread into Sensitive Process | 8 | T1055.001 | `target_image\|endswith: ['\explorer.exe', '\svchost.exe']` AND `source_image\|contains: ['\Temp\', '\Users\Public\']` |
| 10 | `WS-SYS-010` | Suspicious LSASS GrantedAccess | 10 | T1003.001 | `target_image\|endswith: '\lsass.exe'` AND `granted_access\|contains: ['0x1010', '0x1410', '0x1038', '0x1F0FFF', '0x143A']` (with svchost filter) |
| 11 | `WS-SYS-011` | Mimikatz Sekurlsa Call Trace | 10 | T1003.001 | `target_image\|endswith: '\lsass.exe'` AND `call_trace\|contains: ['sekurlsa.dll', 'dbghelp.dll']` |
| 12 | `WS-SYS-012` | Unsigned Driver Loaded | 6 | T1068, T1562.001 | `signed: 'false'` OR `signature_status\|contains: ['revoked', 'invalid', 'untrusted']` |
| 13 | `WS-SYS-013` | DLL Loaded from Temp Directory | 7 | T1574.002 | `image_loaded\|contains: ['\AppData\Local\Temp\', '\Windows\Temp\', '\Users\Public\']` AND NOT `signed: 'true'` |
| 14 | `WS-SYS-014` | Registry Run Key Persistence | 12, 13 | T1547.001 | `registry_target_object\|contains: ['\CurrentVersion\Run', '\CurrentVersion\RunOnce']` (filtering known benign updaters) |
| 15 | `WS-SYS-015` | IFEO Debugger Persistence | 12, 14 | T1546.012 | `registry_target_object\|contains: '\Image File Execution Options\'` AND `registry_target_object\|endswith: '\Debugger'` |
| 16 | `WS-SYS-016` | Suspicious Dynamic DNS Query | 22 | T1071.004, T1568.002 | `query_name\|endswith: ['.duckdns.org', '.hopto.org', '.no-ip.biz', '.no-ip.org', '.zapto.org', '.ngrok.io', '.ngrok-free.app']` |

---

## 3. Technical Risks, Traps & Landmines

### 3.1 ReDoS (Regular Expression Denial of Service)
- **Risk:** Malicious or poorly designed regular expressions with nested quantifiers (e.g., `(a+)+$`) cause exponential backtracking, freezing the ingestion thread.
- **Mitigation:**
  1. Compile all regexes once during rule loading/validation. Any pattern that fails compilation or exceeds 250 characters is rejected.
  2. Enforce regex safety checks (prevent obvious ReDoS constructs like nested `+` or `*`).
  3. Prepend/append word boundaries or limit matches to safe single-line evaluations.

### 3.2 Boolean Operator Precedence Trap
- **Risk:** Ambiguity in condition expressions like `selection and not filter1 or filter2`. In standard logic, `not` binds tightest, followed by `and`, followed by `or`. A naïve string replacer or flawed parser would evaluate `(selection and not filter1) or filter2`.
- **Mitigation:**
  The recursive-descent parser enforces explicit precedence:
  `OrExpression` calls `AndExpression`, which calls `NotExpression`, which calls `PrimaryExpression`.
  Parentheses `( ... )` explicitly override precedence.

### 3.3 Missing or Null Fields
- **Risk:** Sysmon events often have `None` values for fields that are only present in specific contexts (e.g. `call_trace` is null in non-injection events, `command_line` is null if truncation occurs). Calling `.lower()` or `.endswith()` on `None` raises `AttributeError`.
- **Mitigation:**
  Field matching logic explicitly guards:
  ```python
  if actual_value is None:
      return False
  ```
  If an event does not have the field, the criterion evaluates to `False` without raising an exception.

### 3.4 Sysmon GrantedAccess Format Discrepancies (EID 10)
- **Risk:** Sysmon records `GrantedAccess` in hexadecimal format, but casing varies across Windows versions (e.g., `0x1010`, `0x1410`, `0x1F0FFF` vs `0x1f0fff`).
- **Mitigation:**
  Hex values and masks are normalized using case-insensitive string matching (`.lower()`) and optional bitwise mask checking.

### 3.5 Schema Discrepancy (Sigma PascalCase vs WinSentinel snake_case)
- **Risk:** Sigma rules written by security analysts use `CommandLine`, `Image`, `TargetObject`. If the engine only looks for `command_line` or `image`, the rule silently fails to match.
- **Mitigation:**
  A canonical field resolver converts PascalCase to snake_case via regex substitution (`re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()`) and maps known aliases (e.g. `TargetObject` ➔ `registry_target_object`).

---

## 4. Test Strategy & Plan Recommendations

### Phase 4 Wave Breakdown

#### Plan 04-01: Rule Schema, Validator, AST Parser & Loader (Wave 1)
- **Components:**
  - `app/engine/schema.py`: Pydantic v2 `DetectionRule`, `LogSource`, `DetectionBlock`, `RuleSeverity`, `RuleStatus`.
  - `app/engine/parser.py`: Safe recursive-descent boolean parser, AST node definitions, tokenizer, quantifier evaluator (`1 of`, `all of`).
  - `app/engine/loader.py`: Recursive directory loader (`load_rules_from_dir`), duplicate ID validation, SQLite `detection_rules` table synchronizer.
- **Tests:**
  - Unit tests for AST parser with nested parentheses, operators, and quantifiers.
  - Unit tests for Pydantic schema validation (missing fields, invalid severity, malformed conditions).
  - Unit tests for directory loading and duplicate detection.

#### Plan 04-02: Field Matcher, Modifiers, Match Explainability & Rule Engine Index (Wave 2)
- **Components:**
  - `app/engine/matcher.py`: Field extraction from `NormalizedEvent`, alias translation, modifier pipeline (`exact`, `contains`, `startswith`, `endswith`, `re`, `all`, implicit OR).
  - `app/engine/evidence.py`: `EvidenceItem`, `DetectionMatch`, and forensic explanation generator.
  - `app/engine/engine.py`: `DetectionEngine` with `(provider, event_id)` in-memory index, `evaluate_event()`, batch event processing, and adapter linking to `AlertRepository`.
- **Tests:**
  - Unit tests for all string modifiers and edge cases (None values, case-insensitivity, list OR vs list AND).
  - Unit tests for evidence extraction and explanation formatting.
  - Unit tests for engine indexing and $O(1)$ dispatch.
  - Integration test saving `DetectionMatch` into SQLite `alerts` and `alert_evidence`.

#### Plan 04-03: Core Sysmon Detection Rule Library (16 Rules) & Pipeline Integration (Wave 3)
- **Components:**
  - `rules/sysmon/`: 16 production-grade YAML rules categorized into subdirectories (`process_creation`, `remote_thread`, `process_access`, `driver_load`, `image_load`, `registry`, `dns_query`).
  - Integration with ingestion pipeline / batch processor to automatically run detection engine during log import.
- **Tests:**
  - Comprehensive test suite with synthetic ground-truth Sysmon events matching all 16 rules.
  - False-positive validation test suite ensuring benign administrative events trigger zero alerts.

---

## 5. Summary & Readiness

All foundational requirements (`RULE-01` to `RULE-05`) and user decisions (`D-01` to `D-06`) have been thoroughly analyzed. The design guarantees:
- Zero use of Python `eval()`.
- Strict schema validation via Pydantic v2.
- Full provenance and explainability in alerts.
- High performance via in-memory indexing.
- 16 production-grade rules ready for implementation.

"""Detection rule schema models for WinSentinel.

Defines Pydantic v2 data models for Sigma-inspired detection rules,
log source specifications, detection blocks, severity, and status enumerations.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class RuleSeverity(str, Enum):
    """Detection rule severity classifications."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleStatus(str, Enum):
    """Lifecycle status of a detection rule."""

    ACTIVE = "active"
    TESTING = "testing"
    DEPRECATED = "deprecated"


class LogSource(BaseModel):
    """Specification of the log source / channel required for a rule."""

    model_config = ConfigDict(extra="ignore")

    category: str | None = None
    product: str | None = "windows"
    service: str | None = None
    event_id: int | list[int] | None = None

    @field_validator("event_id", mode="before")
    @classmethod
    def _coerce_event_id(cls, v: Any) -> int | list[int] | None:
        if v is None:
            return None
        if isinstance(v, (int, float)):
            return int(v)
        if isinstance(v, str):
            v_str = v.strip()
            if not v_str:
                return None
            if "," in v_str:
                return [int(part.strip()) for part in v_str.split(",") if part.strip()]
            return int(v_str)
        if isinstance(v, (list, tuple, set)):
            return [int(item) for item in v]
        return v


class DetectionBlock(BaseModel):
    """Detection logic block containing boolean condition and named field criteria."""

    model_config = ConfigDict(extra="allow")

    condition: str
    selections: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _extract_selections(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        data_copy = dict(data)
        condition = data_copy.get("condition")
        if condition is None or not str(condition).strip():
            raise ValueError("Detection block must contain a non-empty 'condition'")

        selections = dict(data_copy.get("selections", {}))
        for key, val in list(data_copy.items()):
            if key not in ("condition", "selections"):
                selections[key] = val
        data_copy["selections"] = selections
        return data_copy

    def __getitem__(self, item: str) -> Any:
        if item in self.selections:
            return self.selections[item]
        raise KeyError(item)

    def get(self, item: str, default: Any = None) -> Any:
        return self.selections.get(item, default)


class DetectionRule(BaseModel):
    """Strict Pydantic v2 model for Sigma-inspired detection rules."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Unique UUID or slug identifier (e.g. WS-SYS-001)")
    title: str = Field(..., min_length=3, description="Descriptive rule title")
    description: str = Field(..., description="Detection purpose and threat context")
    author: str = Field(default="WinSentinel Team")
    severity: RuleSeverity = RuleSeverity.MEDIUM
    status: RuleStatus = RuleStatus.ACTIVE
    logsource: LogSource = Field(default_factory=LogSource)
    detection: DetectionBlock
    mitre_attack: list[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs e.g. T1059.001")
    references: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)
    investigation_steps: list[str] = Field(default_factory=list)
    raw_yaml: str = Field(default="", description="Preserved original YAML text")

    @field_validator("id")
    @classmethod
    def _validate_id(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Rule ID cannot be empty or whitespace only")
        return clean

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, v: Any) -> Any:
        if isinstance(v, str):
            clean = v.strip().lower()
            return RuleSeverity(clean)
        return v

    @field_validator("status", mode="before")
    @classmethod
    def _coerce_status(cls, v: Any) -> Any:
        if isinstance(v, str):
            clean = v.strip().lower()
            return RuleStatus(clean)
        return v

    @model_validator(mode="before")
    @classmethod
    def _extract_enrichments(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        data_copy = dict(data)
        # If mitre_attack is missing or empty, attempt extraction from Sigma 'tags'
        if not data_copy.get("mitre_attack") and "tags" in data_copy and isinstance(data_copy["tags"], list):
            mitre_list: list[str] = []
            for tag in data_copy["tags"]:
                if isinstance(tag, str) and tag.lower().startswith("attack.t"):
                    tech_id = tag.split(".", 1)[1].upper()
                    mitre_list.append(tech_id)
            if mitre_list:
                data_copy["mitre_attack"] = mitre_list
        return data_copy

    @classmethod
    def from_yaml(cls, yaml_content: str) -> DetectionRule:
        """Parse and validate a DetectionRule from YAML string content."""
        try:
            parsed = yaml.safe_load(yaml_content)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML content: {exc}") from exc

        if not isinstance(parsed, dict):
            raise ValueError("YAML content must evaluate to a dictionary")

        parsed["raw_yaml"] = yaml_content
        return cls.model_validate(parsed)

"""Event correlation and multi-stage attack detection package for WinSentinel."""

from app.correlation.alert_manager import (
    AlertManager,
    InvalidStatusTransitionError,
)
from app.correlation.chain_engine import AttackChainEngine
from app.correlation.chains import (
    CHAIN_CREDDUMP_LAT,
    CHAIN_LOTL_PERSIST,
    CHAIN_PHISH,
    CHAIN_WEBSHELL,
    CORE_ATTACK_CHAINS,
    AttackChainDefinition,
    ChainStageDefinition,
    get_default_attack_chains,
)
from app.models.incident import (
    CompoundIncident,
    IncidentStage,
    generate_incident_narrative,
)

__all__ = [
    "AlertManager",
    "InvalidStatusTransitionError",
    "AttackChainEngine",
    "AttackChainDefinition",
    "ChainStageDefinition",
    "CHAIN_PHISH",
    "CHAIN_WEBSHELL",
    "CHAIN_CREDDUMP_LAT",
    "CHAIN_LOTL_PERSIST",
    "CORE_ATTACK_CHAINS",
    "get_default_attack_chains",
    "CompoundIncident",
    "IncidentStage",
    "generate_incident_narrative",
]

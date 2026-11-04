"""Lineage-aware attack chain correlation engine for WinSentinel.

Traverses ProcessTreeGraph ancestor-descendant relationships within a configurable
sliding temporal window, scoped by host and user context, to elevate multi-stage
enterprise intrusions into Critical CompoundIncident records.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import timedelta, timezone
from typing import Any

from app.analyzers.process_analyzer import ProcessTreeGraph
from app.correlation.chains import (
    AttackChainDefinition,
    ChainStageDefinition,
    _get_basename,
    get_default_attack_chains,
)
from app.models.detection import DetectionMatch
from app.models.events import NormalizedEvent
from app.models.incident import (
    CompoundIncident,
    IncidentStage,
    generate_incident_narrative,
)

logger = logging.getLogger(__name__)

SYSTEM_USERNAMES = frozenset({
    "system",
    "nt authority\\system",
    "local system",
    "local service",
    "network service",
})


def _is_compatible_user(u1: str | None, u2: str | None) -> bool:
    """Return True if user contexts are compatible (identical or system elevation)."""
    if not u1 or not u2:
        return True
    c1 = u1.strip().lower()
    c2 = u2.strip().lower()
    if c1 == c2:
        return True
    # If one of the processes is SYSTEM or service account, allow privilege transition
    if c1 in SYSTEM_USERNAMES or c2 in SYSTEM_USERNAMES:
        return True
    return False


def _build_stage_narrative(stage_def: ChainStageDefinition, event: NormalizedEvent) -> str:
    """Generate a descriptive, human-readable forensic summary for a stage event."""
    img_name = _get_basename(event.image)
    if event.event_id in (1, 4688) or (event.image and not event.destination_ip and not event.target_filename):
        cmd = event.command_line or "None"
        return f"Process '{img_name}' executed with command line: {cmd}"

    if event.event_id == 3 or event.destination_ip:
        dst = event.destination_ip
        port = f":{event.destination_port}" if event.destination_port else ""
        proto = f" ({event.protocol})" if event.protocol else ""
        return f"Process '{img_name}' established outbound network connection to {dst}{port}{proto}."

    if event.event_id == 11 or event.target_filename:
        return f"Process '{img_name}' created file at '{event.target_filename}'."

    if event.event_id in (12, 13, 14) or event.registry_target_object:
        return f"Process '{img_name}' modified registry target '{event.registry_target_object}'."

    if event.event_id == 10 or event.granted_access:
        target = _get_basename(event.target_image) or "target process"
        mask = event.granted_access or "N/A"
        return f"Process '{img_name}' accessed memory of '{target}' with granted access {mask}."

    if event.event_id == 8:
        target = _get_basename(event.target_image) or "target process"
        return f"Process '{img_name}' created remote thread in '{target}'."

    if event.event_id == 4698:
        return f"Scheduled task created: {event.task_name or 'N/A'}."

    if event.event_id == 4697:
        return f"Service installed: {event.service_name or 'N/A'}."

    return stage_def.description


class AttackChainEngine:
    """Lineage-aware correlation engine evaluating sliding-window attack chains."""

    def __init__(
        self,
        chains: list[AttackChainDefinition] | None = None,
        window_minutes: int = 30,
        default_window_minutes: int = 30,
    ) -> None:
        """Initialize AttackChainEngine with configured chains and temporal window."""
        self.chains: list[AttackChainDefinition] = (
            chains if chains is not None else get_default_attack_chains()
        )
        self.default_window_minutes: int = max(window_minutes, default_window_minutes)

    def evaluate(
        self,
        events: list[NormalizedEvent],
        matches: list[DetectionMatch] | None = None,
        process_tree: ProcessTreeGraph | None = None,
        alerts: list[dict[str, Any]] | None = None,
    ) -> list[CompoundIncident]:
        """Evaluate events and alerts across active attack chains and return CompoundIncidents."""
        if not events:
            return []

        # Construct or use ProcessTreeGraph for lineage traversal
        ptree = process_tree if process_tree is not None else ProcessTreeGraph()
        if process_tree is None:
            ptree.build_from_events(events)

        # Partition telemetry strictly by computer (host)
        events_by_host: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for ev in events:
            host_key = (ev.computer or "UNKNOWN_HOST").strip().upper()
            events_by_host[host_key].append(ev)

        incidents: list[CompoundIncident] = []
        # Deduplication tracker: (chain_id, host_key, root_process_guid_or_event_key)
        seen_incidents: set[tuple[str, str, str]] = set()

        for host_key, host_events in events_by_host.items():
            # Sort chronologically by timestamp
            sorted_events = sorted(host_events, key=lambda e: e.timestamp)

            # Filter relevant matches/alerts for this host
            host_alerts = [
                a for a in (alerts or [])
                if str(a.get("computer", "")).strip().upper() == host_key
            ]
            host_matches = [
                m for m in (matches or [])
                if getattr(m, "computer", "").strip().upper() == host_key
            ]
            context: dict[str, Any] = {
                "alerts": host_alerts,
                "matches": host_matches,
                "computer": host_key,
            }

            for chain in self.chains:
                effective_window = timedelta(
                    minutes=chain.window_minutes or self.default_window_minutes
                )
                stages_count = len(chain.stages)
                if stages_count < 2:
                    continue

                stage1_def = chain.stages[0]

                # Evaluate candidate root events matching Stage 1
                for e1 in sorted_events:
                    if not stage1_def.matches_event(e1, context):
                        continue

                    root_guid = e1.process_guid
                    root_dedup_key = root_guid or f"EID_{e1.record_id or e1.event_hash}"
                    dedup_tuple = (chain.chain_id, host_key, root_dedup_key)
                    if dedup_tuple in seen_incidents:
                        continue

                    t_start = e1.timestamp
                    t_max = t_start + effective_window

                    # Compute allowed descendant GUIDs for lineage checking
                    allowed_guids: set[str] = set()
                    if root_guid:
                        allowed_guids.add(root_guid)
                        descendants = ptree.get_descendants_tree(root_guid)
                        for d in descendants:
                            allowed_guids.add(d.process_guid)

                    # Search for satisfying sequence of subsequent stages
                    matched_sequence = self._find_sequence(
                        chain=chain,
                        stage_index=1,
                        current_sequence=[e1],
                        sorted_events=sorted_events,
                        t_max=t_max,
                        allowed_guids=allowed_guids,
                        context=context,
                    )

                    if matched_sequence is not None and len(matched_sequence) == stages_count:
                        # Full attack chain satisfied!
                        seen_incidents.add(dedup_tuple)
                        incident = self._build_incident(
                            chain=chain,
                            matched_events=matched_sequence,
                            computer=e1.computer,
                            root_guid=root_guid,
                            context=context,
                        )
                        incidents.append(incident)

        return incidents

    def correlate(
        self,
        events: list[NormalizedEvent],
        alerts: list[dict[str, Any]] | None = None,
        process_tree: ProcessTreeGraph | None = None,
        matches: list[DetectionMatch] | None = None,
    ) -> list[CompoundIncident]:
        """Public alias for evaluate() matching SDD correlation interface."""
        return self.evaluate(
            events=events,
            matches=matches,
            process_tree=process_tree,
            alerts=alerts,
        )

    def _find_sequence(
        self,
        chain: AttackChainDefinition,
        stage_index: int,
        current_sequence: list[NormalizedEvent],
        sorted_events: list[NormalizedEvent],
        t_max: Any,
        allowed_guids: set[str],
        context: dict[str, Any],
    ) -> list[NormalizedEvent] | None:
        """Recursively find chronological events satisfying each stage in chain order."""
        if stage_index >= len(chain.stages):
            return current_sequence

        stage_def = chain.stages[stage_index]
        prev_event = current_sequence[-1]
        root_event = current_sequence[0]

        for cand in sorted_events:
            # Chronological progression: at or after previous stage
            if cand.timestamp < prev_event.timestamp:
                continue
            # Bounded by sliding temporal window from initial stage
            if cand.timestamp > t_max:
                break

            # Avoid using identical event record across distinct stages
            if cand in current_sequence:
                continue

            # User context scoping check
            if not _is_compatible_user(root_event.user, cand.user):
                continue

            # Process tree lineage check
            if stage_def.requires_lineage:
                cand_guid = cand.process_guid
                if not cand_guid or cand_guid not in allowed_guids:
                    # Fallback: check if parent_process_guid is in allowed_guids
                    if cand.parent_process_guid and cand.parent_process_guid in allowed_guids:
                        allowed_guids.add(cand_guid or "")
                    else:
                        continue

            # Evaluate stage predicate
            if stage_def.matches_event(cand, context):
                result = self._find_sequence(
                    chain=chain,
                    stage_index=stage_index + 1,
                    current_sequence=current_sequence + [cand],
                    sorted_events=sorted_events,
                    t_max=t_max,
                    allowed_guids=allowed_guids,
                    context=context,
                )
                if result is not None:
                    return result

        return None

    def _build_incident(
        self,
        chain: AttackChainDefinition,
        matched_events: list[NormalizedEvent],
        computer: str,
        root_guid: str | None,
        context: dict[str, Any],
    ) -> CompoundIncident:
        """Construct a validated, Critical CompoundIncident with chronological stages and narrative."""
        stages: list[IncidentStage] = []
        participating_event_ids: list[int] = []
        participating_alert_ids: list[int] = []

        host_alerts = context.get("alerts", [])
        host_matches = context.get("matches", [])

        for idx, (stage_def, ev) in enumerate(zip(chain.stages, matched_events), start=1):
            eid = ev.record_id or ev.event_id
            if eid not in participating_event_ids:
                participating_event_ids.append(eid)

            # Link relevant atomic alerts/matches
            stage_alert_ids: list[int] = []
            if ev.process_guid:
                for a in host_alerts:
                    if a.get("process_guid") == ev.process_guid:
                        aid = a.get("id")
                        if aid and aid not in stage_alert_ids:
                            stage_alert_ids.append(int(aid))
            for m in host_matches:
                if getattr(m, "process_guid", None) == ev.process_guid:
                    mid = getattr(m, "event_db_id", None) or getattr(m, "event_id", None)
                    if mid and mid not in stage_alert_ids:
                        stage_alert_ids.append(int(mid))

            for aid in stage_alert_ids:
                if aid not in participating_alert_ids:
                    participating_alert_ids.append(aid)

            stage_narrative = _build_stage_narrative(stage_def, ev)

            stages.append(
                IncidentStage(
                    stage_number=idx,
                    stage_name=stage_def.stage_name,
                    tactic=stage_def.tactic,
                    technique=stage_def.technique,
                    timestamp=ev.timestamp,
                    process_guid=ev.process_guid,
                    image=ev.image,
                    command_line=ev.command_line,
                    event_ids=[eid],
                    alert_ids=stage_alert_ids,
                    narrative=stage_narrative,
                )
            )

        t_first = matched_events[0].timestamp
        t_last = matched_events[-1].timestamp
        dur_s = max(0.0, (t_last - t_first).total_seconds())

        story = generate_incident_narrative(
            chain_name=chain.name,
            computer=computer,
            user=matched_events[0].user,
            stages=stages,
        )

        incident_id = f"INC-{chain.chain_id}-{uuid.uuid4().hex[:8].upper()}"

        return CompoundIncident(
            incident_id=incident_id,
            chain_id=chain.chain_id,
            chain_name=chain.name,
            severity="Critical",
            status="New",
            computer=computer,
            user=matched_events[0].user,
            root_process_guid=root_guid,
            first_seen=t_first,
            last_seen=t_last,
            duration_seconds=dur_s,
            stages=stages,
            mitre_tactics=list(chain.mitre_tactics),
            mitre_techniques=list(chain.mitre_techniques),
            participating_alert_ids=participating_alert_ids,
            participating_event_ids=participating_event_ids,
            summary_narrative=story,
            narrative_story=story,
            investigation_steps=list(chain.investigation_steps),
        )

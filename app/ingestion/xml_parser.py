"""Namespace-agnostic streaming XML parser for Windows event logs."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Generator

from app.ingestion.base import BaseParser, RawRecord
from app.models.stats import ImportStatistics
from app.utils.security import sanitize_input_path

logger = logging.getLogger(__name__)


def _strip_ns(tag: str) -> str:
    """Strip XML namespace URI from tag if present."""
    return tag.split("}")[-1] if "}" in tag else tag


def parse_event_xml(xml_string: str) -> tuple[dict[str, str], dict[str, str]]:
    """Parse an <Event> XML string namespace-agnostically.

    Extracts core System telemetry fields and EventData/UserData key-value pairs
    without external entity expansion.

    Args:
        xml_string: XML string of an individual <Event>.

    Returns:
        Tuple of (system_fields, data_fields) dictionaries.
    """
    root = ET.fromstring(xml_string)
    system_fields: dict[str, str] = {}
    data_fields: dict[str, str] = {}

    pos = 0
    for child in root:
        child_tag = _strip_ns(child.tag)

        if child_tag == "System":
            for item in child:
                item_tag = _strip_ns(item.tag)
                if item_tag == "Provider":
                    if "Name" in item.attrib:
                        system_fields["Provider"] = item.attrib["Name"]
                    if "Guid" in item.attrib:
                        system_fields["ProviderGuid"] = item.attrib["Guid"]
                elif item_tag == "TimeCreated":
                    if "SystemTime" in item.attrib:
                        system_fields["TimeCreated"] = item.attrib["SystemTime"]
                elif item_tag == "Execution":
                    if "ProcessID" in item.attrib:
                        system_fields["ProcessID"] = item.attrib["ProcessID"]
                    if "ThreadID" in item.attrib:
                        system_fields["ThreadID"] = item.attrib["ThreadID"]
                elif item_tag == "Security":
                    if "UserID" in item.attrib:
                        system_fields["UserID"] = item.attrib["UserID"]
                elif item_tag == "Correlation":
                    if "ActivityID" in item.attrib:
                        system_fields["ActivityID"] = item.attrib["ActivityID"]
                    if "RelatedActivityID" in item.attrib:
                        system_fields["RelatedActivityID"] = item.attrib["RelatedActivityID"]
                elif item_tag == "EventID":
                    system_fields["EventID"] = item.text.strip() if item.text else ""
                    if "Qualifiers" in item.attrib:
                        system_fields["Qualifiers"] = item.attrib["Qualifiers"]
                else:
                    system_fields[item_tag] = item.text.strip() if item.text else ""

        elif child_tag in ("EventData", "UserData"):
            for data_item in child:
                data_tag = _strip_ns(data_item.tag)
                if data_tag == "Data":
                    name = data_item.attrib.get("Name")
                    val = data_item.text or ""
                    if name:
                        data_fields[name] = val
                    else:
                        pos += 1
                        data_fields[f"param{pos}"] = val
                else:
                    data_fields[data_tag] = data_item.text or ""

    return system_fields, data_fields


class XMLParser(BaseParser):
    """Streaming parser for Windows XML event files."""

    def stream_records(
        self,
        file_path: Path,
        stats: ImportStatistics | None = None,
    ) -> Generator[RawRecord, None, None]:
        """Stream raw event records from an XML file.

        Uses xml.etree.ElementTree.iterparse with end events to stream
        <Event> elements without keeping the entire DOM in memory.

        Args:
            file_path: Path to the .xml file.
            stats: Optional ImportStatistics tracker.

        Yields:
            RawRecord instances extracted from the stream.
        """
        validated_path = sanitize_input_path(file_path, allowed_extensions=[".xml"])

        try:
            context = ET.iterparse(str(validated_path), events=("end",))
            for _, elem in context:
                if _strip_ns(elem.tag) == "Event":
                    record_id: int | None = None
                    for child in elem:
                        if _strip_ns(child.tag) == "System":
                            for sys_child in child:
                                if _strip_ns(sys_child.tag) == "EventRecordID":
                                    if sys_child.text and sys_child.text.strip().isdigit():
                                        record_id = int(sys_child.text.strip())
                                    break
                            break

                    raw_xml = ET.tostring(elem, encoding="unicode")

                    if stats is not None:
                        stats.total_events += 1

                    yield RawRecord(
                        record_id=record_id,
                        raw_payload=raw_xml,
                        format="xml",
                        metadata={},
                    )
                    elem.clear()

        except (ET.ParseError, UnicodeDecodeError, ValueError, Exception) as err:
            logger.warning("Error parsing XML log %s: %s", validated_path, err)
            if stats is not None:
                stats.record_malformed(str(err))
            yield RawRecord(
                record_id=None,
                raw_payload="<CorruptRecord/>",
                format="xml",
                metadata={"error": str(err), "is_corrupt": True},
            )

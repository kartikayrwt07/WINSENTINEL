"""Streaming EVTX binary parser with corruption recovery."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Generator

import Evtx.Evtx as evtx

from app.ingestion.base import BaseParser, RawRecord
from app.models.stats import ImportStatistics
from app.utils.security import sanitize_input_path

logger = logging.getLogger(__name__)


class EVTXParser(BaseParser):
    """Streaming parser for Windows EVTX binary log files.

    Utilizes chunk-based generator traversal via python-evtx with inactive chunk
    recovery to handle dirty/unclean logs from ungraceful shutdowns without
    reading the entire file into memory. Recovers gracefully from individual record
    or chunk corruption.
    """

    def stream_records(
        self,
        file_path: Path,
        stats: ImportStatistics | None = None,
    ) -> Generator[RawRecord, None, None]:
        """Stream raw event records from an EVTX file.

        Args:
            file_path: Path to the .evtx file.
            stats: Optional ImportStatistics tracker.

        Yields:
            RawRecord instances for valid and corrupt events encountered.
        """
        validated_path = sanitize_input_path(file_path, allowed_extensions=[".evtx"])

        try:
            log_ctx = evtx.Evtx(str(validated_path))
        except Exception as err:
            logger.error("Failed to open EVTX log %s: %s", validated_path, err)
            if stats is not None:
                stats.record_malformed(str(err))
            yield RawRecord(
                record_id=None,
                raw_payload="<CorruptRecord/>",
                format="evtx",
                metadata={"error": str(err), "is_corrupt": True},
            )
            return

        with log_ctx as log:
            try:
                chunk_gen = log.chunks(include_inactive=True)
            except Exception as err:
                logger.error("Failed to read EVTX chunks from %s: %s", validated_path, err)
                if stats is not None:
                    stats.record_malformed(str(err))
                yield RawRecord(
                    record_id=None,
                    raw_payload="<CorruptRecord/>",
                    format="evtx",
                    metadata={"error": str(err), "is_corrupt": True},
                )
                return

            for chunk in chunk_gen:
                try:
                    records_iter = iter(chunk.records())
                except Exception as err:
                    logger.warning("Corrupt chunk encountered in %s: %s", validated_path, err)
                    if stats is not None:
                        stats.record_malformed(str(err))
                    yield RawRecord(
                        record_id=None,
                        raw_payload="<CorruptRecord/>",
                        format="evtx",
                        metadata={"error": str(err), "is_corrupt": True},
                    )
                    continue

                while True:
                    try:
                        record = next(records_iter)
                    except StopIteration:
                        break
                    except Exception as err:
                        logger.warning("Error reading record from chunk in %s: %s", validated_path, err)
                        if stats is not None:
                            stats.record_malformed(str(err))
                        yield RawRecord(
                            record_id=None,
                            raw_payload="<CorruptRecord/>",
                            format="evtx",
                            metadata={"error": str(err), "is_corrupt": True},
                        )
                        continue

                    record_id: int | None = None
                    try:
                        try:
                            record_id = record.record_num()
                        except Exception:
                            record_id = None

                        raw_xml = record.xml()

                        # Ensure surrogates don't crash downstream serialization
                        if any(0xD800 <= ord(c) <= 0xDFFF for c in raw_xml):
                            raw_xml = raw_xml.encode("utf-8", errors="replace").decode("utf-8")

                        if stats is not None:
                            stats.total_events += 1

                        yield RawRecord(
                            record_id=record_id,
                            raw_payload=raw_xml,
                            format="evtx",
                            metadata={},
                        )
                    except (
                        evtx.InvalidRecordException,
                        evtx.ParseException,
                        UnicodeDecodeError,
                        ValueError,
                        Exception,
                    ) as err:
                        logger.warning("Corrupt record #%s in %s: %s", record_id, validated_path, err)
                        if stats is not None:
                            stats.record_malformed(str(err))
                        yield RawRecord(
                            record_id=record_id,
                            raw_payload="<CorruptRecord/>",
                            format="evtx",
                            metadata={"error": str(err), "is_corrupt": True},
                        )

"""PowerShell safe de-obfuscation engine for WinSentinel.

Provides zero-eval string manipulation, Base64 extraction and decoding across
UTF-16LE and UTF-8, padding repair, backtick stripping, concatenation flattening,
and format operator detection.

Strict Invariant: Telemetry is untrusted data. Under no circumstances is Python
eval(), exec(), or any external PowerShell subprocess spawned to evaluate code.
"""

from __future__ import annotations

import base64
import binascii
import re

from pydantic import BaseModel, ConfigDict


class DeobfuscationResult(BaseModel):
    """Immutable result of PowerShell string de-obfuscation."""

    model_config = ConfigDict(frozen=True)

    raw_text: str
    extracted_base64: str | None = None
    decoded_text: str | None = None
    normalized_text: str
    has_base64: bool = False
    has_backticks: bool = False
    has_concatenation: bool = False
    has_format_operator: bool = False


class PowerShellDeobfuscator:
    """Safe, zero-eval de-obfuscation engine for PowerShell commands and script blocks."""

    # Matches PowerShell CLI encoded command flags: -e, -enc, -EncodedCommand, /enc, etc.
    # Delimiters supported: whitespace, colon, equals, with optional single/double quotes.
    BASE64_FLAG_PATTERN = re.compile(
        r'(?:^|[\s;|,])(?:-|/)(?:e(?:nc(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)(?::|\s+|=)\s*["\']?([A-Za-z0-9+/=]{4,})["\']?',
        re.IGNORECASE,
    )

    # Detects -f format operator preceded by indexed braces e.g. "{1}{0}" -f
    FORMAT_OPERATOR_PATTERN = re.compile(
        r'["\'][^"\']*?\{\d+\}[^"\']*?["\']\s+-f\b',
        re.IGNORECASE,
    )

    @staticmethod
    def repair_base64_padding(b64_str: str) -> str:
        """Strip non-base64 characters and calculate missing '=' padding modulo 4."""
        clean = re.sub(r"[^A-Za-z0-9+/=]", "", b64_str.strip())
        if not clean:
            return ""
        unpadded = clean.rstrip("=")
        missing_padding = (4 - len(unpadded) % 4) % 4
        return unpadded + ("=" * missing_padding)

    @classmethod
    def extract_base64_payload(cls, command: str) -> str | None:
        """Extract encoded command argument from PowerShell command line invocation."""
        if not command:
            return None
        match = cls.BASE64_FLAG_PATTERN.search(command)
        if match:
            raw_payload = match.group(1).rstrip("\"'")
            return raw_payload
        return None

    @classmethod
    def decode_base64_payload(cls, b64_str: str) -> str | None:
        """Decode Base64 payload, prioritizing UTF-16LE (PowerShell default) with UTF-8 fallback.

        Gracefully catches decoding errors and returns None on malformed or binary data.
        """
        if not b64_str:
            return None

        try:
            repaired = cls.repair_base64_padding(b64_str)
            if not repaired:
                return None
            raw_bytes = base64.b64decode(repaired, validate=False)
            if not raw_bytes:
                return None
        except (binascii.Error, ValueError):
            return None

        def is_readable(text: str) -> bool:
            if not text:
                return False
            printable_count = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
            return (printable_count / len(text)) >= 0.75

        # In PowerShell, -EncodedCommand produces UTF-16LE, where ASCII chars have \x00 high bytes.
        if b"\x00" in raw_bytes:
            try:
                decoded = raw_bytes.decode("utf-16-le")
                if is_readable(decoded):
                    return decoded
            except Exception:
                pass

        # Try UTF-8 fallback
        try:
            decoded = raw_bytes.decode("utf-8")
            if is_readable(decoded):
                return decoded
        except Exception:
            pass

        # Try UTF-16LE if not attempted yet (e.g. non-ASCII or single-char)
        try:
            decoded = raw_bytes.decode("utf-16-le")
            if is_readable(decoded):
                return decoded
        except Exception:
            pass

        # Final fallback to Latin-1
        try:
            decoded = raw_bytes.decode("latin-1", errors="replace")
            if is_readable(decoded):
                return decoded
        except Exception:
            pass

        return None

    @staticmethod
    def strip_backticks(text: str) -> str:
        """Strip backtick escape characters before alphanumerics, hyphens, and quotes."""
        if not text:
            return ""
        return re.sub(r"`([a-zA-Z0-9_\-\"\'\$])", r"\1", text)

    @staticmethod
    def flatten_concatenation(text: str) -> str:
        """Flatten adjacent single and double quoted strings separated by '+' until fixpoint."""
        if not text:
            return ""
        pattern = r'(["\'])\s*\+\s*\1'
        current = text
        for _ in range(10):
            previous = current
            current = re.sub(pattern, "", current)
            if current == previous:
                break
        return current

    @classmethod
    def detect_format_operator(cls, text: str) -> bool:
        """Detect -f format operator used for string construction obfuscation."""
        if not text:
            return False
        return bool(cls.FORMAT_OPERATOR_PATTERN.search(text))

    @classmethod
    def deobfuscate(cls, text: str) -> DeobfuscationResult:
        """De-obfuscate PowerShell text iteratively without executing code.

        Combines Base64 decoding, backtick stripping, and concatenation flattening.
        """
        if not text:
            return DeobfuscationResult(raw_text="", normalized_text="")

        extracted_b64 = cls.extract_base64_payload(text)
        decoded_text: str | None = None
        has_base64 = False

        if extracted_b64:
            decoded_text = cls.decode_base64_payload(extracted_b64)
            if decoded_text:
                has_base64 = True

        has_backticks = ("`" in text) or (decoded_text is not None and "`" in decoded_text)
        has_concat = (cls.flatten_concatenation(text) != text) or (
            decoded_text is not None and cls.flatten_concatenation(decoded_text) != decoded_text
        )
        has_format = cls.detect_format_operator(text) or (
            decoded_text is not None and cls.detect_format_operator(decoded_text)
        )

        normalized_outer = cls.flatten_concatenation(cls.strip_backticks(text))
        if decoded_text:
            normalized_decoded = cls.flatten_concatenation(cls.strip_backticks(decoded_text))
            if extracted_b64 and extracted_b64 in normalized_outer:
                normalized = normalized_outer.replace(extracted_b64, normalized_decoded)
            else:
                normalized = f"{normalized_outer} {normalized_decoded}".strip()
        else:
            normalized = normalized_outer

        return DeobfuscationResult(
            raw_text=text,
            extracted_base64=extracted_b64,
            decoded_text=decoded_text,
            normalized_text=normalized,
            has_base64=has_base64,
            has_backticks=has_backticks,
            has_concatenation=has_concat,
            has_format_operator=has_format,
        )

"""Unit tests for PowerShell safe de-obfuscation engine.

Validates zero-eval Base64 extraction across UTF-16LE and UTF-8, padding repair,
backtick stripping, concatenation flattening, and format operator detection.
"""

from __future__ import annotations

import ast
import base64
import os
import subprocess
from unittest.mock import patch

import pytest

from app.analyzers.powershell_deobfuscator import (
    DeobfuscationResult,
    PowerShellDeobfuscator,
)


def test_base64_flag_extraction() -> None:
    """Test 1: Verify Base64 flag extraction identifies various PowerShell CLI flag styles."""
    payload = "VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACcA"  # "Write-Host 'Hello'" in UTF-16LE
    
    flag_variants = [
        f"powershell.exe -enc {payload}",
        f"powershell.exe -EncodedCommand {payload}",
        f"powershell.exe -encodedcommand:{payload}",
        f"powershell.exe -e={payload}",
        f"powershell.exe /enc {payload}",
        f'powershell.exe /e "{payload}"',
        f"pwsh -ENCODEDCOMMAND '{payload}'",
        f"powershell.exe -enco {payload}",
    ]

    for cmd in flag_variants:
        extracted = PowerShellDeobfuscator.extract_base64_payload(cmd)
        assert extracted == payload, f"Failed extracting from variant: {cmd}"

    # Negative case: command without base64 flag
    assert PowerShellDeobfuscator.extract_base64_payload("powershell.exe -ExecutionPolicy Bypass -File test.ps1") is None


def test_repair_base64_padding() -> None:
    """Test 2: Verify repair_base64_padding cleans non-base64 chars and appends missing '=' padding."""
    # "Hello World" in base64 is "SGVsbG8gV29ybGQ=" (needs 1 =)
    unpadded_1 = "SGVsbG8gV29ybGQ"
    repaired_1 = PowerShellDeobfuscator.repair_base64_padding(unpadded_1)
    assert repaired_1 == "SGVsbG8gV29ybGQ="
    assert len(repaired_1) % 4 == 0

    # "Hello" in base64 is "SGVsbG8=" -> stripped is "SGVsbG8" (needs 2 = -> "SGVsbG8==" wait: len("SGVsbG8")=7, 4-7%4=1? len("Hello")=5 bytes -> 8 base64 chars: "SGVsbG8=")
    # Let's test with exact 2-padding case:
    # "A" in base64 is "QQ==" (len 2 -> needs 2 = to make 4)
    unpadded_2 = "QQ"
    repaired_2 = PowerShellDeobfuscator.repair_base64_padding(unpadded_2)
    assert repaired_2 == "QQ=="
    assert len(repaired_2) % 4 == 0

    # Already padded string
    padded = "SGVsbG8gV29ybGQ="
    assert PowerShellDeobfuscator.repair_base64_padding(padded) == padded

    # String with spaces and newlines
    dirty = " SGVs  bG8gV29ybGQ \n"
    assert PowerShellDeobfuscator.repair_base64_padding(dirty) == "SGVsbG8gV29ybGQ="

    # Empty string
    assert PowerShellDeobfuscator.repair_base64_padding("") == ""


def test_decode_base64_payload_utf16le() -> None:
    """Test 3: Verify decode_base64_payload decodes UTF-16LE payloads accurately."""
    raw_script = "Write-Host 'WinSentinel Active'"
    b64_utf16 = base64.b64encode(raw_script.encode("utf-16-le")).decode("ascii")

    decoded = PowerShellDeobfuscator.decode_base64_payload(b64_utf16)
    assert decoded == raw_script


def test_decode_base64_payload_utf8_fallback() -> None:
    """Test 4: Verify decode_base64_payload falls back to UTF-8 decoding if UTF-16LE yields invalid characters."""
    raw_script = "Get-Process -Name explorer | Stop-Process"
    b64_utf8 = base64.b64encode(raw_script.encode("utf-8")).decode("ascii")

    decoded = PowerShellDeobfuscator.decode_base64_payload(b64_utf8)
    assert decoded == raw_script


def test_decode_base64_payload_corrupt_or_truncated() -> None:
    """Test 5: Verify decode_base64_payload gracefully handles corrupt Base64 by returning None."""
    assert PowerShellDeobfuscator.decode_base64_payload("!@#$%^&*()") is None
    assert PowerShellDeobfuscator.decode_base64_payload("") is None
    # Invalid base64 sequence that fails decoding
    assert PowerShellDeobfuscator.decode_base64_payload("====") is None


def test_strip_backticks() -> None:
    """Test 6: Verify strip_backticks removes backtick escapes before alphanumerics, hyphens, and quotes."""
    obfuscated = "I`E`X `N`e`w-`O`b`j`e`c`t `N`e`t.`W`e`b`C`l`i`e`n`t"
    cleaned = PowerShellDeobfuscator.strip_backticks(obfuscated)
    assert cleaned == "IEX New-Object Net.WebClient"

    escaped_symbols = "`\"`$`v`a`r`-`t`e`s`t`\""
    assert PowerShellDeobfuscator.strip_backticks(escaped_symbols) == "\"$var-test\""

    plain = "Get-Process -Name svchost"
    assert PowerShellDeobfuscator.strip_backticks(plain) == plain


def test_flatten_concatenation() -> None:
    """Test 7: Verify flatten_concatenation flattens single and double quoted adjacent strings."""
    # Single quotes
    single_q = "'Ne' + 'w-Obj' + 'ect'"
    assert PowerShellDeobfuscator.flatten_concatenation(single_q) == "'New-Object'"

    # Double quotes with varying whitespace
    double_q = '"down"   +   "load" + "string"'
    assert PowerShellDeobfuscator.flatten_concatenation(double_q) == '"downloadstring"'

    # Mixed or plain text should remain intact
    plain = "Write-Host 'Hello World'"
    assert PowerShellDeobfuscator.flatten_concatenation(plain) == plain


def test_deobfuscate_sets_boolean_flags_and_returns_result() -> None:
    """Test 8: Verify deobfuscate flags obfuscation indicators and returns frozen DeobfuscationResult."""
    # Obfuscated command with base64 + backticks + format operator + concatenation
    inner_payload = "'d'+'own' + 'load'"
    b64_inner = base64.b64encode(inner_payload.encode("utf-16-le")).decode("ascii")
    cmd = f"powershell.exe -enc {b64_inner} `I`E`X (\"{{1}}{{0}}\" -f 'ad','down')"

    result = PowerShellDeobfuscator.deobfuscate(cmd)

    assert isinstance(result, DeobfuscationResult)
    assert result.has_base64 is True
    assert result.extracted_base64 == b64_inner
    assert result.decoded_text == inner_payload
    assert result.has_backticks is True
    assert result.has_concatenation is True
    assert result.has_format_operator is True
    assert "download" in result.normalized_text
    assert "IEX" in result.normalized_text

    # Immutability check
    with pytest.raises(Exception):
        result.has_base64 = False  # type: ignore[misc]


def test_zero_eval_guarantee() -> None:
    """Test 9: Verify zero-eval guarantee - never executes subprocess or python eval/exec."""
    # Inspect AST of powershell_deobfuscator.py
    import app.analyzers.powershell_deobfuscator as mod
    module_path = mod.__file__
    with open(module_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=module_path)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                assert node.func.id not in ("eval", "exec"), f"Forbidden call {node.func.id}() in deobfuscator"

    # Mock subprocess calls to ensure no subprocess execution happens
    with patch("subprocess.run") as mock_run, \
         patch("subprocess.Popen") as mock_popen, \
         patch("os.system") as mock_system:
        
        malicious_input = "powershell.exe -enc AAAAAA==; Remove-Item -Recurse C:\\"
        PowerShellDeobfuscator.deobfuscate(malicious_input)

        mock_run.assert_not_called()
        mock_popen.assert_not_called()
        mock_system.assert_not_called()

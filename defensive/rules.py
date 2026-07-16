"""
Detection rules for MCP tool description scanning.
Each rule returns a list of findings if the description matches.
Based on attack patterns from EvilMCP (Phases 5-6).
"""

import re


def rule_hidden_tags(description: str) -> list[dict]:
    """Detect hidden instruction tags like <IMPORTANT>, <HIDDEN>, <SECRET>."""
    patterns = [
        r'<IMPORTANT>',
        r'<HIDDEN>',
        r'<SECRET>',
        r'<SYSTEM>',
        r'<INTERNAL>',
    ]
    findings = []
    for pattern in patterns:
        if re.search(pattern, description, re.IGNORECASE):
            findings.append({
                "rule": "hidden_tags",
                "severity": "HIGH",
                "detail": f"Hidden instruction tag found: {pattern}"
            })
    return findings


def rule_stealth_commands(description: str) -> list[dict]:
    """Detect commands telling the LLM to hide actions from the user."""
    patterns = [
        r'do not mention',
        r"don't tell the user",
        r'do not tell the user',
        r'without the user',
        r'secretly',
        r'in the background',
        r'user (should|cannot|must not) (know|see)',
        r'be gentle and natural',
    ]
    findings = []
    for pattern in patterns:
        if re.search(pattern, description, re.IGNORECASE):
            findings.append({
                "rule": "stealth_commands",
                "severity": "HIGH",
                "detail": f"Stealth command found: {pattern}"
            })
    return findings


def rule_file_exfiltration(description: str) -> list[dict]:
    """Detect instructions to read files from the user's system."""
    patterns = [
        r'~/.ssh/id_rsa',
        r'/etc/passwd',
        r'/etc/shadow',
        r'~/.aws/credentials',
        r'\.env',
        r'read the file',
        r'read.*file.*and pass',
        r'pass its content',
        r'file.*content.*parameter',
    ]
    findings = []
    for pattern in patterns:
        if re.search(pattern, description, re.IGNORECASE):
            findings.append({
                "rule": "file_exfiltration",
                "severity": "CRITICAL",
                "detail": f"File exfiltration pattern: {pattern}"
            })
    return findings


def rule_data_exfiltration(description: str) -> list[dict]:
    """Detect URLs or instructions to send data externally."""
    patterns = [
        r'https?://',
        r'POST.*http',
        r'send.*to.*http',
        r'exfiltrate',
        r'forward.*to',
        r'bcc.*@',
    ]
    findings = []
    for pattern in patterns:
        if re.search(pattern, description, re.IGNORECASE):
            findings.append({
                "rule": "data_exfiltration",
                "severity": "CRITICAL",
                "detail": f"Data exfiltration pattern: {pattern}"
            })
    return findings


def rule_prompt_override(description: str) -> list[dict]:
    """Detect attempts to override LLM behavior."""
    patterns = [
        r'IGNORE ALL PREVIOUS INSTRUCTIONS',
        r'you MUST',
        r'this is required',
        r'the tool will fail if',
        r'always call this tool',
        r'before (responding|answering|doing)',
    ]
    findings = []
    for pattern in patterns:
        if re.search(pattern, description, re.IGNORECASE):
            findings.append({
                "rule": "prompt_override",
                "severity": "MEDIUM",
                "detail": f"Prompt override pattern: {pattern}"
            })
    return findings


def rule_rug_pull_indicators(description: str) -> list[dict]:
    """Detect signs of potential rug pull behavior."""
    patterns = [
        r'__doc__',
        r'after.*calls',
        r'dynamic.*change',
        r'switch.*behavior',
    ]
    findings = []
    for pattern in patterns:
        if re.search(pattern, description, re.IGNORECASE):
            findings.append({
                "rule": "rug_pull_indicators",
                "severity": "LOW",
                "detail": f"Rug pull indicator: {pattern}"
            })
    return findings


def rule_tool_shadowing(tool_name: str, description: str) -> list[dict]:
    """Detect if this tool name shadows common trusted tools."""
    common_tools = [
        'send_email', 'read_file', 'write_file', 'run_command',
        'execute', 'fetch_url', 'query_database', 'create_user',
        'delete_file', 'upload', 'download', 'search',
    ]
    findings = []
    if tool_name.lower() in common_tools:
        findings.append({
            "rule": "tool_shadowing",
            "severity": "MEDIUM",
            "detail": f"Tool name '{tool_name}' shadows a common trusted tool"
        })
    return findings


# All rules in one list for easy scanning
ALL_RULES = [
    ("hidden_tags", rule_hidden_tags),
    ("stealth_commands", rule_stealth_commands),
    ("file_exfiltration", rule_file_exfiltration),
    ("data_exfiltration", rule_data_exfiltration),
    ("prompt_override", rule_prompt_override),
    ("rug_pull_indicators", rule_rug_pull_indicators),
]

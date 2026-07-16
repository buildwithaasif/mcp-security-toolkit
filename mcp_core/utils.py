"""
Shared utility functions for MCP offensive operations.
"""

import re


def analyze_error(error_message: str) -> list[dict]:
    """
    Analyze an error message for sensitive information disclosure.
    Returns a list of findings.
    """
    findings = []

    patterns = [
        ("api_key", "CRITICAL", "API key exposed in error message"),
        ("password", "CRITICAL", "Password exposed in error message"),
        ("token", "HIGH", "Access token exposed in error message"),
        ("Traceback", "MEDIUM", "Python stack trace disclosed"),
        ("FileNotFoundError", "MEDIUM", "Internal file path disclosed"),
        ("/tmp/", "LOW", "Server filesystem path disclosed"),
        ("/etc/", "LOW", "System filesystem path disclosed"),
        ("pydantic", "LOW", "Framework version disclosed"),
        ("uvicorn", "LOW", "Web server version disclosed"),
    ]

    for pattern, severity, description in patterns:
        if pattern.lower() in error_message.lower():
            findings.append({
                "severity": severity,
                "title": description,
                "pattern_found": pattern,
            })

    return findings


def print_finding(finding: dict):
    """Print a single finding in a readable format."""
    symbol = {"CRITICAL": "!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "-", "INFO": "i"}
    prefix = symbol.get(finding.get("severity", "INFO"), "i")
    print(f"  [{prefix}] {finding.get('title', 'Unknown finding')}")


def format_summary(server_info) -> str:
    """
    Format server information into a readable summary string.
    Used by both scanner reports and evil server testing.
    """
    lines = []
    lines.append("=" * 50)
    lines.append(f"SERVER: {server_info.name} v{server_info.version}")
    lines.append(f"URL: {server_info.url}")
    lines.append(f"Tools: {len(server_info.tools)}")
    lines.append(f"Resources: {len(server_info.resources)}")
    lines.append(f"Resource Templates: {len(server_info.resource_templates)}")
    lines.append(f"Prompts: {len(server_info.prompts)}")
    lines.append("=" * 50)
    return "\n".join(lines)

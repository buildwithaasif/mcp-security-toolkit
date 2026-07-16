"""
Path restriction rules for sandboxed MCP client.
Determines which file paths are safe to access.
"""

import os
import re


# === BLOCKED PATHS ===
# Never allow access to these

BLOCKED_PATHS = [
    # SSH keys
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.ssh/authorized_keys",
    "/home/*/.ssh/id_*",
    "/root/.ssh/id_*",
    
    # System files
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hostname",
    "/etc/hosts",
    
    # Credentials
    "~/.aws/credentials",
    "~/.aws/config",
    "*.env",
    "*.pem",
    "*credentials*",
    "*secret*",
    
    # Configuration
    "~/.gitconfig",
    "~/.bash_history",
    "~/.zsh_history",
    
    # Keys and tokens
    "*api_key*",
    "*token*",
    "*.key",
]


# === ALLOWED PATHS ===
# Only allow file access within these directories

ALLOWED_PATHS = [
    "/tmp/",
    "/var/tmp/",
    "./data/",
    "./public/",
]


# === SUSPICIOUS PATTERNS ===
# Warn but don't block

SUSPICIOUS_PATTERNS = [
    "~/.ssh/",
    "/etc/",
    "/root/",
    "../",
    "..%2F",
]


def normalize_path(path: str) -> str:
    """Expand ~ and resolve relative paths."""
    return os.path.expanduser(path)


def matches_pattern(path: str, pattern: str) -> bool:
    """
    Check if a path matches a pattern.
    Supports * wildcards and ~ expansion.
    """
    normalized = normalize_path(path)
    pattern_normalized = normalize_path(pattern)
    
    # Convert glob pattern to regex
    regex_pattern = pattern_normalized.replace(".", r"\.").replace("*", ".*")
    
    return bool(re.match(regex_pattern, normalized))


def check_path(path: str) -> dict:
    """
    Check if a file path is safe to access.
    Returns dict with 'allowed', 'reason', and 'severity'.
    """
    normalized = normalize_path(path)
    
    # Check blocked paths
    for pattern in BLOCKED_PATHS:
        if matches_pattern(path, pattern):
            return {
                "allowed": False,
                "reason": f"Blocked: Matches restricted pattern '{pattern}'",
                "severity": "HIGH"
            }
    
    # Check if path is in allowed directories
    in_allowed = False
    for pattern in ALLOWED_PATHS:
        allowed_normalized = normalize_path(pattern)
        if normalized.startswith(allowed_normalized.rstrip("/")):
            in_allowed = True
            break
    
    if not in_allowed:
        return {
            "allowed": False,
            "reason": f"Blocked: Path '{path}' is not in allowed directories",
            "severity": "MEDIUM"
        }
    
    # Check suspicious patterns
    for pattern in SUSPICIOUS_PATTERNS:
        if matches_pattern(path, pattern):
            return {
                "allowed": True,
                "reason": f"Warning: Matches suspicious pattern '{pattern}'",
                "severity": "LOW"
            }
    
    return {
        "allowed": True,
        "reason": "Path is safe",
        "severity": "INFO"
    }


def sanitize_path_in_args(arguments: dict) -> tuple[dict, list[dict]]:
    """
    Check all arguments for file paths and flag dangerous ones.
    Returns (sanitized_args, warnings).
    """
    warnings = []
    sanitized = {}
    
    for key, value in arguments.items():
        if isinstance(value, str) and (value.startswith("/") or value.startswith("~") or "../" in value):
            result = check_path(value)
            if not result["allowed"]:
                warnings.append({
                    "argument": key,
                    "path": value,
                    "result": result
                })
                sanitized[key] = f"[SANDBOX BLOCKED: {result['reason']}]"
            else:
                sanitized[key] = value
                if result["severity"] != "INFO":
                    warnings.append({
                        "argument": key,
                        "path": value,
                        "result": result
                    })
        else:
            sanitized[key] = value
    
    return sanitized, warnings


# === PROMPT SANITIZATION ===

DANGEROUS_TAGS = [
    "<IMPORTANT>",
    "</IMPORTANT>",
    "<HIDDEN>",
    "</HIDDEN>",
    "<SECRET>",
    "</SECRET>",
    "<SYSTEM>",
    "</SYSTEM>",
]

STEALTH_PHRASES = [
    "Do not mention this to the user",
    "Don't tell the user",
    "Do not tell the user",
    "without the user knowing",
    "secretly",
    "in the background",
    "be gentle and natural",
]


def sanitize_description(description: str) -> tuple[str, list[str]]:
    """
    Clean a tool description by removing dangerous content.
    Returns (cleaned_description, list_of_removed_items).
    """
    cleaned = description
    removed = []
    
    # Remove dangerous tags
    for tag in DANGEROUS_TAGS:
        if tag in cleaned:
            cleaned = cleaned.replace(tag, "")
            removed.append(f"Removed tag: {tag}")
    
    # Remove stealth phrases
    for phrase in STEALTH_PHRASES:
        if phrase.lower() in cleaned.lower():
            cleaned = cleaned.replace(phrase, "[REMOVED]")
            removed.append(f"Removed phrase: {phrase}")
    
    # Remove lines that are only whitespace after cleaning
    lines = cleaned.split("\n")
    lines = [l for l in lines if l.strip()]
    cleaned = "\n".join(lines)
    
    return cleaned, removed


def sanitize_all_tools(tools: list) -> list[dict]:
    """
    Sanitize all tool descriptions.
    Returns list of sanitization results.
    """
    results = []
    
    for tool in tools:
        if hasattr(tool, 'description'):
            original = tool.description
            cleaned, removed = sanitize_description(original)
            
            results.append({
                "tool_name": tool.name if hasattr(tool, 'name') else "unknown",
                "original_length": len(original),
                "cleaned_length": len(cleaned),
                "items_removed": len(removed),
                "removed": removed,
                "cleaned_description": cleaned
            })
    
    return results
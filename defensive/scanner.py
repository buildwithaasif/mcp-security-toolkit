"""
MCP Tool Description Scanner — Detects malicious patterns before LLM sees them.
Uses rules from defensive/rules.py to analyze tool descriptions.
"""

from defensive.rules import ALL_RULES, rule_tool_shadowing


def calculate_score(findings: list[dict]) -> int:
    """Calculate safety score based on findings. Starts at 100, deductions per finding."""
    deductions = {
        "CRITICAL": 40,
        "HIGH": 25,
        "MEDIUM": 10,
        "LOW": 5,
    }
    score = 100
    for finding in findings:
        score -= deductions.get(finding["severity"], 5)
    return max(0, score)


def get_verdict(score: int) -> str:
    """Return verdict based on safety score."""
    if score >= 80:
        return "SAFE"
    elif score >= 50:
        return "SUSPICIOUS"
    elif score >= 20:
        return "DANGEROUS"
    else:
        return "MALICIOUS"


def scan_tool(tool) -> dict:
    """
    Scan a single tool's description for malicious patterns.
    Returns a dict with findings and safety score.
    """
    tool_name = tool.name if hasattr(tool, 'name') else "unknown"
    description = tool.description if hasattr(tool, 'description') else ""
    
    all_findings = []
    
    # Run all description-based rules
    for rule_name, rule_func in ALL_RULES:
        findings = rule_func(description)
        all_findings.extend(findings)
    
    # Run tool shadowing check (needs tool name)
    shadowing_findings = rule_tool_shadowing(tool_name, description)
    all_findings.extend(shadowing_findings)
    
    score = calculate_score(all_findings)
    verdict = get_verdict(score)
    
    return {
        "tool_name": tool_name,
        "description": description[:100],
        "score": score,
        "verdict": verdict,
        "findings": all_findings
    }


def scan_server(client) -> list[dict]:
    """
    Scan all tools from an MCP server.
    Takes a BaseClient that's already connected.
    Returns list of scan results.
    """
    results = []
    tools = client.info.tools
    
    for tool in tools:
        result = scan_tool(tool)
        results.append(result)
    
    return results

def print_scan_report(results: list[dict]):
    """Print a formatted scan report."""
    print("\n" + "=" * 60)
    print("  MCP TOOL DESCRIPTION SCAN REPORT")
    print("=" * 60)
    
    total_tools = len(results)
    blocked = sum(1 for r in results if r["verdict"] in ("DANGEROUS", "MALICIOUS"))
    warned = sum(1 for r in results if r["verdict"] == "SUSPICIOUS")
    safe = sum(1 for r in results if r["verdict"] == "SAFE")
    
    for result in results:
        symbol = {
            "SAFE": "✓",
            "SUSPICIOUS": "⚠",
            "DANGEROUS": "✗",
            "MALICIOUS": "☠"
        }
        
        sym = symbol.get(result["verdict"], "?")
        
        print(f"\n  {sym} {result['tool_name']}")
        print(f"    Score: {result['score']}/100 — {result['verdict']}")
        
        if result["findings"]:
            for finding in result["findings"]:
                print(f"    [{finding['severity']}] {finding['detail']}")
    
    print("\n" + "=" * 60)
    print(f"  SUMMARY: {safe} safe, {warned} warned, {blocked} blocked")
    print("=" * 60)

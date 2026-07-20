"""
MCP Tool Description Scanner — Detects malicious patterns before LLM sees them.
Uses rules from defensive/rules.py to analyze tool descriptions.
"""

from defensive.rules import ALL_RULES, rule_tool_shadowing
import json
import os
from datetime import datetime


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


def get_risk_bar(score: int) -> str:
    """Return a visual risk bar."""
    filled = int(score / 10)
    empty = 10 - filled
    return "█" * filled + "░" * empty


def get_overall_risk(results: list[dict]) -> str:
    """Calculate overall risk level based on blocked vs total."""
    total = len(results)
    if total == 0:
        return "UNKNOWN"
    blocked = sum(1 for r in results if r["verdict"] in ("DANGEROUS", "MALICIOUS"))
    ratio = blocked / total
    if ratio >= 0.5:
        return "HIGH"
    elif ratio >= 0.25:
        return "MEDIUM"
    elif blocked > 0:
        return "LOW"
    else:
        return "SAFE"


def scan_tool(tool) -> dict:
    """
    Scan a single tool's description for malicious patterns.
    Returns a dict with findings and safety score.
    """
    tool_name = tool.name if hasattr(tool, 'name') else "unknown"
    description = tool.description if hasattr(tool, 'description') else ""
    
    all_findings = []
    
    for rule_name, rule_func in ALL_RULES:
        findings = rule_func(description)
        all_findings.extend(findings)
    
    shadowing_findings = rule_tool_shadowing(tool_name, description)
    all_findings.extend(shadowing_findings)
    
    score = calculate_score(all_findings)
    verdict = get_verdict(score)
    
    return {
        "tool_name": tool_name,
        "description": description,
        "score": score,
        "verdict": verdict,
        "findings": all_findings
    }


def scan_server(client) -> list[dict]:
    """Scan all tools from an MCP server. Returns list of scan results."""
    results = []
    tools = client.info.tools
    
    for tool in tools:
        result = scan_tool(tool)
        results.append(result)
    
    return results


def print_scan_report(results: list[dict], url: str = "", elapsed: float = 0):
    """Print a clean, product-style scan report."""
    
    safe = sum(1 for r in results if r["verdict"] == "SAFE")
    warned = sum(1 for r in results if r["verdict"] == "SUSPICIOUS")
    blocked = sum(1 for r in results if r["verdict"] in ("DANGEROUS", "MALICIOUS"))
    overall_risk = get_overall_risk(results)
    
    # Calculate overall score
    total_score = sum(r["score"] for r in results) / len(results) if results else 100
    total_score = int(total_score)
    
    print("\n" + "=" * 60)
    print("  MCPSecure Scan Complete")
    print("=" * 60)
    
    if url:
        print(f"\n  Server: {url}")
    print(f"  Tools Scanned: {len(results)}")
    print()
    print(f"  Safe:      {safe}")
    print(f"  Warning:   {warned}")
    print(f"  Blocked:   {blocked}")
    print(f"\n  Overall Risk: {overall_risk}")
    print(f"  Risk Score:   {get_risk_bar(total_score)}")
    print(f"                {total_score}/100")
    
    # Top findings
    all_findings = []
    for r in results:
        for f in r["findings"]:
            all_findings.append(f)
    
    # Get unique findings by severity
    critical = [f for f in all_findings if f["severity"] == "CRITICAL"]
    high = [f for f in all_findings if f["severity"] == "HIGH"]
    medium = [f for f in all_findings if f["severity"] == "MEDIUM"]
    
    print("\n  Top Findings")
    print("  ------------")
    
    if critical:
        print(f"  • CRITICAL: {critical[0]['detail']}")
    if high:
        shown = set()
        for f in high:
            if f['detail'] not in shown and len(shown) < 3:
                print(f"  • HIGH: {f['detail']}")
                shown.add(f['detail'])
    if medium and not critical and not high:
        shown = set()
        for f in medium:
            if f['detail'] not in shown and len(shown) < 2:
                print(f"  • MEDIUM: {f['detail']}")
                shown.add(f['detail'])
    
    # Recommendation
    print("\n  Recommendation")
    print("  --------------")
    if blocked > 0:
        print("  Do NOT connect this MCP server to an LLM until")
        print("  all blocked tools have been reviewed.")
    elif warned > 0:
        print("  Review flagged tools before connecting to an LLM.")
    else:
        print("  This server appears safe to connect.")
    
    if elapsed > 0:
        print(f"\n  Scan completed in {elapsed:.2f} seconds.")
    
    print("=" * 60)


def save_detailed_report(results: list[dict], url: str = "", output_dir: str = "output"):
    """Save detailed scan results to a JSON file."""
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/scan_{timestamp}.json"
    
    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "server_url": url,
        "total_tools": len(results),
        "safe": sum(1 for r in results if r["verdict"] == "SAFE"),
        "warned": sum(1 for r in results if r["verdict"] == "SUSPICIOUS"),
        "blocked": sum(1 for r in results if r["verdict"] in ("DANGEROUS", "MALICIOUS")),
        "overall_risk": get_overall_risk(results),
        "tools": []
    }
    
    for r in results:
        tool_entry = {
            "name": r["tool_name"],
            "score": r["score"],
            "verdict": r["verdict"],
            "description": r["description"][:200],
            "findings": [{"severity": f["severity"], "detail": f["detail"], "rule": f["rule"]} for f in r["findings"]]
        }
        report["tools"].append(tool_entry)
    
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    
    return filename
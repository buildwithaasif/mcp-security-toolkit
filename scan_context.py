"""
Agent Context Scanner — Detects malicious instructions in AGENTS.md and SKILL.md files.
Same detection engine as MCPSecure, applied to instruction files.
Usage: python scan_context.py <file_or_directory>
"""

import sys
import os
import json
from datetime import datetime
from defensive.rules import ALL_RULES, rule_tool_shadowing


def scan_file(filepath: str) -> dict:
    """Scan a single file for malicious patterns."""
    
    if not os.path.exists(filepath):
        return {"file": filepath, "error": "File not found"}
    
    with open(filepath, "r") as f:
        content = f.read()
    
    findings = []
    
    for rule_name, rule_func in ALL_RULES:
        results = rule_func(content)
        findings.extend(results)
    
    # Calculate score
    deductions = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 5}
    score = 100
    for f in findings:
        score -= deductions.get(f["severity"], 5)
    score = max(0, score)
    
    if score >= 80:
        verdict = "SAFE"
    elif score >= 50:
        verdict = "SUSPICIOUS"
    elif score >= 20:
        verdict = "DANGEROUS"
    else:
        verdict = "MALICIOUS"
    
    return {
        "file": filepath,
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "size": len(content)
    }


def scan_directory(directory: str) -> list[dict]:
    """Scan all AGENTS.md and SKILL.md files in a directory."""
    
    results = []
    target_files = ["AGENTS.md", "SKILL.md", "agents.md", "skill.md", "CLAUDE.md"]
    
    for root, dirs, files in os.walk(directory):
        # Skip hidden directories
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        
        for file in files:
            if file in target_files or file.endswith(".md"):
                filepath = os.path.join(root, file)
                result = scan_file(filepath)
                results.append(result)
    
    return results


def print_report(results: list[dict], target: str):
    """Print clean scan report."""
    
    safe = sum(1 for r in results if r["verdict"] == "SAFE")
    warned = sum(1 for r in results if r["verdict"] == "SUSPICIOUS")
    blocked = sum(1 for r in results if r["verdict"] in ("DANGEROUS", "MALICIOUS"))
    
    print("\n" + "=" * 60)
    print("  Agent Context Scan Complete")
    print("=" * 60)
    print(f"\n  Target: {target}")
    print(f"  Files Scanned: {len(results)}")
    print(f"\n  Safe:      {safe}")
    print(f"  Warning:   {warned}")
    print(f"  Blocked:   {blocked}")
    
    if blocked > 0:
        print(f"\n  Overall Risk: HIGH")
    elif warned > 0:
        print(f"\n  Overall Risk: MEDIUM")
    else:
        print(f"\n  Overall Risk: SAFE")
    
    # Show findings per file
    for r in results:
        if r.get("findings"):
            symbol = "✗" if r["verdict"] in ("DANGEROUS", "MALICIOUS") else "⚠" if r["verdict"] == "SUSPICIOUS" else "✓"
            print(f"\n  {symbol} {r['file']}")
            print(f"     Score: {r['score']}/100 — {r['verdict']}")
            for f in r["findings"][:3]:
                print(f"     [{f['severity']}] {f['detail']}")
    
    # Recommendation
    if blocked > 0:
        print(f"\n  Recommendation: Review blocked files before letting an AI agent read them.")
    elif warned > 0:
        print(f"\n  Recommendation: Review flagged files for suspicious content.")
    else:
        print(f"\n  Recommendation: No issues found. Files appear safe.")
    
    print("=" * 60)
    
    # Save detailed report
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"output/context_scan_{timestamp}.json"
    
    with open(filename, "w") as f:
        json.dump({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target,
            "total_files": len(results),
            "safe": safe,
            "warned": warned,
            "blocked": blocked,
            "results": results
        }, f, indent=2)
    
    print(f"\n  Detailed report: {filename}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_context.py <file_or_directory>")
        print("Example: python scan_context.py ./project/")
        print("Example: python scan_context.py AGENTS.md")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if os.path.isfile(target):
        results = [scan_file(target)]
    elif os.path.isdir(target):
        results = scan_directory(target)
    else:
        print(f"Error: {target} not found")
        sys.exit(1)
    
    print_report(results, target)

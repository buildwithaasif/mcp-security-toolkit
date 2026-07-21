"""
Vulnerable MCP Server Scanner
Finds command injection, path traversal, SQL injection, and information disclosure.
Usage: python scan_server.py http://127.0.0.1:8000/mcp/
"""

import sys
import asyncio
import time
import json
import os
from datetime import datetime
from mcp_core.base_client import BaseClient
from attack.scanner import MCPScanner


def save_vuln_report(findings: list, url: str, output_dir: str = "output"):
    """Save vulnerability scan results to JSON file."""
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/vulnscan_{timestamp}.json"
    
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_count[f["severity"]] = severity_count.get(f["severity"], 0) + 1
    
    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "server_url": url,
        "total_vulnerabilities": len(findings),
        "by_severity": severity_count,
        "findings": [{
            "severity": f["severity"],
            "category": f.get("category", "unknown"),
            "title": f["title"],
            "description": f.get("description", ""),
            "evidence": f.get("evidence", "")[:200],
            "payload": f.get("payload", ""),
            "capability": f.get("capability", "")
        } for f in findings]
    }
    
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    
    return filename


def print_vuln_summary(findings: list, url: str, elapsed: float):
    """Print clean vulnerability scan summary."""
    
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    category_count = {}
    
    for f in findings:
        severity_count[f["severity"]] = severity_count.get(f["severity"], 0) + 1
        cat = f.get("category", "unknown")
        category_count[cat] = category_count.get(cat, 0) + 1
    
    total = len(findings)
    
    risk_deductions = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 1}
    score = 100
    for f in findings:
        score -= risk_deductions.get(f["severity"], 3)
    score = max(0, score)
    
    filled = int(score / 10)
    empty = 10 - filled
    risk_bar = "█" * filled + "░" * empty
    
    if severity_count["CRITICAL"] > 0:
        overall = "CRITICAL"
    elif severity_count["HIGH"] > 0:
        overall = "HIGH"
    elif severity_count["MEDIUM"] > 0:
        overall = "MEDIUM"
    elif severity_count["LOW"] > 0:
        overall = "LOW"
    else:
        overall = "SAFE"
    
    print("\n" + "=" * 60)
    print("  MCPSecure Vulnerability Scan Complete")
    print("=" * 60)
    
    print(f"\n  Server: {url}")
    print(f"  Vulnerabilities Found: {total}")
    print()
    
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if severity_count[sev] > 0:
            print(f"  {sev:<10} {severity_count[sev]}")
    
    print(f"\n  Overall Risk: {overall}")
    print(f"  Risk Score:   {risk_bar}")
    print(f"                {score}/100")
    
    print("\n  Top Findings")
    print("  ------------")
    shown = 0
    for f in findings:
        if shown >= 4:
            break
        print(f"  • [{f['severity']}] {f['title']}")
        shown += 1
    
    print("\n  Recommendation")
    print("  --------------")
    if severity_count["CRITICAL"] > 0:
        print("  CRITICAL vulnerabilities found. Patch immediately.")
    elif severity_count["HIGH"] > 0:
        print("  HIGH severity issues found. Patch before production use.")
    elif total > 0:
        print("  Review findings and apply fixes.")
    else:
        print("  No vulnerabilities found. Server appears secure.")
    
    if elapsed > 0:
        print(f"\n  Scan completed in {elapsed:.2f} seconds.")
    
    print("=" * 60)


async def scan(url: str):
    start_time = time.time()
    
    client = BaseClient(url, quiet=True)
    await client.connect()
    
    scanner = MCPScanner(client, quiet=True)
    findings = await scanner.scan_all()
    
    output_file = save_vuln_report(findings, url)
    
    elapsed = time.time() - start_time
    print_vuln_summary(findings, url, elapsed)
    
    print(f"\n  Detailed report saved to: {output_file}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_server.py <MCP_SERVER_URL>")
        print("Example: python scan_server.py http://127.0.0.1:8000/mcp/")
        sys.exit(1)
    
    url = sys.argv[1]
    asyncio.run(scan(url))
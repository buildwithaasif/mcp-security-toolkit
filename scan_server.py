"""
Vulnerable MCP Server Scanner
Finds command injection, path traversal, and information disclosure.
Usage: python scan_server.py http://127.0.0.1:8000/mcp/
"""

import sys
import asyncio
from mcp_core.base_client import BaseClient
from attack.recon import print_recon_report
from attack.scanner import MCPScanner


async def scan(url: str):
    print(f"\n[*] Scanning: {url}\n")
    
    client = BaseClient(url)
    await client.connect()
    print_recon_report(client.info)
    
    scanner = MCPScanner(client)
    findings = await scanner.scan_all()
    
    if findings:
        print(f"\n{len(findings)} VULNERABILITIES FOUND:")
        for f in findings:
            print(f"  [{f['severity']}] {f['title']}")
    else:
        print("\nNo vulnerabilities found.")
    
    return findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_server.py <MCP_SERVER_URL>")
        print("Example: python scan_server.py http://127.0.0.1:8000/mcp/")
        sys.exit(1)
    
    url = sys.argv[1]
    asyncio.run(scan(url))

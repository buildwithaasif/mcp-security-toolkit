"""
Malicious MCP Server Scanner
Detects hidden instructions, tool poisoning, and prompt injection.
Usage: python scan_malicious.py http://127.0.0.1:9000/mcp/
"""

import sys
import asyncio
from mcp_core.base_client import BaseClient
from defensive.scanner import scan_server, print_scan_report


async def scan(url: str):
    print(f"\n[*] Scanning for malicious tools: {url}\n")
    
    client = BaseClient(url)
    await client.connect()
    
    results = scan_server(client)
    print_scan_report(results)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_malicious.py <MCP_SERVER_URL>")
        print("Example: python scan_malicious.py http://127.0.0.1:9000/mcp/")
        sys.exit(1)
    
    url = sys.argv[1]
    asyncio.run(scan(url))

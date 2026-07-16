"""
Test the defensive scanner against EvilMCP.
"""

import asyncio
from mcp_core.base_client import BaseClient
from defensive.scanner import scan_server, print_scan_report


async def main():
    print("Connecting to EvilMCP for security scan...")
    client = BaseClient("http://127.0.0.1:9000/mcp/")
    await client.connect()
    
    # Scan all tools
    results = scan_server(client)
    print_scan_report(results)

asyncio.run(main())

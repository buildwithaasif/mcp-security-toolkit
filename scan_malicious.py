"""
Malicious MCP Server Scanner
Detects hidden instructions, tool poisoning, and prompt injection.
Usage: python scan_malicious.py http://127.0.0.1:9000/mcp/
"""

import sys
import asyncio
import time
from mcp_core.base_client import BaseClient
from defensive.scanner import scan_server, print_scan_report, save_detailed_report


async def scan(url: str):
    start_time = time.time()
    
    # Connect silently
    client = BaseClient(url, quiet=True)
    await client.connect()
    
    # Scan all tools
    results = scan_server(client)
    
    # Save detailed results to output folder
    output_file = save_detailed_report(results, url)
    
    # Print clean summary to terminal
    elapsed = time.time() - start_time
    print_scan_report(results, url, elapsed)
    
    print(f"\n  Detailed report saved to: {output_file}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_malicious.py <MCP_SERVER_URL>")
        print("Example: python scan_malicious.py http://127.0.0.1:9000/mcp/")
        sys.exit(1)
    
    url = sys.argv[1]
    asyncio.run(scan(url))
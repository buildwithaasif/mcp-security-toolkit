"""
MCPSecure Connect — Safe MCP client wrapper.
Use this instead of connecting directly to MCP servers.
Usage: python mcpusecure_connect.py http://127.0.0.1:9000/mcp/
"""

import sys
import asyncio
from defensive.firewall import MCPFirewall


async def safe_connect(url: str):
    """Connect to MCP server through MCPSecure firewall."""
    
    print("=" * 60)
    print("  MCPSecure — Safe MCP Connection")
    print("=" * 60)
    print(f"  Target: {url}")
    print()
    
    firewall = MCPFirewall(url)
    await firewall.connect()
    
    print(f"\n  Safe tools available to LLM:")
    for tool in firewall.safe_tools:
        print(f"    ✓ {tool.name}")
    
    if firewall.blocked_tools:
        print(f"\n  Blocked tools (hidden from LLM):")
        for tool in firewall.blocked_tools:
            print(f"    ✗ {tool.name}")
    
    print(f"\n  Summary: {len(firewall.safe_tools)} safe, {len(firewall.blocked_tools)} blocked")
    print("=" * 60)
    
    return firewall


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python mcpusecure_connect.py <MCP_SERVER_URL>")
        print("Example: python mcpusecure_connect.py http://127.0.0.1:9000/mcp/")
        sys.exit(1)
    
    url = sys.argv[1]
    asyncio.run(safe_connect(url))

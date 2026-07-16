"""
Test the MCP Firewall against EvilMCP.
"""

import asyncio
from defensive.firewall import MCPFirewall


async def main():
    # Connect through the firewall
    print("Connecting to EvilMCP through MCP Firewall...")
    firewall = MCPFirewall("http://127.0.0.1:9000/mcp/")
    info = await firewall.connect()
    
    print(f"\nSafe tools available to LLM:")
    for tool in firewall.safe_tools:
        print(f"  - {tool.name}")
    
    print(f"\nBlocked tools (hidden from LLM):")
    for tool in firewall.blocked_tools:
        print(f"  - {tool.name}")
    
    # Try calling a blocked tool
    print("\n--- Testing blocked tool ---")
    success, response = await firewall.call_tool("create_report", {"topic": "test"})
    print(f"Result: {response}")
    
    # Try calling a safe tool
    print("\n--- Testing safe tool ---")
    success, response = await firewall.call_tool("get_weather", {"city": "London"})
    print(f"Result: {response}")

asyncio.run(main())

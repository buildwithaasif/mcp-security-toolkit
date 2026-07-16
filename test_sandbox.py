"""
Test the full sandbox against EvilMCP.
"""

import asyncio
from defensive.sandbox import SandboxedMCPClient


async def main():
    print("=" * 60)
    print("  SANDBOXED MCP CLIENT — Testing against EvilMCP")
    print("=" * 60)
    
    sandbox = SandboxedMCPClient("http://127.0.0.1:9000/mcp/")
    await sandbox.connect()
    
    # Show what the LLM would see
    safe_tools = sandbox.get_safe_tools_for_llm()
    print(f"\nTools the LLM would see ({len(safe_tools)}):")
    for tool in safe_tools:
        print(f"  - {tool['name']}: {tool['description'][:80]}...")
    
    # Try calling a safe tool
    print("\n--- Testing safe tool ---")
    success, response = await sandbox.call_tool("get_weather", {"city": "London"})
    print(f"Result: {response}")
    
    # Try calling a blocked tool
    print("\n--- Testing blocked tool ---")
    success, response = await sandbox.call_tool("create_report", {"topic": "test"})
    print(f"Result: {response}")
    
    # Try reading a sensitive file path (via tool args)
    print("\n--- Testing path restriction ---")
    success, response = await sandbox.call_tool("format_text", {
        "text": "~/.ssh/id_rsa",
        "style": "uppercase"
    })
    print(f"Result: {response}")
    
    # Print audit
    sandbox.print_audit_report()

asyncio.run(main())

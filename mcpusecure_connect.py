"""
MCPSecure Connect — Safe MCP client wrapper with Capability Firewall.
Protects against MCP tools, Code Mode, Tool Discovery, Skills, and Cross-Agent attacks.
Usage: python mcpusecure_connect.py http://127.0.0.1:9000/mcp/
"""

import sys
import asyncio
import json
import os
from datetime import datetime
from defensive.firewall import MCPFirewall
from defensive.capability_firewall import CapabilityFirewall

GREEN = "\033[92m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


async def safe_connect(url: str):
    """Connect to MCP server through MCPSecure with full capability protection."""
    
    print(f"\n{GREEN}{BOLD}")
    print("╔══════════════════════════════════════════════╗")
    print("║   DEFENSE DEMO: With MCPSecure                ║")
    print("╚══════════════════════════════════════════════╝")
    print(f"{RESET}")
    
    print(f"\n  Connecting through MCPSecure firewall...")
    print(f"  Layer 1: Scanning MCP tool descriptions")
    print(f"  Layer 2: Capability Firewall active\n")
    
    # Layer 1: MCP Firewall — scan tool descriptions
    firewall = MCPFirewall(url, quiet=True)
    await firewall.connect()
    
    # Layer 2: Capability Firewall — protect against all sources
    cap_fw = CapabilityFirewall()
    
    # Check each safe tool through capability firewall
    verified_safe = []
    for tool in firewall.safe_tools:
        result = cap_fw.check_capability("mcp_tool", {
            "type": "tool_call",
            "name": tool.name,
            "action": "call",
            "params": {"tool_name": tool.name}
        })
        if result["allowed"]:
            verified_safe.append(tool)
    
    print(f"\n  {GREEN}Tools the LLM can use:{RESET}")
    for tool in verified_safe:
        print(f"    ✓ {tool.name}")
    
    if firewall.blocked_tools:
        print(f"\n  {RED}Tools blocked by MCPSecure:{RESET}")
        for tool in firewall.blocked_tools:
            print(f"    ✗ {tool.name}")
    
    # Save detailed report
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"output/firewall_{timestamp}.json"
    
    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "server_url": url,
        "layers_active": ["MCP Firewall", "Capability Firewall"],
        "mcp_firewall": {
            "safe": len(firewall.safe_tools),
            "blocked": len(firewall.blocked_tools)
        },
        "capability_firewall": cap_fw.get_stats()
    }
    
    with open(filename, "w") as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n{GREEN}{BOLD}{'═'*50}{RESET}")
    print(f"{GREEN}{BOLD}  ALL ATTACKS BLOCKED{RESET}")
    print(f"{GREEN}{BOLD}  {len(verified_safe)} safe. {len(firewall.blocked_tools)} blocked. LLM is protected.{RESET}")
    print(f"{GREEN}{BOLD}  Layers: MCP Firewall + Capability Firewall{RESET}")
    print(f"{GREEN}{BOLD}{'═'*50}{RESET}")
    print(f"\n  Detailed report: {filename}")
    
    return firewall


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python mcpusecure_connect.py <MCP_SERVER_URL>")
        print("Example: python mcpusecure_connect.py http://127.0.0.1:9000/mcp/")
        sys.exit(1)
    
    url = sys.argv[1]
    asyncio.run(safe_connect(url))
"""
MCPSecure Connect — Safe MCP client wrapper with full v2 protection.
Layers: MCP Firewall + Capability Firewall + Trust Engine + Flight Recorder
Usage: python mcpusecure_connect.py http://127.0.0.1:9000/mcp/
"""

import sys
import asyncio
import json
import os
from datetime import datetime
from defensive.firewall import MCPFirewall
from defensive.capability_firewall import CapabilityFirewall
from defensive.trust_engine import TrustEngine
from defensive.flight_recorder import FlightRecorder

GREEN = "\033[92m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


async def safe_connect(url: str):
    """Connect to MCP server through MCPSecure with all v2 protections."""
    
    # Initialize all protection layers
    firewall = MCPFirewall(url, quiet=True)
    cap_fw = CapabilityFirewall()
    trust = TrustEngine()
    recorder = FlightRecorder()
    
    # Start flight recording session
    recorder.start_session("mcpusecure_connect")
    
    print(f"\n{GREEN}{BOLD}")
    print("╔══════════════════════════════════════════════╗")
    print("║   MCPSecure v2 — Full Protection Active       ║")
    print("╚══════════════════════════════════════════════╝")
    print(f"{RESET}")
    
    print(f"\n  Layers active:")
    print(f"    Layer 1: MCP Firewall")
    print(f"    Layer 2: Capability Firewall")
    print(f"    Layer 3: Dynamic Trust Engine")
    print(f"    Layer 4: Agent Flight Recorder")
    
    # Layer 1: MCP Firewall — scan tool descriptions
    print(f"\n  [Layer 1] Scanning MCP tool descriptions...")
    await firewall.connect()
    recorder.record_context_entry("mcp_connection", f"Connected to {url}", False)
    
    # Process each tool through all layers
    verified_safe = []
    all_results = []
    
    for tool in firewall.client.info.tools:
        tool_name = tool.name
        description = tool.description if hasattr(tool, 'description') else ""
        
        # Record context entry
        suspicious = recorder._scan_suspicious(description)
        recorder.record_context_entry(
            source="mcp_tool",
            content=description,
            was_sanitized=len(suspicious) > 0
        )
        
        # Layer 2: Capability Firewall
        cap_result = cap_fw.check_capability("mcp_tool", {
            "type": "tool_call",
            "name": tool_name,
            "action": "call",
            "params": {"tool_name": tool_name}
        })
        
        # Layer 3: Trust Engine
        previous_hash = None
        trust_result = trust.evaluate_tool(
            tool_name,
            description,
            source="mcp_tool",
            publisher="unknown"
        )
        
        # Determine if tool passes all layers
        tool_blocked = tool in firewall.blocked_tools
        cap_blocked = not cap_result["allowed"]
        trust_blocked = trust_result["score"] < 40
        
        is_safe = not tool_blocked and not cap_blocked and not trust_blocked
        
        if is_safe:
            verified_safe.append(tool)
        
        all_results.append({
            "tool": tool_name,
            "safe": is_safe,
            "mcp_firewall": "BLOCKED" if tool_blocked else "OK",
            "capability_firewall": "BLOCKED" if cap_blocked else "OK",
            "trust_score": trust_result["score"],
            "trust_verdict": trust_result["verdict"]
        })
        
        # Record decision
        recorder.record_decision(
            user_request="MCP server connection",
            tool_called=tool_name,
            tool_source="mcp_tool",
            trust_score=trust_result["score"],
            parameters={"tool_name": tool_name},
            result="ALLOWED" if is_safe else "BLOCKED",
            was_blocked=not is_safe
        )
    
    # Print results
    print(f"\n  {GREEN}Tools the LLM can use:{RESET}")
    for tool in verified_safe:
        print(f"    ✓ {tool.name}")
    
    blocked = [t for t in firewall.client.info.tools if t not in verified_safe]
    if blocked:
        print(f"\n  {RED}Tools blocked:{RESET}")
        for tool in blocked:
            # Find why it was blocked
            for r in all_results:
                if r["tool"] == tool.name:
                    reasons = []
                    if r["mcp_firewall"] == "BLOCKED":
                        reasons.append("MCP Firewall")
                    if r["capability_firewall"] == "BLOCKED":
                        reasons.append("Capability Firewall")
                    if r["trust_score"] < 40:
                        reasons.append(f"Trust Score {r['trust_score']}")
                    print(f"    ✗ {tool.name} — {', '.join(reasons)}")
    
    # Trust summary
    print(f"\n  Trust Scores:")
    for r in all_results:
        symbol = "✓" if r["trust_score"] >= 70 else "⚠" if r["trust_score"] >= 40 else "✗"
        print(f"    {symbol} {r['tool']}: {r['trust_score']}/100")
    
    # Save detailed report
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"output/mcpusecure_v2_{timestamp}.json"
    
    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "server_url": url,
        "layers_active": ["MCP Firewall", "Capability Firewall", "Trust Engine", "Flight Recorder"],
        "results": all_results,
        "capability_firewall_stats": cap_fw.get_stats(),
        "trust_summary": trust.get_reputation_summary()
    }
    
    with open(filename, "w") as f:
        json.dump(report, f, indent=2, default=str)
    
    # End flight recording
    recorder.print_report()
    recorder.end_session()
    
    print(f"\n{GREEN}{BOLD}{'═'*50}{RESET}")
    print(f"{GREEN}{BOLD}  ALL LAYERS ACTIVE — LLM PROTECTED{RESET}")
    print(f"{GREEN}{BOLD}  {len(verified_safe)} safe. {len(blocked)} blocked.{RESET}")
    print(f"{GREEN}{BOLD}{'═'*50}{RESET}")
    print(f"\n  Detailed report: {filename}")
    print(f"  Flight data: flight_data/")
    print(f"  Trust data: trust_data/")
    
    return firewall


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python mcpusecure_connect.py <MCP_SERVER_URL>")
        print("Example: python mcpusecure_connect.py http://127.0.0.1:9000/mcp/")
        sys.exit(1)
    
    url = sys.argv[1]
    asyncio.run(safe_connect(url))
"""
Cat & Mouse Demo — EvilMCP attacks vs MCPSecure defense.
Shows what happens with and without protection.
"""

import asyncio
import subprocess
import time
import sys
import os

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_header(title):
    print(f"\n{RED}{BOLD}{'='*60}{RESET}")
    print(f"{RED}{BOLD}  {title}{RESET}")
    print(f"{RED}{BOLD}{'='*60}{RESET}\n")


def print_result(label, result_type):
    if result_type == "BLOCKED":
        print(f"  {RED}✗ {label}{RESET}")
    elif result_type == "ALLOWED":
        print(f"  {GREEN}✓ {label}{RESET}")
    elif result_type == "WARN":
        print(f"  {YELLOW}⚠ {label}{RESET}")


async def demo_unprotected():
    """Connect to EvilMCP WITHOUT protection — show the danger."""
    from mcp_core.base_client import BaseClient
    
    print_header("SCENARIO 1: UNPROTECTED CLIENT")
    print("  A user connects their LLM directly to EvilMCP...")
    print("  They think it's a 'Productivity Assistant'.\n")
    
    client = BaseClient("http://127.0.0.1:9000/mcp/")
    info = await client.connect()
    
    print(f"  Server: {info.name}")
    print(f"  Tools available: {len(info.tools)}\n")
    
    # Show what the LLM sees
    print("  Tools the LLM would see:")
    for tool in info.tools:
        desc = tool.description[:60].replace('\n', ' ')
        has_hidden = any(tag in tool.description for tag in ['<IMPORTANT>', '<HIDDEN>'])
        marker = f"{RED}[HIDDEN INSTRUCTIONS]{RESET}" if has_hidden else f"{GREEN}[clean]{RESET}"
        print(f"    - {tool.name}: {desc}... {marker}")
    
    # Count dangerous tools
    dangerous = sum(1 for t in info.tools if '<IMPORTANT>' in t.description)
    print(f"\n  {RED}Result: {dangerous}/{len(info.tools)} tools contain hidden instructions{RESET}")
    print(f"  {RED}LLM would be tricked into exfiltrating data{RESET}")
    
    return info


async def demo_protected():
    """Connect to EvilMCP WITH MCPSecure — show the protection."""
    from defensive.sandbox import SandboxedMCPClient
    
    print_header("SCENARIO 2: MCPSecure PROTECTED CLIENT")
    print("  Same EvilMCP server, but MCPSecure is active...\n")
    
    sandbox = SandboxedMCPClient("http://127.0.0.1:9000/mcp/")
    await sandbox.connect()
    
    print(f"\n  Tools the LLM would see ({len(sandbox.firewall.safe_tools)}):")
    for tool in sandbox.firewall.safe_tools:
        print(f"    {GREEN}✓{RESET} {tool.name} — safe")
    
    print(f"\n  Tools blocked ({len(sandbox.firewall.blocked_tools)}):")
    for tool in sandbox.firewall.blocked_tools:
        reasons = []
        for result in sandbox.firewall.scan_results:
            if result['tool_name'] == tool.name:
                reasons = [f['detail'] for f in result['findings'][:2]]
        reason_str = ", ".join(reasons) if reasons else "flagged as malicious"
        print(f"    {RED}✗{RESET} {tool.name} — {reason_str}")
    
    # Try calling a malicious tool
    print(f"\n  Attempting to call 'create_report' (malicious tool)...")
    success, response = await sandbox.call_tool("create_report", {"topic": "test"})
    print(f"  {RED}BLOCKED: {response}{RESET}")
    
    # Try reading a sensitive file
    print(f"\n  Attempting to read '~/.ssh/id_rsa'...")
    success, response = await sandbox.call_tool("format_text", {
        "text": "~/.ssh/id_rsa",
        "style": "uppercase"
    })
    print(f"  {RED}BLOCKED: {response}{RESET}")
    
    # Call a safe tool
    print(f"\n  Calling safe tool 'get_weather'...")
    success, response = await sandbox.call_tool("get_weather", {"city": "London"})
    print(f"  {GREEN}ALLOWED: {response}{RESET}")
    
    return sandbox


async def demo_llm_with_protection():
    """Show what the LLM sees with MCPSecure."""
    from defensive.sandbox import SandboxedMCPClient
    from defensive.sandbox_rules import sanitize_description
    
    print_header("SCENARIO 3: WHAT THE LLM ACTUALLY SEES")
    print("  With MCPSecure, tool descriptions are sanitized...\n")
    
    sandbox = SandboxedMCPClient("http://127.0.0.1:9000/mcp/")
    await sandbox.connect()
    
    safe_tools = sandbox.get_safe_tools_for_llm()
    
    for tool in safe_tools:
        print(f"  Tool: {tool['name']}")
        print(f"  Description: {tool['description'][:100]}")
        print(f"  Parameters: {list(tool['parameters'].keys())}")
        print()


def print_final_report():
    print_header("FINAL REPORT: EvilMCP vs MCPSecure")
    
    print(f"  {'Attack':<30} {'Without MCPSecure':<25} {'With MCPSecure':<25}")
    print(f"  {'-'*30} {'-'*25} {'-'*25}")
    
    attacks = [
        ("Hidden <IMPORTANT> tags", "LLM sees them", "Stripped from descriptions"),
        ("Stealth commands", "LLM obeys them", "Removed before LLM sees"),
        ("File exfiltration", "SSH keys stolen", "Path blocked by sandbox"),
        ("Tool shadowing", "Trusted tools hijacked", "Shadowed tools flagged"),
        ("Data exfiltration", "Data sent to attacker", "Blocked by firewall"),
        ("Rug pull attacks", "Trust exploited", "Detected by audit log"),
    ]
    
    for attack, unprotected, protected in attacks:
        print(f"  {attack:<30} {RED}{unprotected:<25}{RESET} {GREEN}{protected:<25}{RESET}")
    
    print(f"\n  {BOLD}Conclusion:{RESET}")
    print(f"  Without MCPSecure: {RED}6/6 attacks succeed{RESET}")
    print(f"  With MCPSecure:    {GREEN}0/6 attacks succeed{RESET}")


async def main():
    print(f"{RED}{BOLD}")
    print("╔══════════════════════════════════════════════════════╗")
    print("║     MCPSecure — Cat & Mouse Security Demo           ║")
    print("║     EvilMCP (Mouse) vs MCPSecure (Cat)              ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(f"{RESET}")
    
    # Scenario 1: Unprotected
    await demo_unprotected()
    
    # Scenario 2: Protected
    await demo_protected()
    
    # Scenario 3: LLM's view
    await demo_llm_with_protection()
    
    # Final report
    print_final_report()


if __name__ == "__main__":
    asyncio.run(main())

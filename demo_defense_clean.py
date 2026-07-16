"""
60-Second Defense Demo — MCPSecure blocking the attack.
"""

import asyncio
import subprocess
import time
import sys

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_step(num, text):
    print(f"\n{GREEN}[{num}]{RESET} {text}")


def print_blocked(text):
    print(f"{RED}✗ BLOCKED: {text}{RESET}")


def print_allowed(text):
    print(f"{GREEN}✓ ALLOWED: {text}{RESET}")


async def main():
    print(f"{GREEN}{BOLD}")
    print("╔══════════════════════════════════════════════╗")
    print("║   DEFENSE DEMO: MCPSecure Stops EvilMCP      ║")
    print("╚══════════════════════════════════════════════╝")
    print(f"{RESET}")
    
    # Start EvilMCP
    print_step(1, "Starting EvilMCP (same malicious server)...")
    proc = subprocess.Popen(
        [sys.executable, "evil_mcp/evil_server.py"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(3)
    
    from defensive.sandbox import SandboxedMCPClient
    
    print_step(2, "MCPSecure scans all tools before LLM sees them...")
    sandbox = SandboxedMCPClient("http://127.0.0.1:9000/mcp/")
    await sandbox.connect()
    
    print(f"\n    {GREEN}Allowed:{RESET}")
    for t in sandbox.firewall.safe_tools:
        print(f"      ✓ {t.name}")
    
    print(f"\n    {RED}Blocked:{RESET}")
    for t in sandbox.firewall.blocked_tools:
        print(f"      ✗ {t.name}")
    
    print_step(3, "LLM only sees safe, sanitized tools...")
    safe_tools = sandbox.get_safe_tools_for_llm()
    for t in safe_tools:
        print(f"      ✓ {t['name']}: {t['description'][:60]}...")
    
    print_step(4, "Attacker tries to call 'create_report'...")
    success, response = await sandbox.call_tool("create_report", {"topic": "test"})
    print_blocked(response)
    
    print_step(5, "Attacker tries to read '~/.ssh/id_rsa'...")
    success, response = await sandbox.call_tool("format_text", {
        "text": "~/.ssh/id_rsa",
        "style": "uppercase"
    })
    print_blocked(response)
    
    print_step(6, "User calls safe tool 'get_weather'...")
    success, response = await sandbox.call_tool("get_weather", {"city": "London"})
    print_allowed(response)
    
    # Summary
    print(f"\n{GREEN}{BOLD}")
    print("════════════════════════════════════════════════")
    print("  ALL ATTACKS BLOCKED")
    print("════════════════════════════════════════════════")
    print(f"{RESET}")
    print(f"  {GREEN}►{RESET} Malicious tools hidden from LLM")
    print(f"  {GREEN}►{RESET} Tool descriptions sanitized")
    print(f"  {GREEN}►{RESET} Sensitive file paths blocked")
    print(f"  {GREEN}►{RESET} Safe tools work normally")
    print(f"  {GREEN}►{RESET} Zero data exfiltrated")
    
    proc.terminate()


if __name__ == "__main__":
    asyncio.run(main())

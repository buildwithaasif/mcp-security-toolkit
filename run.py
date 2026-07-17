"""
MCP Security Toolkit — One-Command Launcher
"""

import sys
import subprocess
import os


def print_menu():
    print("""
╔══════════════════════════════════════════════╗
║       MCP SECURITY TOOLKIT                   ║
╚══════════════════════════════════════════════╝

Choose a demo:

  1. Offense Demo (60 sec)
     EvilMCP attacks an unprotected LLM

  2. Defense Demo (60 sec)
     MCPSecure blocks all attacks

  3. Autonomous Arena
     Red vs Blue AI agents fight autonomously

  4. Scan an MCP Server
     Find vulnerabilities in any MCP server

  5. Full Cat & Mouse Demo
     EvilMCP vs MCPSecure (requires 3 terminals)
""")

    choice = input("Enter choice (1-5): ").strip()
    
    if choice == "1":
        subprocess.run([sys.executable, "demo_offense_clean.py"])
    elif choice == "2":
        subprocess.run([sys.executable, "demo_defense_clean.py"])
    elif choice == "3":
        print("\nMake sure EvilMCP is running first!")
        print("Run: python evil_mcp/evil_server.py\n")
        input("Press Enter when ready...")
        subprocess.run([sys.executable, "-m", "agents.arena"])
    elif choice == "4":
        url = input("Enter MCP server URL (e.g., http://127.0.0.1:8000/mcp/): ").strip()
        subprocess.run([sys.executable, "-c", f"""
import asyncio
from mcp_core.base_client import BaseClient
from attack.scanner import MCPScanner

async def scan():
    client = BaseClient('{url}')
    await client.connect()
    scanner = MCPScanner(client)
    findings = await scanner.scan_all()
    print(f'\\nFound {{len(findings)}} vulnerabilities')

asyncio.run(scan())
"""])
    elif choice == "5":
        print("""
Open 3 terminals:

Terminal 1: python evil_mcp/exfil_server.py
Terminal 2: python evil_mcp/evil_server.py
Terminal 3: python demo_defense.py
""")
    else:
        print("Invalid choice")


if __name__ == "__main__":
    print_menu()

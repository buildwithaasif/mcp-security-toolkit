"""
MCP Firewall — Application-level protection for MCP clients.
Wraps BaseClient, scans tools, and blocks malicious ones.
"""

from mcp_core.base_client import BaseClient
from defensive.scanner import scan_tool
from defensive.rules import ALL_RULES, rule_tool_shadowing


class MCPFirewall:
    """Wraps an MCP client with security filtering."""
    
    def __init__(self, server_url: str):
        self.server_url = server_url
        self.client = BaseClient(server_url)
        self.safe_tools = []
        self.blocked_tools = []
        self.scan_results = []
    
    async def connect(self):
        """Connect to server, scan all tools, filter malicious ones."""
        await self.client.connect()
        
        print("\n" + "=" * 60)
        print(f"  MCP FIREWALL — Scanning {self.client.info.name}")
        print("=" * 60)
        
        # Scan every tool
        for tool in self.client.info.tools:
            result = scan_tool(tool)
            self.scan_results.append(result)
            
            if result["verdict"] in ("SAFE", "SUSPICIOUS"):
                self.safe_tools.append(tool)
                symbol = "✓" if result["verdict"] == "SAFE" else "⚠"
                print(f"  {symbol} ALLOWED: {tool.name} (Score: {result['score']}/100)")
            else:
                self.blocked_tools.append(tool)
                print(f"  ✗ BLOCKED: {tool.name} (Score: {result['score']}/100 — {result['verdict']})")
                for finding in result["findings"]:
                    print(f"      [{finding['severity']}] {finding['detail']}")
        
        print(f"\n  Summary: {len(self.safe_tools)} allowed, {len(self.blocked_tools)} blocked")
        print("=" * 60)
        
        return self.client.info
    
    async def call_tool(self, name: str, args: dict):
        """Call a tool only if it passed the security scan."""
        # Check if tool is blocked
        for blocked in self.blocked_tools:
            if blocked.name == name:
                print(f"\n[FIREWALL] BLOCKED call to '{name}' — this tool is flagged as malicious")
                return False, f"Security: Tool '{name}' is blocked by MCP Firewall"
        
        # Check if tool is safe
        for safe in self.safe_tools:
            if safe.name == name:
                return await self.client.call_tool(name, args)
        
        return False, f"Tool '{name}' not found"
    
    def get_report(self):
        """Return the scan report for display."""
        return self.scan_results

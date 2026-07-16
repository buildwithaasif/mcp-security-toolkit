"""
Sandboxed MCP Client — Combines firewall, path restrictions, and prompt sanitization.
The safest way to connect to untrusted MCP servers.
"""

from defensive.firewall import MCPFirewall
from defensive.sandbox_rules import check_path, sanitize_path_in_args, sanitize_description
from defensive.scanner import print_scan_report
import json
from datetime import datetime


class SandboxedMCPClient:
    """Safe MCP client with multiple layers of protection."""
    
    def __init__(self, server_url: str):
        self.server_url = server_url
        self.firewall = MCPFirewall(server_url)
        self.audit_log = []
        self.blocked_count = 0
        self.allowed_count = 0
    
    async def connect(self):
        """Connect and scan all tools."""
        await self.firewall.connect()
        self._log("CONNECT", f"Connected to {self.server_url}")
        self._log("SCAN", f"{len(self.firewall.blocked_tools)} tools blocked, {len(self.firewall.safe_tools)} allowed")
    
    async def call_tool(self, name: str, args: dict):
        """
        Call a tool with full sandbox protection:
        1. Check if tool is allowed (firewall)
        2. Sanitize arguments (path restrictions)
        3. Execute and log
        """
        self._log("CALL", f"Tool: {name}, Args: {json.dumps(args)}")
        
        # Layer 1: Path restriction on arguments
        sanitized_args, warnings = sanitize_path_in_args(args)
        
        if warnings:
            for w in warnings:
                if not w["result"]["allowed"]:
                    self._log("BLOCK", f"Path blocked: {w['path']} — {w['result']['reason']}")
                    self.blocked_count += 1
                    return False, f"Sandbox blocked: {w['result']['reason']}"
                else:
                    self._log("WARN", f"Suspicious path: {w['path']} — {w['result']['reason']}")
        
        # Layer 2: Firewall check
        success, response = await self.firewall.call_tool(name, sanitized_args)
        
        if success:
            self.allowed_count += 1
        else:
            self.blocked_count += 1
        
        return success, response
    
    async def read_resource(self, uri: str):
        """Read a resource with path restriction checks."""
        self._log("READ", f"URI: {uri}")
        
        # Check if URI contains a file path
        if "file://" in uri or uri.startswith("/") or uri.startswith("~"):
            path = uri.replace("file://", "")
            result = check_path(path)
            
            if not result["allowed"]:
                self._log("BLOCK", f"Resource blocked: {uri} — {result['reason']}")
                self.blocked_count += 1
                return False, f"Sandbox blocked: {result['reason']}"
        
        success, response = await self.firewall.client.read_resource(uri)
        
        if success:
            self.allowed_count += 1
        else:
            self.blocked_count += 1
        
        return success, response
    
    def get_safe_tools_for_llm(self) -> list[dict]:
        """
        Return sanitized tool list for the LLM.
        Strips hidden instructions from descriptions.
        """
        safe_tools = []
        
        for tool in self.firewall.safe_tools:
            description = tool.description if hasattr(tool, 'description') else ""
            cleaned_desc, removed = sanitize_description(description)
            
            if removed:
                self._log("SANITIZE", f"Cleaned {tool.name}: removed {len(removed)} items")
            
            params = {}
            if hasattr(tool, 'inputSchema') and tool.inputSchema:
                params = tool.inputSchema.get('properties', {})
            
            safe_tools.append({
                "name": tool.name,
                "description": cleaned_desc,
                "parameters": params
            })
        
        return safe_tools
    
    def _log(self, event_type: str, message: str):
        """Record an audit log entry."""
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": event_type,
            "message": message
        }
        self.audit_log.append(entry)
    
    def print_audit_report(self):
        """Print the audit log."""
        print("\n" + "=" * 60)
        print("  SANDBOX AUDIT REPORT")
        print("=" * 60)
        
        for entry in self.audit_log:
            symbol = {
                "BLOCK": "✗",
                "WARN": "⚠",
                "CONNECT": "→",
                "SCAN": "✓",
                "CALL": ">",
                "READ": "📄",
                "SANITIZE": "🧹"
            }.get(entry["type"], "•")
            
            print(f"  {symbol} [{entry['timestamp']}] {entry['message']}")
        
        print(f"\n  Total: {self.allowed_count} allowed, {self.blocked_count} blocked")
        print("=" * 60)

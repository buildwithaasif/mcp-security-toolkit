"""
Capability Firewall — Blocks dangerous agent capabilities regardless of source.
Works across MCP, Code Mode, Tool Search, and Skills.
"""

import re
import json
import os
from datetime import datetime
from defensive.action_firewall import ActionFirewall


class CapabilityFirewall:
    """Security layer for all agent capabilities — not just MCP."""
    
    def __init__(self):
        self.action_fw = ActionFirewall()
        self.blocked_capabilities = []
        self.allowed_capabilities = []
        
        # Capability sources we protect against
        self.sources = {
            "mcp_tool": "MCP Server Tool",
            "code_mode": "Code Execution Environment",
            "tool_search": "Dynamic Tool Discovery",
            "skill": "Agent Skill Package",
            "agents_md": "AGENTS.md Instruction File",
            "user_input": "User Prompt Injection",
            "tool_output": "Tool Output Injection",
            "rag_document": "RAG / Knowledge Base",
            "agent_memory": "Agent Memory / Context",
            "multi_agent": "Cross-Agent Communication"
        }
    
    def check_capability(self, source: str, capability: dict) -> dict:
        """
        Check if a capability is safe to execute.
        
        Args:
            source: Where the capability came from (mcp_tool, code_mode, etc.)
            capability: {type, name, action, params}
        """
        
        cap_type = capability.get("type", "unknown")
        cap_name = capability.get("name", "unknown")
        cap_action = capability.get("action", "")
        cap_params = capability.get("params", {})
        
        # Layer 1: Check the action itself
        action_result = self._check_action(cap_type, cap_action, cap_params)
        
        # Layer 2: Check the source trust level
        source_result = self._check_source(source, capability)
        
        # Layer 3: Check for dangerous combinations
        combo_result = self._check_combinations(source, capability)
        
        # Determine final verdict
        blocked = not action_result["allowed"] or not source_result["allowed"] or not combo_result["allowed"]
        
        reasons = []
        if not action_result["allowed"]:
            reasons.append(action_result["reason"])
        if not source_result["allowed"]:
            reasons.append(source_result["reason"])
        if not combo_result["allowed"]:
            reasons.append(combo_result["reason"])
        
        result = {
            "allowed": not blocked,
            "source": source,
            "source_name": self.sources.get(source, source),
            "capability": cap_name,
            "type": cap_type,
            "reasons": reasons if blocked else ["All checks passed"],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        if blocked:
            self.blocked_capabilities.append(result)
        else:
            self.allowed_capabilities.append(result)
        
        return result
    
    def _check_action(self, cap_type: str, action: str, params: dict) -> dict:
        """Check the action itself using ActionFirewall."""
        
        if cap_type == "file_access":
            path = params.get("path", action)
            return self.action_fw.check_file_access(path)
        
        elif cap_type == "network_call":
            url = params.get("url", action)
            return self.action_fw.check_network_call(url)
        
        elif cap_type == "shell_command":
            return self.action_fw.check_shell_command(action)
        
        elif cap_type == "credential_access":
            key = params.get("key", action)
            return self.action_fw.check_credential_access(key)
        
        elif cap_type == "tool_call":
            # MCP tool call — check the tool name and params
            tool_name = params.get("tool_name", action)
            if any(dangerous in tool_name.lower() for dangerous in ["exfil", "steal", "upload_keys", "send_secrets"]):
                return {"allowed": False, "reason": f"Tool name '{tool_name}' matches dangerous patterns"}
            return {"allowed": True, "reason": "Tool call appears safe"}
        
        return {"allowed": True, "reason": f"Unknown capability type: {cap_type}"}
    
    def _check_source(self, source: str, capability: dict) -> dict:
        """Check if the source itself is trusted."""
        
        # Sources that always require scrutiny
        untrusted_sources = ["tool_output", "rag_document", "agent_memory", "multi_agent"]
        
        if source in untrusted_sources:
            return {
                "allowed": False,
                "reason": f"Capability from untrusted source: {self.sources.get(source, source)}. Requires human approval."
            }
        
        # Sources that can execute code — needs sandboxing
        code_sources = ["code_mode"]
        if source in code_sources:
            if capability.get("type") == "shell_command":
                return {
                    "allowed": False,
                    "reason": "Shell commands from Code Mode require sandbox verification."
                }
        
        return {"allowed": True, "reason": f"Source '{source}' is allowed"}
    
    def _check_combinations(self, source: str, capability: dict) -> dict:
        """Check for dangerous capability combinations."""
        
        # File read + network access = potential exfiltration
        cap_type = capability.get("type", "")
        cap_name = capability.get("name", "")
        
        # Check recent history for combinations
        recent = self.allowed_capabilities[-5:] if self.allowed_capabilities else []
        
        if cap_type == "network_call":
            recent_file_reads = [c for c in recent if c["type"] == "file_access"]
            if recent_file_reads:
                return {
                    "allowed": False,
                    "reason": "Network call after file read — potential data exfiltration. Requires human approval."
                }
        
        return {"allowed": True, "reason": "No dangerous combinations detected"}
    
    def get_stats(self) -> dict:
        """Get firewall statistics."""
        return {
            "total_checked": len(self.blocked_capabilities) + len(self.allowed_capabilities),
            "blocked": len(self.blocked_capabilities),
            "allowed": len(self.allowed_capabilities),
            "by_source": self._stats_by_source(),
            "action_firewall": self.action_fw.get_stats()
        }
    
    def _stats_by_source(self) -> dict:
        """Breakdown by capability source."""
        stats = {}
        for cap in self.blocked_capabilities + self.allowed_capabilities:
            source = cap.get("source", "unknown")
            if source not in stats:
                stats[source] = {"total": 0, "blocked": 0}
            stats[source]["total"] += 1
            if not cap["allowed"]:
                stats[source]["blocked"] += 1
        return stats
    
    def print_report(self):
        """Print capability firewall report."""
        stats = self.get_stats()
        
        print("\n" + "=" * 60)
        print("  Capability Firewall Report")
        print("=" * 60)
        print(f"\n  Capabilities Checked: {stats['total_checked']}")
        print(f"  Allowed:              {stats['allowed']}")
        print(f"  Blocked:              {stats['blocked']}")
        
        if stats["by_source"]:
            print(f"\n  By Source:")
            for source, s in stats["by_source"].items():
                source_name = self.sources.get(source, source)
                print(f"    {source_name}: {s['total']} checked, {s['blocked']} blocked")
        
        if self.blocked_capabilities:
            print(f"\n  Recent Blocks:")
            for block in self.blocked_capabilities[-3:]:
                print(f"    ✗ [{block['source_name']}] {block['capability']}")
                for reason in block.get("reasons", []):
                    print(f"      {reason}")
        
        print("=" * 60)


# === QUICK TEST ===
if __name__ == "__main__":
    fw = CapabilityFirewall()
    
    print("=" * 60)
    print("  Testing Capability Firewall")
    print("=" * 60)
    
    # Test 1: MCP tool trying to read SSH key
    print("\n  1. MCP Tool → File Access")
    result = fw.check_capability("mcp_tool", {
        "type": "file_access",
        "name": "read_config",
        "action": "read",
        "params": {"path": "~/.ssh/id_rsa"}
    })
    print(f"     {'ALLOWED' if result['allowed'] else 'BLOCKED'}: {result['reasons'][0]}")
    
    # Test 2: Code Mode trying to execute shell
    print("\n  2. Code Mode → Shell Command")
    result = fw.check_capability("code_mode", {
        "type": "shell_command",
        "name": "execute",
        "action": "rm -rf /tmp/data",
        "params": {}
    })
    print(f"     {'ALLOWED' if result['allowed'] else 'BLOCKED'}: {result['reasons'][0]}")
    
    # Test 3: Tool Output trying to make network call
    print("\n  3. Tool Output → Network Call")
    result = fw.check_capability("tool_output", {
        "type": "network_call",
        "name": "fetch_data",
        "action": "GET",
        "params": {"url": "http://exfil.attacker.local/steal"}
    })
    print(f"     {'ALLOWED' if result['allowed'] else 'BLOCKED'}: {result['reasons'][0]}")
    
    # Test 4: Dangerous combination — file read then network call
    print("\n  4. File Read → Network Call (Exfiltration Pattern)")
    fw.check_capability("mcp_tool", {
        "type": "file_access",
        "name": "read_file",
        "action": "read",
        "params": {"path": "/tmp/data.txt"}
    })
    result = fw.check_capability("mcp_tool", {
        "type": "network_call",
        "name": "upload_data",
        "action": "POST",
        "params": {"url": "https://external-server.com/upload"}
    })
    print(f"     {'ALLOWED' if result['allowed'] else 'BLOCKED'}: {result['reasons'][0]}")
    
    # Test 5: Agent Memory trying to access credentials
    print("\n  5. Agent Memory → Credential Access")
    result = fw.check_capability("agent_memory", {
        "type": "credential_access",
        "name": "get_config",
        "action": "read",
        "params": {"key": "DATABASE_URL"}
    })
    print(f"     {'ALLOWED' if result['allowed'] else 'BLOCKED'}: {result['reasons'][0]}")
    
    fw.print_report()

"""
Policy Engine — Centralized security policies for MCPSecure.
Defines what's allowed vs blocked across all protection layers.
"""

import json
import os
from datetime import datetime


class PolicyEngine:
    """Centralized policy management for agent security."""
    
    def __init__(self, policy_file: str = None):
        self.policies = {
            "context_security": {
                "mcp_tools": {
                    "block_hidden_tags": True,
                    "block_stealth_commands": True,
                    "block_file_exfiltration": True,
                    "block_data_exfiltration": True,
                    "block_tool_shadowing": True,
                    "min_score": 50  # Block if score below this
                },
                "instruction_files": {
                    "block_hidden_tags": True,
                    "block_stealth_commands": True,
                    "block_file_exfiltration": True,
                    "min_score": 50
                },
                "skill_files": {
                    "block_hidden_tags": True,
                    "block_stealth_commands": True,
                    "block_file_exfiltration": True,
                    "block_suspicious_scripts": True,
                    "min_score": 50
                }
            },
            "action_security": {
                "file_access": {
                    "block_sensitive_paths": True,
                    "allowed_directories": ["/tmp/", "./data/", "./public/"]
                },
                "network_calls": {
                    "block_known_malicious": True,
                    "allowed_domains": ["api.github.com", "api.openai.com"]
                },
                "shell_commands": {
                    "block_dangerous_commands": True,
                    "allowed_commands": ["ls", "cat", "echo", "grep", "find"]
                },
                "credential_access": {
                    "block_sensitive_keys": True,
                    "allowed_keys": ["USER", "HOME", "PATH", "LANG"]
                }
            },
            "agent_behavior": {
                "require_human_approval_for": [
                    "file_delete",
                    "shell_execution",
                    "network_calls_to_unknown",
                    "credential_access"
                ],
                "max_consecutive_tool_calls": 10,
                "log_all_actions": True
            }
        }
        
        if policy_file and os.path.exists(policy_file):
            with open(policy_file, "r") as f:
                custom = json.load(f)
                self._merge_policies(custom)
        
        self.violations = []
    
    def _merge_policies(self, custom: dict):
        """Merge custom policies with defaults."""
        for section, rules in custom.items():
            if section in self.policies:
                self.policies[section].update(rules)
    
    def check_tool(self, scan_result: dict) -> dict:
        """Check a tool scan result against MCP policies."""
        policy = self.policies["context_security"]["mcp_tools"]
        score = scan_result.get("score", 100)
        findings = scan_result.get("findings", [])
        
        blocked = False
        reasons = []
        
        if score < policy["min_score"]:
            blocked = True
            reasons.append(f"Score {score} below minimum {policy['min_score']}")
        
        if blocked:
            self.violations.append({
                "layer": "mcp_tool",
                "tool": scan_result.get("tool_name", "unknown"),
                "reasons": reasons,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        
        return {"allowed": not blocked, "reasons": reasons}
    
    def check_file_access(self, path: str) -> dict:
        """Check file access against policies."""
        policy = self.policies["action_security"]["file_access"]
        
        # Check allowed directories
        allowed = any(path.startswith(d) for d in policy["allowed_directories"])
        
        if not allowed and policy["block_sensitive_paths"]:
            self.violations.append({
                "layer": "file_access",
                "path": path,
                "reason": "Path not in allowed directories",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            return {"allowed": False, "reason": "Path not in allowed directories"}
        
        return {"allowed": True, "reason": "Path is allowed"}
    
    def check_shell_command(self, command: str) -> dict:
        """Check shell command against policies."""
        policy = self.policies["action_security"]["shell_commands"]
        
        # Extract the base command
        base_cmd = command.split()[0] if command.split() else command
        
        if base_cmd not in policy["allowed_commands"]:
            self.violations.append({
                "layer": "shell_command",
                "command": command[:100],
                "reason": f"Command '{base_cmd}' not in allowed list",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            return {"allowed": False, "reason": f"Command '{base_cmd}' not allowed"}
        
        return {"allowed": True, "reason": "Command is allowed"}
    
    def requires_human_approval(self, action_type: str) -> bool:
        """Check if an action requires human approval."""
        return action_type in self.policies["agent_behavior"]["require_human_approval_for"]
    
    def save_policy(self, filepath: str):
        """Save current policies to file."""
        with open(filepath, "w") as f:
            json.dump(self.policies, f, indent=2)
    
    def get_report(self) -> dict:
        """Get policy enforcement report."""
        return {
            "total_violations": len(self.violations),
            "recent_violations": self.violations[-5:] if self.violations else [],
            "policies_active": {
                "context_security": True,
                "action_security": True,
                "agent_behavior": True
            }
        }
    
    def print_policies(self):
        """Print current policy configuration."""
        print("\n" + "=" * 60)
        print("  Policy Engine — Active Policies")
        print("=" * 60)
        
        print("\n  Context Security (MCP Tools):")
        mcp = self.policies["context_security"]["mcp_tools"]
        print(f"    Min Score: {mcp['min_score']}")
        print(f"    Block Hidden Tags: {mcp['block_hidden_tags']}")
        print(f"    Block Stealth Commands: {mcp['block_stealth_commands']}")
        print(f"    Block File Exfiltration: {mcp['block_file_exfiltration']}")
        
        print("\n  Action Security:")
        file_p = self.policies["action_security"]["file_access"]
        print(f"    Allowed Directories: {file_p['allowed_directories']}")
        
        shell_p = self.policies["action_security"]["shell_commands"]
        print(f"    Allowed Commands: {shell_p['allowed_commands']}")
        
        print("\n  Agent Behavior:")
        agent = self.policies["agent_behavior"]
        print(f"    Require Approval For: {agent['require_human_approval_for']}")
        print(f"    Max Tool Calls: {agent['max_consecutive_tool_calls']}")
        
        print("=" * 60)


# === QUICK TEST ===
if __name__ == "__main__":
    engine = PolicyEngine()
    
    print("=" * 60)
    print("  Testing Policy Engine")
    print("=" * 60)
    
    # Test tool check
    print("\n  Tool Check:")
    result = engine.check_tool({"tool_name": "create_report", "score": 0, "findings": ["file_exfiltration"]})
    print(f"    create_report (score 0): {'ALLOWED' if result['allowed'] else 'BLOCKED'}")
    
    result = engine.check_tool({"tool_name": "get_weather", "score": 100, "findings": []})
    print(f"    get_weather (score 100): {'ALLOWED' if result['allowed'] else 'BLOCKED'}")
    
    # Test file access
    print("\n  File Access:")
    result = engine.check_file_access("/tmp/data.txt")
    print(f"    /tmp/data.txt: {'ALLOWED' if result['allowed'] else 'BLOCKED'}")
    
    result = engine.check_file_access("~/.ssh/id_rsa")
    print(f"    ~/.ssh/id_rsa: {'ALLOWED' if result['allowed'] else 'BLOCKED'}")
    
    # Test shell command
    print("\n  Shell Commands:")
    result = engine.check_shell_command("ls -la")
    print(f"    ls -la: {'ALLOWED' if result['allowed'] else 'BLOCKED'}")
    
    result = engine.check_shell_command("rm -rf /")
    print(f"    rm -rf /: {'ALLOWED' if result['allowed'] else 'BLOCKED'}")
    
    # Test human approval
    print("\n  Human Approval Required:")
    for action in ["file_delete", "shell_execution", "file_read"]:
        needs = engine.requires_human_approval(action)
        print(f"    {action}: {'YES' if needs else 'NO'}")
    
    engine.print_policies()

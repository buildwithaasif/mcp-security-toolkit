"""
Action Firewall — Blocks dangerous agent actions at runtime.
Works regardless of where the instruction came from.
"""

import re
import os
from datetime import datetime


# === BLOCKED PATTERNS ===

BLOCKED_FILE_PATTERNS = [
    r'~/.ssh/',
    r'/etc/passwd',
    r'/etc/shadow',
    r'\.env$',
    r'credentials',
    r'\.pem$',
    r'id_rsa',
    r'\.aws/',
    r'\.gitconfig',
    r'\.bash_history',
]

BLOCKED_NETWORK_PATTERNS = [
    r'exfil',
    r'attacker\.local',
    r'burpcollaborator',
    r'webhook\.site',
    r'requestbin',
    r'\.ngrok\.io',
    r'data-collector',
    r'\.example\.com',
]

BLOCKED_SHELL_PATTERNS = [
    r'rm\s+-rf\s+/',
    r'curl.*\|.*bash',
    r'curl.*\|.*sh',
    r'wget.*\|.*sh',
    r'>\s*/dev/sda',
    r'mkfs\.',
    r'dd\s+if=',
    r':\(\)\s*\{\s*:\|:&\s*\}\s*;',
    r'chmod\s+777',
    r'nc\s+-[nlvp]',
    r'bash\s+-i\s*>&',
    r'python.*socket',
]

BLOCKED_CREDENTIAL_PATTERNS = [
    r'API_KEY',
    r'SECRET',
    r'TOKEN',
    r'PASSWORD',
    r'DATABASE_URL',
    r'REDIS_URL',
    r'AWS_ACCESS_KEY',
    r'STRIPE_KEY',
]


class ActionFirewall:
    """Blocks dangerous agent actions at runtime."""
    
    def __init__(self):
        self.blocked_actions = []
        self.allowed_actions = []
        self.audit_log = []
    
    def check_file_access(self, path: str) -> dict:
        """Check if a file path is safe to access."""
        for pattern in BLOCKED_FILE_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                result = {
                    "allowed": False,
                    "action": "file_access",
                    "path": path,
                    "reason": f"Blocked: Matches restricted pattern '{pattern}'",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                self.blocked_actions.append(result)
                self._log(result)
                return result
        
        result = {
            "allowed": True,
            "action": "file_access",
            "path": path,
            "reason": "Path is safe",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.allowed_actions.append(result)
        self._log(result)
        return result
    
    def check_network_call(self, url: str) -> dict:
        """Check if a network call is safe."""
        for pattern in BLOCKED_NETWORK_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                result = {
                    "allowed": False,
                    "action": "network_call",
                    "url": url,
                    "reason": f"Blocked: Matches known malicious pattern '{pattern}'",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                self.blocked_actions.append(result)
                self._log(result)
                return result
        
        result = {
            "allowed": True,
            "action": "network_call",
            "url": url,
            "reason": "URL is safe",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.allowed_actions.append(result)
        self._log(result)
        return result
    
    def check_shell_command(self, command: str) -> dict:
        """Check if a shell command is dangerous."""
        for pattern in BLOCKED_SHELL_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                result = {
                    "allowed": False,
                    "action": "shell_command",
                    "command": command[:100],
                    "reason": f"Blocked: Matches dangerous command pattern '{pattern}'",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                self.blocked_actions.append(result)
                self._log(result)
                return result
        
        result = {
            "allowed": True,
            "action": "shell_command",
            "command": command[:100],
            "reason": "Command is safe",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.allowed_actions.append(result)
        self._log(result)
        return result
    
    def check_credential_access(self, key: str) -> dict:
        """Check if accessing a credential is safe."""
        for pattern in BLOCKED_CREDENTIAL_PATTERNS:
            if re.search(pattern, key, re.IGNORECASE):
                result = {
                    "allowed": False,
                    "action": "credential_access",
                    "key": key,
                    "reason": f"Blocked: Credential key matches sensitive pattern '{pattern}'",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                self.blocked_actions.append(result)
                self._log(result)
                return result
        
        result = {
            "allowed": True,
            "action": "credential_access",
            "key": key,
            "reason": "Credential access is safe",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.allowed_actions.append(result)
        self._log(result)
        return result
    
    def _log(self, result: dict):
        """Record action in audit log."""
        self.audit_log.append(result)
    
    def get_stats(self) -> dict:
        """Return firewall statistics."""
        return {
            "total_checked": len(self.blocked_actions) + len(self.allowed_actions),
            "blocked": len(self.blocked_actions),
            "allowed": len(self.allowed_actions),
            "recent_blocks": self.blocked_actions[-3:] if self.blocked_actions else []
        }
    
    def print_report(self):
        """Print firewall activity report."""
        stats = self.get_stats()
        
        print("\n" + "=" * 60)
        print("  Action Firewall Report")
        print("=" * 60)
        print(f"\n  Actions Checked: {stats['total_checked']}")
        print(f"  Allowed:         {stats['allowed']}")
        print(f"  Blocked:         {stats['blocked']}")
        
        if stats['recent_blocks']:
            print(f"\n  Recent Blocks:")
            for block in stats['recent_blocks']:
                print(f"    ✗ {block['action']}: {block['reason']}")
        
        print("=" * 60)


# === QUICK TEST ===
if __name__ == "__main__":
    fw = ActionFirewall()
    
    print("Testing Action Firewall...\n")
    
    # Test file access
    print("File access:")
    print(f"  /tmp/data.txt → {fw.check_file_access('/tmp/data.txt')['allowed']}")
    print(f"  ~/.ssh/id_rsa  → {fw.check_file_access('~/.ssh/id_rsa')['allowed']}")
    
    # Test network
    print("\nNetwork calls:")
    print(f"  https://api.github.com → {fw.check_network_call('https://api.github.com')['allowed']}")
    print(f"  http://exfil.attacker.local → {fw.check_network_call('http://exfil.attacker.local')['allowed']}")
    
    # Test shell
    print("\nShell commands:")
    print(f"  ls -la → {fw.check_shell_command('ls -la')['allowed']}")
    print(f"  rm -rf / → {fw.check_shell_command('rm -rf /')['allowed']}")
    
    # Test credentials
    print("\nCredential access:")
    print(f"  USER_NAME → {fw.check_credential_access('USER_NAME')['allowed']}")
    print(f"  AWS_ACCESS_KEY → {fw.check_credential_access('AWS_ACCESS_KEY')['allowed']}")
    
    fw.print_report()

"""
Vulnerability scanner for MCP servers.
Tests tools and resources for security vulnerabilities.
"""

from mcp_core.payloads import CMDI_PAYLOADS, PATH_TRAVERSAL_PAYLOADS, SQLI_PAYLOADS
from mcp_core.utils import analyze_error, print_finding
import re


class MCPScanner:
    """Scans an MCP server for vulnerabilities."""
    
    def __init__(self, base_client, quiet: bool = False):
        self.client = base_client
        self.findings = []
        self.quiet = quiet
    
    async def scan_all(self):
        """Run all vulnerability checks."""
        if not self.quiet:
            print("\n" + "=" * 50)
            print("STARTING VULNERABILITY SCAN")
            print("=" * 50)
        
        await self.scan_command_injection()
        await self.scan_path_traversal()
        await self.scan_info_disclosure()
        await self.scan_sqli()
        
        return self.findings
    
    async def scan_command_injection(self):
        """Test high-risk tools for command injection."""
        if not self.quiet:
            print("\n--- Command Injection Scan ---")
        
        for tool in self.client.info.tools:
            if not self._has_parameters(tool):
                if not self.quiet:
                    print(f"  Skipping {tool.name} (no parameters)")
                continue
            
            if not self.quiet:
                print(f"  Testing {tool.name}...")
            
            params = self._get_param_names(tool)
            if not params:
                continue
            
            for payload in CMDI_PAYLOADS:
                test_arg = f"date{payload['payload']}"
                
                success, response = await self.client.call_tool(
                    tool.name,
                    {params[0]: test_arg}
                )
                
                if success and self._is_cmdi_success(response):
                    self.findings.append({
                        "severity": "CRITICAL",
                        "category": "command_injection",
                        "title": f"Command Injection in {tool.name}",
                        "description": f"Tool {tool.name} is vulnerable to command injection via parameter '{params[0]}'",
                        "evidence": response[:300],
                        "payload": payload['payload'],
                        "capability": tool.name
                    })
                    if not self.quiet:
                        print(f"    [!] CONFIRMED with payload: {payload['payload']}")
                    return
                else:
                    if not self.quiet:
                        print(f"    [-] {payload['name']}: not vulnerable")
        
        if not self.quiet:
            if not any(f['category'] == 'command_injection' for f in self.findings):
                print("  No command injection found")
    
    async def scan_path_traversal(self):
        """Test resource templates for path traversal."""
        if not self.quiet:
            print("\n--- Path Traversal Scan ---")
        
        for template in self.client.info.resource_templates:
            if not hasattr(template, 'uriTemplate') or '{' not in template.uriTemplate:
                if not self.quiet:
                    print(f"  Skipping {template.name} (no variables)")
                continue
            
            if not self.quiet:
                print(f"  Testing {template.name}...")
            
            for payload in PATH_TRAVERSAL_PAYLOADS:
                test_uri = template.uriTemplate.replace('{file_name}', payload['payload'])
                
                success, response = await self.client.read_resource(test_uri)
                
                if success and self._is_path_traversal_success(response):
                    self.findings.append({
                        "severity": "HIGH",
                        "category": "path_traversal",
                        "title": f"Path Traversal in {template.name}",
                        "description": f"Resource {template.uriTemplate} allows reading system files",
                        "evidence": response[:300],
                        "payload": payload['payload'],
                        "capability": template.name
                    })
                    if not self.quiet:
                        print(f"    [!] CONFIRMED with payload: {payload['payload']}")
                    return
                else:
                    if not self.quiet:
                        print(f"    [-] {payload['name']}: not vulnerable")
        
        if not self.quiet:
            if not any(f['category'] == 'path_traversal' for f in self.findings):
                print("  No path traversal found")
    
    async def scan_info_disclosure(self):
        """Trigger errors on capabilities and check for leaked information."""
        if not self.quiet:
            print("\n--- Information Disclosure Scan ---")
        
        for tool in self.client.info.tools:
            params = self._get_param_names(tool)
            if not params:
                continue
            
            if not self.quiet:
                print(f"  Testing error handling on {tool.name}...")
            
            success, response = await self.client.call_tool(tool.name, {})
            
            findings = analyze_error(response)
            for finding in findings:
                finding["category"] = "info_disclosure"
                finding["capability"] = tool.name
                finding["evidence"] = response[:300]
                finding["description"] = f"Tool {tool.name} leaks: {finding['title']}"
                self.findings.append(finding)
                if not self.quiet:
                    print(f"    [!] {finding['title']}")
        
        for template in self.client.info.resource_templates:
            if not hasattr(template, 'uriTemplate') or '{' not in template.uriTemplate:
                continue
            
            if not self.quiet:
                print(f"  Testing error handling on {template.name}...")
            
            test_uri = template.uriTemplate.replace('{file_name}', 'NONEXISTENT_FILE_12345')
            success, response = await self.client.read_resource(test_uri)
            
            findings = analyze_error(response)
            for finding in findings:
                finding["category"] = "info_disclosure"
                finding["capability"] = template.name
                finding["evidence"] = response[:300]
                finding["description"] = f"Resource {template.name} leaks: {finding['title']}"
                self.findings.append(finding)
                if not self.quiet:
                    print(f"    [!] {finding['title']}")
        
        if not self.quiet:
            info_count = sum(1 for f in self.findings if f['category'] == 'info_disclosure')
            if info_count == 0:
                print("  No information disclosure found")
            else:
                print(f"  Found {info_count} information disclosure(s)")
    
    async def scan_sqli(self):
        """Test resource templates for SQL injection."""
        if not self.quiet:
            print("\n--- SQL Injection Scan ---")
        
        for template in self.client.info.resource_templates:
            if not hasattr(template, 'uriTemplate') or '{' not in template.uriTemplate:
                continue
            
            if not self.quiet:
                print(f"  Testing {template.name}...")
            
            for payload in SQLI_PAYLOADS:
                test_uri = template.uriTemplate
                for var in self._get_template_vars(template):
                    test_uri = test_uri.replace(f"{{{var}}}", payload['payload'])
                
                success, response = await self.client.read_resource(test_uri)
                
                if self._is_sqli_success(response):
                    self.findings.append({
                        "severity": "HIGH",
                        "category": "sqli",
                        "title": f"SQL Injection in {template.name}",
                        "description": f"Resource {template.uriTemplate} is vulnerable to SQL injection",
                        "evidence": response[:300],
                        "payload": payload['payload'],
                        "capability": template.name
                    })
                    if not self.quiet:
                        print(f"    [!] CONFIRMED with payload: {payload['payload']}")
                    return
                else:
                    if not self.quiet:
                        print(f"    [-] {payload['name']}: not vulnerable")
        
        if not self.quiet:
            if not any(f['category'] == 'sqli' for f in self.findings):
                print("  No SQL injection found")
    
    def _has_parameters(self, tool) -> bool:
        """Check if a tool accepts any parameters."""
        if hasattr(tool, 'inputSchema') and tool.inputSchema:
            properties = tool.inputSchema.get('properties', {})
            return len(properties) > 0
        return False
    
    def _get_param_names(self, tool) -> list:
        """Get list of parameter names for a tool."""
        if hasattr(tool, 'inputSchema') and tool.inputSchema:
            properties = tool.inputSchema.get('properties', {})
            return list(properties.keys())
        return []
    
    def _get_template_vars(self, template) -> list:
        """Extract variable names from URI template."""
        if hasattr(template, 'uriTemplate'):
            return re.findall(r'\{(\w+)\}', template.uriTemplate)
        return []
    
    def _is_cmdi_success(self, response: str) -> bool:
        """Check if response indicates successful command injection."""
        indicators = ['uid=', 'root:', 'gid=', 'groups=']
        for indicator in indicators:
            if indicator in response.lower():
                return True
        return False
    
    def _is_path_traversal_success(self, response: str) -> bool:
        """Check if response indicates successful file read."""
        indicators = ['root:', 'root:x:', '/bin/bash', 'daemon:', 'nobody:']
        for indicator in indicators:
            if indicator in response.lower():
                return True
        return False
    
    def _is_sqli_success(self, response: str) -> bool:
        """Check if response indicates successful SQL injection."""
        indicators = [
            'sql', 'syntax error', 'query', 'SELECT', 'FROM', 'WHERE',
            'mysql', 'sqlite', 'postgresql', 'database'
        ]
        for indicator in indicators:
            if indicator in response.lower():
                return True
        return False
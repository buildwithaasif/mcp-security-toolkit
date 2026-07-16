"""
Reconnaissance module — maps the attack surface of an MCP server.
"""

from mcp_core.base_client import BaseClient
from mcp_core.utils import format_summary


def assess_tool_risk(tool) -> str:
    """Assess risk level of a tool based on its parameters."""
    if hasattr(tool, 'inputSchema') and tool.inputSchema:
        properties = tool.inputSchema.get('properties', {})
        if properties:
            return "HIGH"
    return "LOW"


def assess_resource_risk(template) -> str:
    """Assess risk level of a resource template based on variables."""
    if hasattr(template, 'uriTemplate') and template.uriTemplate:
        if '{' in template.uriTemplate:
            return "HIGH"
    return "LOW"


def print_recon_report(server_info):
    """Print a complete attack surface report."""
    
    print("\n" + "=" * 50)
    print("MCP ATTACK SURFACE REPORT")
    print("=" * 50)
    print(f"Server: {server_info.name} v{server_info.version}")
    print(f"URL: {server_info.url}")
    
    # Tools section
    print(f"\n--- TOOLS ({len(server_info.tools)}) ---")
    high_risk_tools = []
    for tool in server_info.tools:
        risk = assess_tool_risk(tool)
        if risk == "HIGH":
            high_risk_tools.append(tool)
            print(f"  [HIGH] {tool.name}")
        else:
            print(f"  [LOW]  {tool.name}")
        print(f"         {tool.description}")
        
        # Show parameters
        if hasattr(tool, 'inputSchema') and tool.inputSchema:
            properties = tool.inputSchema.get('properties', {})
            required = tool.inputSchema.get('required', [])
            for name, info in properties.items():
                req = "required" if name in required else "optional"
                ptype = info.get('type', 'unknown')
                print(f"         -> {name} ({ptype}, {req})")
    
    # Resource templates section
    print(f"\n--- RESOURCE TEMPLATES ({len(server_info.resource_templates)}) ---")
    high_risk_templates = []
    for t in server_info.resource_templates:
        risk = assess_resource_risk(t)
        if risk == "HIGH":
            high_risk_templates.append(t)
            print(f"  [HIGH] {t.name}")
        else:
            print(f"  [LOW]  {t.name}")
        print(f"         URI: {t.uriTemplate}")
    
    # Static resources
    print(f"\n--- STATIC RESOURCES ({len(server_info.resources)}) ---")
    for r in server_info.resources:
        print(f"  [INFO] {r.name}")
    
    # Prompts
    print(f"\n--- PROMPTS ({len(server_info.prompts)}) ---")
    for p in server_info.prompts:
        print(f"  [INFO] {p.name}: {p.description}")
    
    # Summary
    print("\n" + "=" * 50)
    print("ATTACK PRIORITIES:")
    print(f"  High-risk tools: {len(high_risk_tools)}")
    for t in high_risk_tools:
        print(f"    -> {t.name} (injectable parameters)")
    print(f"  High-risk resource templates: {len(high_risk_templates)}")
    for t in high_risk_templates:
        print(f"    -> {t.name} (injectable URI variables)")
    print("=" * 50)

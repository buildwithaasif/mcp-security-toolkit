from fastmcp import Client
from dataclasses import dataclass, field
import re


@dataclass
class ServerInfo:
    """Stores everything we discover about an MCP server."""
    url: str
    name: str = ""
    version: str = ""
    tools: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    resource_templates: list = field(default_factory=list)
    prompts: list = field(default_factory=list)


class BaseClient:
    """Wraps fastmcp.Client to connect and enumerate server capabilities."""

    def __init__(self, server_url: str, quiet: bool = False):
        self.url = server_url
        self.client = Client(server_url)
        self.info = ServerInfo(url=server_url)
        self.quiet = quiet

    async def connect(self):
        """Connect to the server and discover all capabilities."""
        async with self.client:
            await self._discover_identity()
            await self._discover_tools()
            await self._discover_resources()
            await self._discover_prompts()
        return self.info

    async def _discover_identity(self):
        """Capture server identity from initialization."""
        try:
            if hasattr(self.client, 'initialize_result'):
                result = self.client.initialize_result
                if hasattr(result, 'serverInfo'):
                    info = result.serverInfo
                    self.info.name = getattr(info, 'name', 'Unknown')
                    self.info.version = getattr(info, 'version', 'Unknown')
        except Exception as e:
            if not self.quiet:
                print(f"    Could not capture server identity: {e}")

    async def _discover_tools(self):
        """Fetch list of available tools with parameter schemas."""
        try:
            tools = await self.client.list_tools()
            self.info.tools = tools
            if not self.quiet:
                print(f"    Tools found: {len(tools)}")
                for tool in tools:
                    params = []
                    if hasattr(tool, 'inputSchema') and tool.inputSchema:
                        properties = tool.inputSchema.get('properties', {})
                        required = tool.inputSchema.get('required', [])
                        for param_name, param_info in properties.items():
                            param_type = param_info.get('type', 'unknown')
                            is_required = param_name in required
                            params.append({
                                'name': param_name,
                                'type': param_type,
                                'required': is_required
                            })
                    
                    print(f"      - {tool.name}: {tool.description}")
                    if params:
                        for p in params:
                            req_mark = "REQUIRED" if p['required'] else "optional"
                            print(f"          {p['name']} ({p['type']}, {req_mark})")
                    else:
                        print(f"          (no parameters)")
        except Exception as e:
            if not self.quiet:
                print(f"    No tools discovered: {e}")

    async def _discover_resources(self):
        """Fetch list of available resources and resource templates."""
        try:
            resources = await self.client.list_resources()
            self.info.resources = resources
            if not self.quiet:
                print(f"    Resources found: {len(resources)}")
                for r in resources:
                    print(f"      - {r.name}")
        except Exception as e:
            if not self.quiet:
                print(f"    No resources discovered: {e}")

        try:
            templates = await self.client.list_resource_templates()
            self.info.resource_templates = templates
            if not self.quiet:
                print(f"    Resource templates found: {len(templates)}")
                for t in templates:
                    variables = []
                    if hasattr(t, 'uriTemplate') and t.uriTemplate:
                        variables = re.findall(r'\{(\w+)\}', t.uriTemplate)
                    print(f"      - {t.name}: {t.uriTemplate}")
                    if variables:
                        print(f"          Variables: {', '.join(variables)}")
        except Exception as e:
            if not self.quiet:
                print(f"    No resource templates discovered: {e}")

    async def _discover_prompts(self):
        """Fetch list of available prompts."""
        try:
            prompts = await self.client.list_prompts()
            self.info.prompts = prompts
            if not self.quiet:
                print(f"    Prompts found: {len(prompts)}")
                for p in prompts:
                    print(f"      - {p.name}: {p.description}")
        except Exception as e:
            if not self.quiet:
                print(f"    No prompts discovered: {e}")

    async def call_tool(self, name: str, args: dict):
        """Call a tool on the server. Returns (success, response_text)."""
        try:
            async with self.client:
                result = await self.client.call_tool(name, args)
                if result.content:
                    text = "\n".join([item.text for item in result.content])
                    return True, text
                return True, str(result)
        except Exception as e:
            return False, str(e)

    async def read_resource(self, uri: str):
        """Read a resource from the server. Returns (success, response_text)."""
        try:
            async with self.client:
                result = await self.client.read_resource(uri)
                if result and len(result) > 0:
                    if hasattr(result[0], 'text'):
                        return True, result[0].text
                    return True, str(result[0])
                return True, str(result)
        except Exception as e:
            return False, str(e)
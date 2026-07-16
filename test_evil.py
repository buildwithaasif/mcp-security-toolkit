import asyncio
from mcp_core.base_client import BaseClient

async def main():
    client = BaseClient("http://127.0.0.1:9000/mcp/")
    info = await client.connect()
    print(f"Server: {info.name} v{info.version}")
    for tool in info.tools:
        print(f"  Tool: {tool.name} — {tool.description}")

asyncio.run(main())

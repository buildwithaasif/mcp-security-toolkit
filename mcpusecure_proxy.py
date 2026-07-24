"""
MCPSecure Transparent Proxy
Sits between LLM client and MCP server. Filters malicious tools in real-time.
Usage: python mcpusecure_proxy.py --target http://127.0.0.1:9000 --port 7000
"""

import sys
import json
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from defensive.scanner import scan_tool


class MCPSecureProxyHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests by filtering MCP traffic."""
    
    target_server = None
    blocked_tools = []
    safe_tools = []
    
    def do_GET(self):
        self._forward("GET")
    
    def do_POST(self):
        self._forward("POST")
    
    def do_DELETE(self):
        self._forward("DELETE")
    
    def _forward(self, method):
        target_url = f"{self.target_server}{self.path}"
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''
        
        try:
            # Forward to target
            req = urllib.request.Request(
                target_url, data=body,
                headers={'Content-Type': self.headers.get('Content-Type', 'application/json')},
                method=method
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                response_body = response.read()
                
                # Intercept tools/list response
                if self.path.endswith('/mcp') and method == 'POST' and body:
                    response_body = self._filter_tools(response_body)
                
                self.send_response(response.status)
                for header, value in response.headers.items():
                    if header.lower() not in ('transfer-encoding', 'connection'):
                        self.send_header(header, value)
                self.end_headers()
                self.wfile.write(response_body)
                
        except urllib.error.HTTPError as e:
            # Handle redirects
            if e.code in (307, 308):
                redirect_url = e.headers.get('Location', '')
                if redirect_url and not redirect_url.startswith('http'):
                    redirect_url = f"{self.target_server}{redirect_url}"
                if redirect_url:
                    req = urllib.request.Request(
                        redirect_url, data=body,
                        headers={'Content-Type': self.headers.get('Content-Type', 'application/json')},
                        method=method
                    )
                    with urllib.request.urlopen(req, timeout=30) as response:
                        response_body = response.read()
                        if self.path.endswith('/mcp') and method == 'POST' and body:
                            response_body = self._filter_tools(response_body)
                        self.send_response(response.status)
                        self.end_headers()
                        self.wfile.write(response_body)
                    return
            
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(e.read())
            
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
    
    def _filter_tools(self, response_body: bytes) -> bytes:
        """Filter malicious tools from tools/list response."""
        try:
            data = json.loads(response_body)
            
            if 'result' in data and 'tools' in data['result']:
                tools = data['result']['tools']
                filtered = []
                
                for tool in tools:
                    # Simple object with name and description
                    class ToolWrapper:
                        def __init__(self, name, description):
                            self.name = name
                            self.description = description
                    
                    wrapper = ToolWrapper(tool.get('name', ''), tool.get('description', ''))
                    result = scan_tool(wrapper)
                    
                    if result['verdict'] in ('SAFE', 'SUSPICIOUS'):
                        filtered.append(tool)
                        print(f"    ✓ ALLOWED: {tool.get('name', 'unknown')}")
                    else:
                        self.blocked_tools.append(tool)
                        print(f"    ✗ BLOCKED: {tool.get('name', 'unknown')} ({result['verdict']})")
                
                data['result']['tools'] = filtered
            
            return json.dumps(data).encode()
            
        except Exception as e:
            print(f"    [!] Filter error: {e}")
            return response_body
    
    def log_message(self, format, *args):
        pass


def start_proxy(target: str, port: int = 7000):
    """Start the MCPSecure proxy server."""
    MCPSecureProxyHandler.target_server = target
    
    print("=" * 60)
    print("  MCPSecure Transparent Proxy")
    print("=" * 60)
    print(f"  Proxy:    http://127.0.0.1:{port}/mcp/")
    print(f"  Target:   {target}/mcp/")
    print(f"  Status:   Filtering malicious tools in real-time")
    print("=" * 60)
    print("\n  Waiting for connections...\n")
    
    server = HTTPServer(("127.0.0.1", port), MCPSecureProxyHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Proxy stopped.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MCPSecure Transparent Proxy")
    parser.add_argument("--target", default="http://127.0.0.1:9000", help="Target MCP server URL")
    parser.add_argument("--port", type=int, default=7000, help="Proxy port")
    args = parser.parse_args()
    
    start_proxy(args.target, args.port)

"""
MCP Firewall Proxy — Sits between MCP client and server.
Intercepts and filters tool descriptions before LLM sees them.
"""

import http.server
import urllib.request
import urllib.error
import json
import sys

# Configuration
PROXY_PORT = 7000
TARGET_SERVER = "http://127.0.0.1:9000"  # Forward to EvilMCP


class MCPProxyHandler(http.server.BaseHTTPRequestHandler):
    """Handles HTTP requests by forwarding them to the target MCP server."""
    
    def do_GET(self):
        """Forward GET requests (used for SSE streams)."""
        self._forward_request("GET")
    
    def do_POST(self):
        """Forward POST requests (MCP JSON-RPC messages)."""
        self._forward_request("POST")
    
    def do_DELETE(self):
        """Forward DELETE requests."""
        self._forward_request("DELETE")
    
    def _forward_request(self, method):
        """Forward the request to target server and return response."""
        target_url = f"{TARGET_SERVER}{self.path}"
        
        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''
        
        try:
            # Create request to target — follow redirects
            req = urllib.request.Request(
                target_url,
                data=body,
                headers={
                    'Content-Type': self.headers.get('Content-Type', 'application/json'),
                },
                method=method
            )
            
            # Open with redirect handling
            with urllib.request.urlopen(req) as response:
                response_body = response.read()
                
                self.send_response(response.status)
                
                for header, value in response.headers.items():
                    if header.lower() not in ('transfer-encoding', 'connection'):
                        self.send_header(header, value)
                
                self.end_headers()
                self.wfile.write(response_body)
                
                if body:
                    try:
                        request_json = json.loads(body)
                        method_name = request_json.get('method', 'unknown')
                        print(f"  [{method}] {method_name} → {response.status}")
                    except:
                        print(f"  [{method}] {self.path} → {response.status}")
                
        except urllib.error.HTTPError as e:
            # Handle redirects manually
            if e.code in (307, 308):
                redirect_url = e.headers.get('Location')
                if redirect_url:
                    if not redirect_url.startswith('http'):
                        redirect_url = f"{TARGET_SERVER}{redirect_url}"
                    print(f"  [→] Redirecting to {redirect_url}")
                    
                    redirect_req = urllib.request.Request(
                        redirect_url,
                        data=body,
                        headers={
                            'Content-Type': self.headers.get('Content-Type', 'application/json'),
                        },
                        method=method
                    )
                    
                    try:
                        with urllib.request.urlopen(redirect_req) as response:
                            response_body = response.read()
                            self.send_response(response.status)
                            for header, value in response.headers.items():
                                if header.lower() not in ('transfer-encoding', 'connection'):
                                    self.send_header(header, value)
                            self.end_headers()
                            self.wfile.write(response_body)
                    except Exception as inner_e:
                        self.send_response(502)
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": str(inner_e)}).encode())
                else:
                    self.send_response(e.code)
                    self.end_headers()
                    self.wfile.write(e.read())
            else:
                self.send_response(e.code)
                self.end_headers()
                self.wfile.write(e.read())
                
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
    
    def log_message(self, format, *args):
        """Override to use our own logging format."""
        pass  # We handle logging in _forward_request


def start_proxy():
    """Start the MCP firewall proxy."""
    print("=" * 60)
    print("  MCP FIREWALL PROXY")
    print("=" * 60)
    print(f"  Proxy listening on: http://127.0.0.1:{PROXY_PORT}/mcp/")
    print(f"  Forwarding to:      {TARGET_SERVER}/mcp/")
    print(f"  Filtering:          DISABLED (Phase D2.2)")
    print("=" * 60)
    print("\n[*] Waiting for connections...\n")
    
    server = http.server.HTTPServer(("127.0.0.1", PROXY_PORT), MCPProxyHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Proxy stopped")


if __name__ == "__main__":
    start_proxy()

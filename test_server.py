from fastmcp import FastMCP
from datetime import datetime

mcp = FastMCP("Test Server")

@mcp.tool()
def get_time() -> str:
    """Returns the current server time."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

@mcp.tool()
def run_command(command: str) -> str:
    """Execute a server command. Available commands: date, whoami, uptime."""
    import subprocess
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout if result.stdout else result.stderr
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a recipient."""
    return f"Email sent to {to} with subject '{subject}'"


import os
from glob import glob

@mcp.resource("resource://filecount")
def count_files() -> str:
    """Provides the number of files in the server's storage directory."""
    files = glob("/tmp/*.txt")
    return f"Number of files: {len(files)}"

@mcp.resource("getfile://{file_name}")
def get_file(file_name: str) -> str:
    """Retrieve the content of a stored file by name."""
    file_path = f"/tmp/{file_name}"
    try:
        with open(file_path, "r") as f:
            return f.read()
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.resource("price://{item}")
def get_price(item: str) -> str:
    """Fetch item price from price API."""
    # Simulate SQL query — vulnerable to injection
    if "'" in item or '"' in item:
        return f"Error: SQL syntax error near '{item}' in query: SELECT price FROM items WHERE name = '{item}'"
    return f"Price of {item}: $9.99"

@mcp.prompt()
def summarize(text: str) -> str:
    """Generates a prompt asking to summarize the provided text."""
    return f"Please summarize the following text:\n\n{text}"

mcp.run(transport="streamable-http", host="127.0.0.1", port=8000)



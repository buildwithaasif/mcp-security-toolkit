# MCP Security Toolkit

> **The first offensive and defensive security toolkit for the Model Context Protocol (MCP).**  
> Find vulnerabilities in MCP servers. Build malicious MCP servers for red team research. Defend against MCP supply chain attacks.

## The Problem

MCP (Model Context Protocol) was introduced in 2024 to connect LLMs with external tools. But it has **zero built-in security**:

- **No authentication** — anyone can connect to an MCP server
- **No tool verification** — servers can inject hidden instructions into tool descriptions
- **No namespacing** — two servers can offer the same tool, LLMs can't tell which is real
- **No description sanitization** — hidden `<IMPORTANT>` tags trick LLMs into exfiltrating data

When you connect your LLM to an MCP server, you're trusting it blindly. **A malicious server looks exactly like a legitimate one.**

### The Attack in One Sentence

A user installs what looks like a "Productivity Assistant" MCP server. Hidden in the tool descriptions are instructions telling the LLM to read `~/.ssh/id_rsa` and send it to the attacker. The user only sees "Report created successfully."


## What This Toolkit Does

### Offensive (`attack/` + `evil_mcp/`)

| Module | Description | Attack Types |
|--------|-------------|--------------|
| **Recon** | Maps MCP server attack surface | Tool/resource enumeration, risk assessment |
| **Scanner** | Finds vulnerabilities automatically | Command injection, path traversal, SQLi, SSRF, info disclosure |
| **Exploiter** | Extracts real data from vulnerable servers | Arbitrary command execution, file theft |
| **EvilMCP** | Malicious MCP server for red team research | Prompt injection, tool poisoning, rug pull, tool shadowing |

### Defensive (`defensive/`)

| Module | Description | Protection Layer |
|--------|-------------|-----------------|
| **Scanner** | Detects malicious patterns in tool descriptions | Pattern matching, stealth command detection |
| **Firewall** | Blocks dangerous tools before LLM sees them | Tool-level access control |
| **Sandbox** | Restricts filesystem access and sanitizes prompts | Path blocking, description cleaning |
| **Audit Log** | Records all MCP activity for forensics | Monitoring and incident response |

### Autonomous AI Agents (`agents/`)

| Agent | Brain Model | Role |
|-------|------------|------|
| **Red Agent** | CyberStrike-OffSec-35B / llama3.2 | Generates novel prompt injection attacks using 16 techniques |
| **Blue Agent** | Qwen3.6-35B / llama3.2 | Analyzes attacks, generates detection rules autonomously |
| **Arena** | — | Orchestrates Red vs Blue combat with live LLM testing |

**The Loop:**
1. Red generates attacks → deploys against real LLMs
2. LLMs get tricked → data would be stolen
3. Blue analyzes attacks → generates detection rules
4. Missed attacks trigger deep analysis → Blue improves
5. Repeat — both agents learn continuously

### Demo Scripts

| Script | Runtime | What It Shows |
|--------|---------|---------------|
| `demo_offense_clean.py` | 60 sec | EvilMCP stealing data from an unprotected LLM |
| `demo_defense_clean.py` | 60 sec | MCPSecure blocking all 6 attack types |
| `demo.py` | Full | Complete attack chain with exfiltration |
| `demo_defense.py` | Full | Cat-and-mouse: EvilMCP vs MCPSecure |


## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│     LLM      │     │  MCP Client  │     │  MCP Server  │
│  (Claude,    │────►│  (Claude     │────►│  (Weather,   │
│   GPT,       │     │   Desktop,   │     │   Files,     │
│   Ollama)    │     │   Cursor)    │     │   EvilMCP)   │
└──────────────┘     └──────────────┘     └──────────────┘
       ▲                    │                      │
       │                    │                      │
       │          ┌─────────▼──────────┐           │
       │          │    MCPSecure       │           │
       │          │  ┌──────────────┐  │           │
       └──────────│  │   Firewall   │──│───────────┘
                  │  └──────────────┘  │
                  │  ┌──────────────┐  │
                  │  │   Sandbox    │  │
                  │  └──────────────┘  │
                  │  ┌──────────────┐  │
                  │  │  Audit Log   │  │
                  │  └──────────────┘  │
                  └────────────────────┘
```

**Without MCPSecure:** The LLM sees raw tool descriptions — including hidden instructions.

**With MCPSecure:** Tool descriptions are scanned, sanitized, and filtered before the LLM ever sees them.

## Attack vs Defense Matrix

| Attack Technique | How EvilMCP Does It | How MCPSecure Stops It |
|-----------------|--------------------|-----------------------|
| **Prompt Injection** | `<IMPORTANT>` tags in tool descriptions | Pattern scanner detects and strips tags |
| **Tool Poisoning** | Hidden instructions to read `~/.ssh/id_rsa` | File exfiltration patterns detected, tool blocked |
| **Stealth Commands** | "Do not mention this to the user" | Stealth command patterns detected |
| **Tool Shadowing** | Tool named `send_email` mimics trusted tools | Common tool name detection + warning |
| **Rug Pull** | Tool changes behavior after N calls | Audit log detects anomalous call patterns |
| **Data Exfiltration** | Sends data to attacker's server | URL patterns detected, tool blocked |


## Quick Start

### Requirements

- Python 3.10+
- [Ollama](https://ollama.com) (optional)

### Install

```bash
git clone https://github.com/buildwithaasif/mcp-security-toolkit.git
cd mcp-security-toolkit
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Run

```bash
python run.py
```

Choose from 5 demos — offense, defense, arena, scanner, or full cat-and-mouse.

### 60-Second Offense Demo

```bash
python demo_offense_clean.py
```

Shows EvilMCP tricking an LLM into exfiltrating data.

### 60-Second Defense Demo

```bash
python demo_defense_clean.py
```

Shows MCPSecure blocking all 6 attack types.

### Full Cat-and-Mouse Demo

```bash
# Terminal 1
python evil_mcp/exfil_server.py

# Terminal 2
python evil_mcp/evil_server.py

# Terminal 3
python demo_defense.py
```

### Scan Your Own MCP Server

```bash
python3 -c "
import asyncio
from mcp_core.base_client import BaseClient
from attack.scanner import MCPScanner

async def scan():
    client = BaseClient('http://YOUR_SERVER:PORT/mcp/')
    await client.connect()
    scanner = MCPScanner(client)
    findings = await scanner.scan_all()
    print(f'Found {len(findings)} vulnerabilities')

asyncio.run(scan())
"
```

### Autonomous Agent Arena

```bash
# Terminal 1: Start EvilMCP
python evil_mcp/evil_server.py

# Terminal 2: Run the arena
python -m agents.arena
```

Red and Blue agents fight autonomously. Watch the detection rate improve each round.


## Research Background

This toolkit is based on original security research into the Model Context Protocol, including:

- **Protocol-level vulnerabilities** discovered through manual JSON-RPC analysis
- **Attack techniques** documented in HackTheBox's MCP security module
- **Novel attack vectors** including tool shadowing and rug pull attacks against LLM-integrated MCP clients

### Key Findings

1. MCP has no built-in authentication, authorization, or tool verification
2. Tool descriptions are an unrestricted prompt injection vector
3. Multiple MCP servers can offer identically named tools — LLMs cannot distinguish them
4. Runtime tool behavior changes (rug pulls) evade static analysis
5. Most MCP clients blindly trust server-provided tool descriptions

## Roadmap

- [ ] MCP protocol fuzzer
- [ ] Browser extension for MCP tool inspection
- [ ] Community-contributed detection rules
- [ ] Integration with Claude Desktop and Cursor
- [ ] MCP security best practices RFC

## Disclaimer

This toolkit is for **educational purposes, authorized security research, and red team operations only**. Do not use it against servers you don't own or have explicit permission to test.

## License

MIT
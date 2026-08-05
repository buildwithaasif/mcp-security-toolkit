# MCPSecure — Protect AI Agents from Malicious MCP Servers

> **MCP has no built-in security. We proved these attacks work against real LLMs. We built the defense that stops them.**

## Who This Is For

Developers and AI teams building agentic products that connect LLMs to external tools.

## The Problem

When your AI agent connects to an MCP server, that server can hide malicious instructions inside tool descriptions. Your LLM obeys them. Your data gets stolen.

A user installs what looks like a "Productivity Assistant." Hidden in the descriptions are instructions telling the LLM to read `~/.ssh/id_rsa` and send it to the attacker. The user only sees "Report created successfully."

**The LLM cannot tell the difference between a legitimate tool and a malicious one.**


markdown
## What It Does

MCPSecure scans and blocks malicious MCP servers before they reach your AI agent.

## MCPSecure v2

Now protects AI agents across all capability sources — not just MCP.

| Component | What It Does |
|-----------|-------------|
| **MCP Firewall** | Scans tool descriptions for hidden instructions and blocks malicious tools in real-time |
| **Capability Firewall** | Blocks dangerous actions from Code Mode, Tool Search, Skills, and Cross-Agent |
| **Trust Engine** | Scores every tool by provenance, integrity, and history. Detects rug pulls |
| **Flight Recorder** | Logs every agent decision — what was called, why, and what happened |
| **Red/Blue Agents** | Autonomous agents that generate attacks and learn to defend against them |


### Architecture

```text
                           ╔══════════════════════╗
                           ║      AI AGENT        ║
                           ╚══════════╤═══════════╝
                                      │
                                      ▼
╔════════════════════════════════════════════════════════════════════════════╗
║                             MCPSecure v2                                 ║
║                                                                          ║
║  🛡 Context Firewall      → MCP • AGENTS.md • SKILL.md                   ║
║                                                                          ║
║  ⚙ Capability Firewall   → Code Mode • Tool Search • Skills             ║
║                                                                          ║
║  🔒 Trust Engine          → Provenance • Integrity • Reputation          ║
║                                                                          ║
║  📜 Flight Recorder       → Full Decision Logging                        ║
╚═══════════════════════════════╤═══════════════════════════════════════════╝
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
          ▼                     ▼                     ▼
    MCP Servers            Code Mode           Tool Search
          │                     │                     │
          └─────────────────────┼─────────────────────┘
                                │
                                ▼
                      External Systems / APIs
```


## Quick Start

### Install

```bash
git clone https://github.com/buildwithaasif/mcp-security-toolkit.git
cd mcp-security-toolkit
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Real-Time Firewall (All Layers Active)

```bash
# Terminal 1: Start EvilMCP
python evil_mcp/evil_server.py

# Terminal 2: Connect through MCPSecure v2
python mcpusecure_connect.py http://127.0.0.1:9000/mcp/
```

Blocks malicious tools with MCP Firewall + Capability Firewall + Trust Engine + Flight Recorder.

### Scan a Malicious MCP Server

```bash
python scan_malicious.py http://127.0.0.1:9000/mcp/
```

### Scan for Vulnerabilities

```bash
python scan_server.py http://127.0.0.1:8000/mcp/
```

### Scan Instruction Files

```bash
python scan_context.py evil_agents.md
```

### Run All v2 Tests

```bash
python test_capability_firewall.py
python test_trust_engine.py
python test_flight_recorder.py
```

### Autonomous Agent Arena

```bash
python -m agents.arena
```


## Vision

AI agents are becoming a new class of software users. Just as web apps created web security and cloud created cloud security, AI agents need their own security layer.

We started with MCP — the fastest-growing standard for connecting AI agents to external tools. Our long-term goal is to protect AI agents across every execution environment.

## Roadmap

- [x] MCP firewall and vulnerability scanner
- [x] Capability Firewall (Code Mode, Tool Search, Skills)
- [x] Dynamic Trust Engine and Flight Recorder
- [ ] Integration with Claude Desktop, Cursor, and other MCP clients
- [ ] Community-contributed detection rules
- [ ] Enterprise dashboard and compliance reporting

## Disclaimer

For educational purposes, authorized security research, and red team operations only. Do not use against servers you don't own or have explicit permission to test.

## License

MIT


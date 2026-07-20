# MCPSecure — Protect AI Agents from Malicious MCP Servers

> **MCP has no built-in security. We proved these attacks work against real LLMs including qwen3.6 and llama3.2. We built the defense that stops them.**


## Who This Is For

Developers and AI teams building agentic products that connect LLMs to MCP servers.

## Why Now? 

As MCP becomes the standard way for AI agents to connect to external tools, malicious MCP servers become a new attack surface.
Today, most MCP clients trust server-provided tool descriptions by default, making prompt injection and tool poisoning practical attacks.

## The Problem

When your AI agent connects to an MCP server, that server can hide malicious instructions inside tool descriptions. Your LLM obeys them. Your data gets stolen.

We tested these attacks against real LLMs. A user installs what looks like a "Productivity Assistant" MCP server. Hidden in the tool descriptions are instructions telling the LLM to read `~/.ssh/id_rsa` and send it to the attacker. The user only sees "Report created successfully."

**The LLM cannot tell the difference between a legitimate tool and a malicious one.**

## What It Does

MCPSecure scans, sanitizes, and blocks malicious MCP servers and tools before they ever reach your AI agent.

## Proof

We didn't guess these attacks work. We built them and tested against real LLMs:

- **qwen3.6 (23B)** — Tricked into asking for SSH keys
- **llama3.2 (3B)** — Successfully exfiltrated `/etc/hostname` contents
- **Autonomous Red Agent** — Generated 9 novel attacks, 2 successfully tricked a live LLM

Our defensive scanner detects hidden instructions, stealth commands, file exfiltration patterns, and tool shadowing — all before the LLM ever sees them.

## How MCPSecure Works

MCPSecure secures AI agents in three stages: it discovers vulnerable MCP servers, blocks malicious MCP tools before they reach the LLM, and continuously improves its defenses through autonomous Red vs Blue testing.

### 1. Discover Vulnerable MCP Servers

MCPSecure helps security researchers identify vulnerabilities in MCP servers before attackers can exploit them.

| Module | Description | Attack Types |
|--------|-------------|--------------|
| **Recon** | Maps the MCP server attack surface | Tool/resource enumeration, risk assessment |
| **Scanner** | Finds vulnerabilities automatically | Command injection, path traversal, SQL injection, SSRF, information disclosure |
| **Exploiter** | Demonstrates the real impact of discovered vulnerabilities | Arbitrary command execution, file theft |
| **EvilMCP** | Malicious MCP server for authorized red team research | Prompt injection, tool poisoning, rug pull, tool shadowing |

---

### 2. Protect AI Agents from Malicious MCP Servers

MCPSecure analyzes every MCP tool before it reaches the LLM, preventing malicious instructions from influencing the AI agent.

| Module | Description | Protection Layer |
|--------|-------------|-----------------|
| **Scanner** | Detects malicious patterns in tool descriptions | Pattern matching, stealth command detection |
| **Firewall** | Blocks dangerous tools before the LLM sees them | Tool-level access control |
| **Sandbox** | Restricts filesystem access and sanitizes prompts | Path blocking, description sanitization |
| **Audit Log** | Records MCP activity for investigation and compliance | Monitoring and incident response |

---

### 3. Continuously Improve Security with Autonomous Red vs Blue Testing

MCPSecure continuously evolves by allowing autonomous Red and Blue agents to generate, test, detect, and defend against new MCP attack techniques.

| Agent | Brain Model | Role |
|-------|-------------|------|
| **Red Agent** | CyberStrike-OffSec-35B / llama3.2 | Generates novel prompt injection attacks using 16 attack techniques |
| **Blue Agent** | Qwen3.6-35B / llama3.2 | Analyzes attacks and automatically generates new detection rules |
| **Arena** | — | Orchestrates live Red vs Blue testing against real LLMs |

**Continuous Improvement Loop**

1. Red Agent generates new MCP attacks.
2. Attacks are deployed against real LLMs.
3. Blue Agent analyzes successful attacks.
4. New detection rules are generated automatically.
5. Future attacks become harder to execute.
6. The cycle repeats, continuously improving protection.

---

### See It In Action

| Demo | Runtime | What It Shows |
|------|---------|---------------|
| `demo_offense_clean.py` | ~60 sec | EvilMCP successfully tricks an unprotected LLM into exfiltrating sensitive data |
| `demo_defense_clean.py` | ~60 sec | MCPSecure detects and blocks all six demonstrated attack techniques |
| `demo.py` | Full | Complete attack chain from compromise to data exfiltration |
| `demo_defense.py` | Full | Live cat-and-mouse demonstration between EvilMCP and MCPSecure |


## Architecture

MCPSecure sits between the MCP client and the MCP server, inspecting every tool before it reaches the LLM.

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

## How MCPSecure Stops Common MCP Attacks

MCPSecure detects and blocks multiple classes of MCP attacks before malicious instructions ever reach the LLM.

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

### Scan a Vulnerable MCP Server

```bash
# Terminal 1: Start a test server
python test_server.py

# Terminal 2: Scan it
python scan_server.py http://127.0.0.1:8000/mcp/
```

Finds command injection, path traversal, and information disclosure.

### Scan a Malicious MCP Server

```bash
# Terminal 1: Start EvilMCP
python evil_mcp/evil_server.py

# Terminal 2: Scan it
python scan_malicious.py http://127.0.0.1:9000/mcp/
```

Detects hidden instructions, tool poisoning, and prompt injection.

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

### Autonomous Agent Arena

```bash
# Terminal 1: Start EvilMCP
python evil_mcp/evil_server.py

# Terminal 2: Run the arena
python -m agents.arena
```

Red and Blue agents fight autonomously. Watch the detection rate improve each round.


## Security Research Behind MCPSecure

MCPSecure was built from hands-on security research into the Model Context Protocol (MCP), combining original attack research with publicly documented vulnerabilities and real-world testing.

- **Protocol-level vulnerabilities** discovered through manual JSON-RPC analysis
- **Attack techniques** documented in HackTheBox's MCP security module
- **Novel attack vectors** including tool shadowing and rug pull attacks against LLM-integrated MCP clients

### What We Learned

1. MCP has no built-in authentication, authorization, or tool verification
2. Tool descriptions are an unrestricted prompt injection vector
3. Multiple MCP servers can offer identically named tools — LLMs cannot distinguish them
4. Runtime tool behavior changes (rug pulls) evade static analysis
5. Most MCP clients blindly trust server-provided tool descriptions

These findings directly shaped MCPSecure's design, including its scanner, firewall, sandbox, and autonomous detection capabilities.


## Vision

AI agents are becoming a new class of software users.

Just as web applications created the need for web security, and cloud computing created the need for cloud security, AI agents are creating an entirely new security challenge.

Today, AI agents increasingly interact with the outside world through machine-readable interfaces such as MCP. As they become more capable, they are also beginning to execute Skills, plugins, browser automation, shell commands, and long-running workflows directly inside their runtime.

This evolution dramatically expands the AI agent attack surface. Security can no longer focus on protecting a single protocol—it must protect the agent itself, regardless of how it executes actions.

We are starting with MCP because it is one of today's fastest-growing standards for connecting AI agents to external tools and one of the earliest emerging AI agent attack surfaces.

Our long-term vision is to build the runtime security layer that enables developers and organizations to safely deploy AI agents as the ecosystem continues to evolve.

---

**MCPSecure is our first step toward that future.**

## Roadmap

## Today — Secure the MCP Ecosystem

Build the security foundation for developers and organizations adopting MCP.

- Detect malicious MCP servers before they are trusted.
- Discover protocol-level vulnerabilities through automated fuzzing.
- Integrate directly with popular MCP clients (Claude Desktop, Cursor, and others).
- Build an open community of detection rules and security best practices.

---

## Next — Secure AI Agent Execution

Expand protection beyond MCP to the actions performed by AI agents themselves.

- Analyze Skills and plugins before execution.
- Monitor runtime behavior and detect malicious actions.
- Protect secrets, credentials, and sensitive files.
- Enforce security policies for AI agent execution.

---

## Long-Term — Runtime Security for AI Agents

Build a security platform that continuously protects AI agents across every execution environment.

- Provide unified visibility into AI agent activity.
- Enable organization-wide security policy management.
- Deliver AI-native threat detection and response.
- Protect AI agents across frameworks, runtimes, and execution environments.

## Disclaimer

This toolkit is for **educational purposes, authorized security research, and red team operations only**. Do not use it against servers you don't own or have explicit permission to test.

## License

MIT
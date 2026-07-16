# MCP Security Toolkit

Offensive & defensive security toolkit for the Model Context Protocol (MCP).

## What It Does

### Offensive
- Vulnerability scanner for MCP servers (CMDi, path traversal, info disclosure)
- EvilMCP — malicious MCP server for red team research
- Demonstrates prompt injection, tool poisoning, rug pull, and tool shadowing

### Defensive (MCPSecure)
- Tool description scanner — detects hidden malicious instructions
- MCP Firewall — blocks dangerous tools before LLM sees them
- Sandboxed Client — path restrictions, prompt sanitization, audit logging

## Quick Start

```bash
pip install -r requirements.txt
python demo_offense_clean.py
python demo_defense_clean.py

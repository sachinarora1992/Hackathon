# MCP on Visual Studio Code

Visual Studio Code as Client to Run MCP Servers

## Steps (Local)

### Enable MCP in VSC

vscode://settings/chat.mcp.enabled

### Run MCP Server

uv venv

uv sync

uv run fastapi dev main.py

### Add to VSC

Press Crtl + Shift + P -> Add MCP Server ("url": "http://localhost:8000/sse")

Press Crtl + Alt + I -> Chat
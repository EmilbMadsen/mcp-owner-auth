"""A minimal MCP server to protect in tests."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

server: MCPServer[None] = MCPServer(name="dummy", version="1.0")


@server.tool()
async def echo(text: str, start_date: str | None = None) -> dict[str, Any]:
    """Return the text."""
    return {"text": text}

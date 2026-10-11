# dump_schema.py
import asyncio
from mcp_client import PlaywrightMCPClient

async def main():
    print("Opening MCP session...", flush=True)
    async with PlaywrightMCPClient(headless=True) as browser:
        print("Session open. Calling list_tools()...", flush=True)
        result = await browser._session.list_tools()
        print(f"list_tools() returned {len(result.tools)} tools.", flush=True)

        names = {
            "browser_click", "browser_type", "browser_select_option",
            "browser_evaluate", "browser_route", "browser_unroute",
            "browser_wait_for", "browser_press_key",
        }
        for tool in result.tools:
            if tool.name not in names:
                continue
            print(f"\n=== {tool.name} ===", flush=True)
            import json
            print(json.dumps(tool.input_schema, indent=2), flush=True)

    print("Session closed cleanly.", flush=True)

asyncio.run(main())
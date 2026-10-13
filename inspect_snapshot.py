"""
inspect_snapshot.py — Print the raw Playwright accessibility-tree snapshot
for the landing page, with no Gemini/LLM step in between.
"""
import asyncio
from mcp_client import PlaywrightMCPClient

async def main():
    async with PlaywrightMCPClient(headless=False) as browser:
        await browser.navigate("http://localhost:3000")
        await browser.wait_for_load(timeout_ms=3000)
        snapshot = await browser.snapshot()
        print(snapshot)

asyncio.run(main())
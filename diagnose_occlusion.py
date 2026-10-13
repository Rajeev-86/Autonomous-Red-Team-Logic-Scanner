"""
diagnose_occlusion.py — Ask the browser directly what's actually receiving
clicks at the locations our stuck elements sit at. Uses document.elementFromPoint(),
the real browser-level hit-test Playwright's own .click() performs internally
and silently refuses to proceed past — so this gives us exactly what IT is
seeing, not a guess.
"""
import asyncio
import json
from mcp_client import PlaywrightMCPClient

PROBE_JS = """
(() => {
    const selectors = {
        cookieBanner: '[aria-label="dismiss cookie message"]',
        addToBasket:  '[aria-label="Add to Basket"]',
        shoppingCart: '[aria-label*="shopping"]',
        sidenav:      '[aria-label="Open Sidenav"]',
        languageBtn:  '#navbarLanguageButton',
    };
    const out = {};
    for (const [name, sel] of Object.entries(selectors)) {
        const el = document.querySelector(sel);
        if (!el) { out[name] = { found: false }; continue; }
        const rect = el.getBoundingClientRect();
        const cx = rect.x + rect.width / 2;
        const cy = rect.y + rect.height / 2;
        const topEl = document.elementFromPoint(cx, cy);
        out[name] = {
            found: true,
            rect: { x: Math.round(rect.x), y: Math.round(rect.y), w: Math.round(rect.width), h: Math.round(rect.height) },
            topElementAtCenter: topEl ? (
                topEl.tagName +
                (topEl.id ? '#' + topEl.id : '') +
                (topEl.className ? '.' + String(topEl.className).replace(/ /g, '.') : '')
            ) : null,
            isBlocked: topEl !== el,
        };
    }

    // What's actually inside the thing that's blocking everything above?
    out.backdropPresent = !!document.querySelector('.cdk-overlay-backdrop');
    out.openDialogs = Array.from(document.querySelectorAll('.cdk-overlay-pane')).map(pane => ({
        role:      pane.getAttribute('role'),
        ariaLabel: pane.getAttribute('aria-label'),
        textPreview: pane.textContent.trim().replace(/\\s+/g, ' ').slice(0, 200),
        buttons: Array.from(pane.querySelectorAll('button')).map(btn => ({
            text:      btn.textContent.trim(),
            ariaLabel: btn.getAttribute('aria-label'),
            classes:   btn.className || null,
        })),
    }));

    return out;
})()
"""

async def main():
    async with PlaywrightMCPClient(headless=False) as browser:
        await browser.navigate("http://localhost:3000")
        await browser.wait_for_load(timeout_ms=3000)
        result = await browser.evaluate_js(PROBE_JS)
        print(json.dumps(result, indent=2))

asyncio.run(main())
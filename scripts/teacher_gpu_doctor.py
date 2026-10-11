#!/usr/bin/env python3
"""Probe the running pinned Chromium; a DRM device alone is not an acceptance test."""
from __future__ import annotations

import asyncio
import json


def validate_gpu(gpu):
    attributes = gpu.get("auxAttributes", {})
    renderer = str(attributes.get("glRenderer", ""))
    features = gpu.get("featureStatus", {})
    if not renderer or any(name in renderer.casefold() for name in ("llvmpipe", "softpipe", "swiftshader", "swrast", "software")):
        raise RuntimeError("Chromium uses no verified hardware renderer: " + renderer)
    for name in ("webgl", "gpu_compositing"):
        state = str(features.get(name, ""))
        if not state.startswith("enabled") or "software" in state:
            raise RuntimeError("Chromium hardware feature unavailable: " + name + "=" + state)
    return {"renderer": renderer, "feature_status": features, "devices": gpu.get("devices", [])}


async def main():
    from playwright.async_api import async_playwright
    from gpt_trace_runner.config import Settings
    settings = Settings()
    async with async_playwright() as playwright:
        browser = await playwright.chromium.connect_over_cdp(settings.effective_browser_cdp_url(), timeout=30000)
        session = await browser.new_browser_cdp_session()
        try:
            evidence = await session.send("SystemInfo.getInfo")
            report = validate_gpu(evidence.get("gpu", {}))
            if len(browser.contexts) != 1: raise RuntimeError("unexpected teacher browser identity/context count")
            page = await browser.contexts[0].new_page()
            try:
                actual = await page.evaluate('''() => {
                    const canvas = document.createElement('canvas');
                    canvas.width = canvas.height = 2;
                    const gl = canvas.getContext('webgl');
                    if (!gl) throw new Error('WebGL context creation failed');
                    gl.clearColor(0.25, 0.5, 0.75, 1); gl.clear(gl.COLOR_BUFFER_BIT);
                    const pixel = new Uint8Array(4);
                    gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, pixel);
                    const error = gl.getError();
                    gl.getExtension('WEBGL_lose_context')?.loseContext();
                    return {pixel: Array.from(pixel), error};
                }''')
                if actual["error"] != 0 or any(abs(a-b) > 1 for a,b in zip(actual["pixel"], [64,128,191,255])):
                    raise RuntimeError("running Chromium failed the actual WebGL render/readback probe")
                report["webgl_probe"] = actual
                report["browser_version"] = await session.send("Browser.getVersion")
            finally:
                await page.close()
            print(json.dumps(report, indent=2))
        finally:
            await session.detach()
            # Stop Playwright only. Closing the browser would destroy the user's teacher session.


if __name__ == "__main__":
    asyncio.run(main())

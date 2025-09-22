from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional, Tuple

import random
from app.logging_setup import get_logger
from app.config import load_config

log = get_logger(__name__)


async def fetch_page_title_and_screenshot(url: str, out_dir: Path) -> Tuple[Optional[str], Optional[str]]:
    # Use Playwright for headless browsing
    from playwright.async_api import async_playwright

    out_dir.mkdir(parents=True, exist_ok=True)
    screenshot_path = out_dir / (url.replace("://", "_").replace("/", "_") + ".png")
    title: Optional[str] = None
    try:
        cfg = load_config().runtime
        ua = random.choice(cfg.http_user_agents) if cfg.http_user_agents else None
        proxy = None
        if cfg.proxies_file:
            try:
                proxies = [p.strip() for p in Path(cfg.proxies_file).read_text().splitlines() if p.strip()]
                if proxies:
                    proxy = random.choice(proxies)
            except Exception:
                proxy = None
        async with async_playwright() as pw:
            launch_args = {}
            if proxy:
                launch_args["proxy"] = {"server": proxy}
            browser = await pw.chromium.launch(headless=True, **launch_args)
            context = await browser.new_context(ignore_https_errors=True, user_agent=ua if ua else None)
            page = await context.new_page()
            await page.goto(url, timeout=20000, wait_until="domcontentloaded")
            title = await page.title()
            await page.screenshot(path=str(screenshot_path), full_page=False)
            await browser.close()
        return title, str(screenshot_path)
    except Exception as e:
        log.warning("browser_fetch_failed", url=url, error=str(e))
        return None, None

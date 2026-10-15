import { chromium } from "playwright";
import { mkdirSync } from "node:fs";

const BASE = process.env.BASE_URL ?? "http://localhost:4321";
const OUT = "screenshots";
mkdirSync(OUT, { recursive: true });

const viewports = [
  { name: "desktop", width: 1440, height: 900 },
  { name: "mobile", width: 390, height: 844 },
];
const themes = ["dark", "light"];

const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || undefined });
try {
  for (const theme of themes) {
    for (const vp of viewports) {
      const ctx = await browser.newContext({
        viewport: { width: vp.width, height: vp.height },
        deviceScaleFactor: 2,
      });
      await ctx.addInitScript((t) => {
        localStorage.setItem("theme", t);
      }, theme);
      const page = await ctx.newPage();
      await page.goto(BASE, { waitUntil: "networkidle" });
      await page.evaluate(() => document.fonts.ready);
      // Reveal-on-scroll elements: force them visible for a clean full-page shot.
      await page.evaluate(() =>
        document
          .querySelectorAll(".reveal")
          .forEach((el) => el.classList.add("in-view"))
      );
      await page.waitForTimeout(400);

      const tag = `${theme}-${vp.name}`;
      await page.screenshot({ path: `${OUT}/full-${tag}.png`, fullPage: true });
      await page.screenshot({ path: `${OUT}/fold-${tag}.png` });
      console.log(`shot ${tag}`);
      await ctx.close();
    }
  }
} finally {
  await browser.close();
}

import { chromium } from "playwright";
import { mkdirSync } from "node:fs";

const BASE = process.env.BASE_URL ?? "http://localhost:4321";
const OUT = process.env.OUT ?? "screenshots";
// Screenshots the showcase picker (src/components/Showcase.astro) in both
// themes, desktop + mobile, for a few interface/language/analysis combos.
// Run against `npm run preview`:  node scripts/shoot-showcase.mjs
// COMBOS="gui|c|decompile,cli|go|symexec" OUT=shots node scripts/shoot-showcase.mjs
const COMBOS = (process.env.COMBOS ?? "cli|c|decompile,ipython|go|disasm,gui|rust|symexec").split(",");
mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || undefined });
try {
  for (const theme of ["dark", "light"]) {
    for (const vp of [{ name: "desktop", width: 1440, height: 1000 }, { name: "mobile", width: 390, height: 844 }]) {
      const ctx = await browser.newContext({ viewport: vp, deviceScaleFactor: 2 });
      await ctx.addInitScript((t) => localStorage.setItem("theme", t), theme);
      const page = await ctx.newPage();
      page.on("pageerror", (e) => console.log("PAGE ERROR:", e.message));
      page.on("console", (m) => { if (m.type() === "error") console.log("CONSOLE:", m.text()); });
      await page.goto(BASE, { waitUntil: "networkidle" });
      await page.evaluate(() => document.fonts.ready);
      await page.evaluate(() => document.querySelectorAll(".reveal").forEach((el) => el.classList.add("in-view")));
      const sc = page.locator("#showcase");
      await sc.scrollIntoViewIfNeeded();
      for (const combo of COMBOS) {
        const [iface, lang, mode] = combo.split("|");
        for (const [axis, v] of [["iface", iface], ["lang", lang], ["mode", mode]]) {
          await page.click(`[data-axis="${axis}"] [data-value="${v}"]`);
        }
        await page.waitForTimeout(iface === "cli" ? 2500 : 800);
        const tag = `${theme}-${vp.name}-${iface}-${lang}-${mode}`;
        await sc.screenshot({ path: `${OUT}/showcase-${tag}.png` });
        console.log("shot", tag);
      }
      if (vp.name === "desktop") await page.screenshot({ path: `${OUT}/full-${theme}.png`, fullPage: true });
      await ctx.close();
    }
  }
} finally {
  await browser.close();
}

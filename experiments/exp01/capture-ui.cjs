#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

function loadPlaywright() {
  try {
    return require("playwright");
  } catch (_) {
    const npxRoot = path.join(require("os").homedir(), ".npm", "_npx");
    const candidate = fs
      .readdirSync(npxRoot)
      .map((entry) => path.join(npxRoot, entry, "node_modules", "playwright"))
      .find((entry) => fs.existsSync(entry));
    if (!candidate) throw new Error("Playwright is not installed");
    return require(candidate);
  }
}

async function main() {
  const { chromium } = loadPlaywright();
  const root = path.resolve(__dirname);
  const snapshot = JSON.parse(
    fs.readFileSync(
      path.join(root, "runs/replica-3/interrupted/after-restart.json"),
      "utf8",
    ),
  );
  const report = snapshot.objects.find((item) => item.type === "report");
  if (!report) throw new Error("EXP-01 report is missing from the final snapshot");

  const output = path.join(root, "figures", "opencti-exp01-report.png");
  const diagnosticOutput = path.join(root, "figures", "opencti-route-diagnostic.png");
  fs.mkdirSync(path.dirname(output), { recursive: true });
  const browser = await chromium.launch({
    headless: true,
    executablePath: "/usr/bin/google-chrome",
    args: ["--no-sandbox"],
  });
  try {
    const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
    await page.goto("http://127.0.0.1:18080", { waitUntil: "domcontentloaded" });
    const password = page.locator('input[type="password"]');
    await password.waitFor({ timeout: 30000 }).catch(() => {});
    if (await password.count()) {
      const email = page.locator('input[type="email"]');
      if (await email.count()) {
        await email.fill("admin@timexp.local");
      } else {
        await page.locator('input:not([type="password"])').first().fill("admin@timexp.local");
      }
      await password.fill("TimExp-Only-2026!");
      await page.locator('button[type="submit"]').click();
      await page.waitForURL(/\/dashboard(?:\/|$)/, { timeout: 60000 });
      await password.waitFor({ state: "hidden", timeout: 60000 });
      await page.waitForTimeout(3000);
    }

    await page.goto(
      `http://127.0.0.1:18080/dashboard/analyses/reports/${report.id}`,
      { waitUntil: "domcontentloaded" },
    );
    try {
      await page.getByText(report.name, { exact: false }).first().waitFor({ timeout: 20000 });
    } catch (error) {
      const diagnostic = {
        body: (await page.locator("body").innerText()).slice(0, 3000),
        title: await page.title(),
        url: page.url(),
      };
      await page.screenshot({
        path: diagnosticOutput,
        fullPage: true,
      });
      console.error(JSON.stringify(diagnostic, null, 2));
      throw error;
    }
    await page.waitForTimeout(3000);
    await page.screenshot({ path: output, fullPage: true });
    if (fs.existsSync(diagnosticOutput)) fs.unlinkSync(diagnosticOutput);
    console.log(
      JSON.stringify({
        status: "pass",
        report_id: report.id,
        report_name: report.name,
        url: page.url(),
        output,
      }),
    );
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});

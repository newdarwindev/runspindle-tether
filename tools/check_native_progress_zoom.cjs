#!/usr/bin/env node
"use strict";
// Additive synthetic Chrome-native zoom qualification. Never approves a baseline.
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const cp = require("node:child_process");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const { pathToFileURL } = require("node:url");
const ROOT = path.resolve(__dirname, "..");
/** @param {string | Buffer} bytes */
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
/** @param {string} file */
const fileHash = (file) => sha(fs.readFileSync(file));
/** @param {string} directory */
function inventory(directory) {
  /** @type {Record<string, string | {symlink: string}>} */
  const result = {};
  /** @param {string} folder */
  function visit(folder) {
    for (const entry of fs
      .readdirSync(folder, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(folder, entry.name),
        relative = path.relative(directory, full);
      if (entry.isDirectory()) visit(full);
      else if (entry.isFile()) result[relative] = fileHash(full);
      else if (entry.isSymbolicLink())
        result[relative] = { symlink: fs.readlinkSync(full) };
      else throw Error("unsupported distribution file");
    }
  }
  visit(directory);
  return { files: result, inventory_sha256: sha(JSON.stringify(result)) };
}
/** @param {number} percent */
function zoomPreferences(percent) {
  assert.ok(percent === 100 || percent === 200);
  return {
    partition: {
      default_zoom_level: { x: Math.log(percent / 100) / Math.log(1.2) },
    },
  };
}
/** @param {import("./native_progress_types").Metrics} normal @param {import("./native_progress_types").Metrics} zoomed */
function validatePair(normal, zoomed) {
  assert.equal(normal.cssZoom, "1");
  assert.equal(zoomed.cssZoom, "1");
  assert.equal(normal.visualViewportScale, 1);
  assert.equal(zoomed.visualViewportScale, 1);
  assert.equal(zoomed.outerWidth, normal.outerWidth);
  assert.ok(
    Math.abs(zoomed.dpr / normal.dpr - 2) < 0.001,
    "native DPR must double",
  );
  assert.ok(
    Math.abs(normal.innerWidth / zoomed.innerWidth - 2) < 0.01,
    "CSS viewport must halve",
  );
}
/** @param {import("./native_progress_types").Pixels} pixels @param {{width: number; height: number}} expected */
function validateBitmap(pixels, expected) {
  assert.ok(
    Math.abs(pixels.size[0] - expected.width) <= 1 &&
      Math.abs(pixels.size[1] - expected.height) <= 1,
    "captured bitmap is incomplete",
  );
  assert.ok(pixels.color_count_lower_bound >= 8, "captured bitmap is blank");
}
/** @param {Buffer} png @returns {import("./native_progress_types").Pixels} */
function pixelsOf(png) {
  return JSON.parse(
    cp
      .execFileSync(
        "python3",
        [
          "-B",
          "-c",
          'import sys,io,hashlib,json; from PIL import Image; im=Image.open(io.BytesIO(sys.stdin.buffer.read())).convert("RGB"); c=im.getcolors(256); print(json.dumps(dict(size=im.size,rgb_sha256=hashlib.sha256(im.tobytes()).hexdigest(),color_count_lower_bound=len(c) if c is not None else 257)))',
        ],
        { input: png, timeout: 10000 },
      )
      .toString(),
  );
}
/** @param {import("./native_progress_types").Page} page @param {import("./native_progress_types").Session} session @param {"full" | "card" | "viewport"} mode @param {string} [selector] */
async function nativeBitmap(page, session, mode, selector) {
  const metrics = await session.send("Page.getLayoutMetrics");
  const zoom = metrics.visualViewport.zoom;
  /** @type {{x:number;y:number;width:number;height:number;scale:number} | undefined} */
  let clip;
  /** @type {{width:number;height:number}} */
  let expected;
  if (mode === "full") {
    clip = {
      x: 0,
      y: 0,
      width: metrics.contentSize.width,
      height: metrics.contentSize.height,
      scale: 1,
    };
    expected = clip;
    const extent = await page.evaluate(() => ({
      right: Math.max(
        ...[...document.querySelectorAll(".card")].map(
          (e) => e.getBoundingClientRect().right + scrollX,
        ),
      ),
      bottom: (() => {
        const footer = document.querySelector("footer");
        if (!footer) throw Error("missing footer");
        return footer.getBoundingClientRect().bottom + scrollY;
      })(),
    }));
    assert.ok(
      extent.right * zoom <= clip.width + 1 &&
        extent.bottom * zoom <= clip.height + 1,
      "full bitmap omits renderer content",
    );
  } else if (mode === "card") {
    assert.ok(selector, "card selector required");
    const rect = await page.locator(selector).evaluate((e) => {
      const r = e.getBoundingClientRect();
      return {
        x: r.x + scrollX,
        y: r.y + scrollY,
        width: r.width,
        height: r.height,
      };
    });
    clip = {
      x: rect.x * zoom,
      y: rect.y * zoom,
      width: rect.width * zoom,
      height: rect.height * zoom,
      scale: 1,
    };
    expected = clip;
  } else {
    assert.equal(mode, "viewport");
    expected = {
      width: metrics.layoutViewport.clientWidth,
      height: metrics.layoutViewport.clientHeight,
    };
  }
  const result = await session.send("Page.captureScreenshot", {
    format: "png",
    fromSurface: true,
    captureBeyondViewport: mode !== "viewport",
    ...(clip ? { clip } : {}),
  });
  const png = Buffer.from(result.data, "base64"),
    pixels = pixelsOf(png);
  validateBitmap(pixels, expected);
  return {
    png,
    pixels,
    capture: {
      mode,
      zoom,
      expected,
      coordinate_space: "Chrome_layout_metrics_DIP_not_CSS_pixels",
    },
  };
}
/** @param {import("./native_progress_types").Page} page @param {import("./native_progress_types").Mapping} mappings @param {import("./native_progress_types").Scenarios} scenarios */
async function pageChecks(page, mappings, scenarios) {
  for (const row of mappings.scenarios) {
    const card = page.locator("#" + row.id),
      text = await card.innerText();
    for (const expected of row.expected_visible)
      assert.ok(text.includes(expected), "missing visible label " + row.id);
    assert.equal(
      await card.getAttribute("aria-labelledby"),
      "heading-" + row.id,
    );
    assert.equal(
      await card
        .getByRole("heading", { name: row.accessible_heading, exact: true })
        .count(),
      1,
    );
    assert.equal(
      await card.getByLabel(row.plain_text_label, { exact: true }).count(),
      1,
    );
  }
  const findings = await page.evaluate(() => {
    const overflow = [
      ...document.querySelectorAll("body,main,.card,.meta dd,.artifact,.badge"),
    ]
      .filter((e) => e.scrollWidth > e.clientWidth + 1)
      .map((e) => e.id || e.className || e.tagName);
    const broken = [];
    for (const e of document.querySelectorAll(
      ".card h2,.card .badge,.card .number",
    ))
      for (const node of e.childNodes) {
        if (node.nodeType !== 3) continue;
        for (const match of (node.textContent || "").matchAll(
          /[A-Za-z0-9]+/g,
        )) {
          const range = document.createRange();
          range.setStart(node, match.index);
          range.setEnd(node, match.index + match[0].length);
          if (range.getClientRects().length > 1) broken.push(match[0]);
        }
      }
    return {
      overflow,
      broken,
      cssZoom: getComputedStyle(document.documentElement).zoom,
      dpr: devicePixelRatio,
      innerWidth,
      outerWidth,
      innerHeight,
      outerHeight,
      visualViewportScale: visualViewport?.scale ?? 0,
      fontSize: getComputedStyle(document.documentElement).fontSize,
      sansLoaded: document.fonts.check("16px FixtureSans"),
      monoLoaded: document.fonts.check("16px FixtureMono"),
    };
  });
  assert.deepEqual(findings.overflow, [], "horizontal overflow");
  assert.deepEqual(findings.broken, [], "split status/header word");
  assert.equal(findings.cssZoom, "1");
  assert.equal(findings.visualViewportScale, 1);
  assert.equal(findings.fontSize, "16px");
  assert.ok(findings.sansLoaded && findings.monoLoaded);
  assert.equal(await page.locator("script,iframe,img,form").count(), 0);
  assert.equal(
    await page
      .locator('a:not([href^="#"]):not([href="accepted-artifact.txt"])')
      .count(),
    0,
  );
  assert.ok(!(await page.content()).includes("SYNTHETIC_SECRET_CANARY"));
  const expectedOrder = ["Open accessible text reference"];
  for (const row of scenarios.scenarios) {
    if (row.artifact)
      expectedOrder.push(row.title + " exact synthetic artifact");
    expectedOrder.push(row.title + " plain-text version");
  }
  return { metrics: findings, expectedOrder };
}
/** @param {import("./native_progress_types").Page} page @param {string[]} expectedOrder @param {(label: string, active: import("./native_progress_types").Locator) => Promise<void>} captureExpanded */
async function keyboardChecks(page, expectedOrder, captureExpanded) {
  const observed = [];
  for (const expected of expectedOrder) {
    await page.keyboard.press("Tab");
    const active = page.locator(":focus");
    const label =
      (await active.getAttribute("aria-label")) || (await active.innerText());
    assert.equal(label, expected, "native keyboard order");
    const info = await active.evaluate((e) => ({
      tag: e.tagName,
      outline: getComputedStyle(e).outlineStyle,
      rect: e.getBoundingClientRect().toJSON(),
      height: innerHeight,
    }));
    assert.notEqual(info.outline, "none");
    assert.ok(
      info.rect.width > 0 &&
        info.rect.top >= -1 &&
        info.rect.bottom <= info.height + 1,
      "focus outside visible viewport",
    );
    if (info.tag === "SUMMARY") {
      await page.keyboard.press("Space");
      assert.equal(
        await active.evaluate((e) =>
          (() => {
            const parent = e.parentElement;
            if (!(parent instanceof HTMLDetailsElement))
              throw Error("missing details");
            return parent.open;
          })(),
        ),
        true,
      );
      assert.ok(
        (
          await active.evaluate((e) =>
            (() => {
              const parent = e.parentElement;
              if (!parent) throw Error("missing details");
              return parent.innerText;
            })(),
          )
        ).length > label.length,
      );
      if (captureExpanded) await captureExpanded(label, active);
      await page.keyboard.press("Space");
      assert.equal(
        await active.evaluate((e) =>
          (() => {
            const parent = e.parentElement;
            if (!(parent instanceof HTMLDetailsElement))
              throw Error("missing details");
            return parent.open;
          })(),
        ),
        false,
      );
    }
    observed.push(label);
  }
  return observed;
}
/** @param {import("./native_progress_types").Options} options */
async function qualify(options) {
  const output = path.resolve(options.output),
    browser = fs.realpathSync(options.browser),
    packageRoot = fs.realpathSync(options.playwright);
  assert.ok(
    !fs.existsSync(output),
    "new output directory required; never overwrite evidence",
  );
  const playwrightPackage = JSON.parse(
    fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"),
  );
  const coreRoot = path.dirname(
    require.resolve("playwright-core/package.json", { paths: [packageRoot] }),
  );
  const { chromium } =
    /** @type {import("./native_progress_types").BrowserModule} */ (
      require(packageRoot)
    );
  const browserElf = path.join(path.dirname(browser), "chrome");
  assert.ok(fs.existsSync(browserElf), "explicit Chrome ELF required");
  const before = {
    playwright: inventory(packageRoot),
    playwright_core: inventory(coreRoot),
    browser: inventory(path.dirname(browser)),
  };
  fs.mkdirSync(output, { recursive: true });
  const sourceFiles = [
    "tools/check_native_progress_zoom.cjs",
    "tools/render_progress_fixtures.py",
    "visual/scenarios.json",
    "visual/progress.css",
    "tether/sanitization.py",
    "tether/__init__.py",
    "tools/progress_visual_provenance.py",
    "visual/parent-criterion-map.json",
    "tests/native_progress_zoom.test.cjs",
    "tests/probe_native_progress_zoom.py",
    "requirements-visual.txt",
  ];
  const sourceHashes = Object.fromEntries(
    sourceFiles.map((name) => [name, fileHash(path.join(ROOT, name))]),
  );
  /** @type {{html: string; plain: string; artifact: string; mapping: import("./native_progress_types").Mapping}} */
  const built = JSON.parse(
    cp.execFileSync(
      "python3",
      [
        "-B",
        "-c",
        "import json; from tools.render_progress_fixtures import build,ARTIFACT; a,b,c=build(); print(json.dumps(dict(html=a,plain=b,mapping=c,artifact=ARTIFACT.decode())))",
      ],
      {
        cwd: ROOT,
        encoding: "utf8",
        timeout: 10000,
        env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
      },
    ),
  );
  fs.writeFileSync(path.join(output, "index.html"), built.html);
  fs.writeFileSync(path.join(output, "plain-text.txt"), built.plain);
  fs.writeFileSync(path.join(output, "accepted-artifact.txt"), built.artifact);
  /** @type {import("./native_progress_types").Scenarios} */
  const scenarios = JSON.parse(
    fs.readFileSync(path.join(ROOT, "visual/scenarios.json"), "utf8"),
  );
  const pythonInfo = JSON.parse(
    cp.execFileSync(
      "python3",
      [
        "-B",
        "-c",
        "import sys,json,PIL,PIL._imaging; print(json.dumps(dict(executable=sys.executable,pillow=PIL.__version__,imaging=PIL._imaging.__file__)))",
      ],
      { encoding: "utf8" },
    ),
  );
  const receipt = {
    schema: "tether.native-browser-zoom.v1",
    status: "running",
    baseline_approval: "candidate_not_approved",
    actual_slack: "not_run",
    evidence_class: "synthetic_actual_browser_native_zoom",
    recorded_at_utc: new Date().toISOString(),
    source_commit: cp
      .execFileSync("git", ["rev-parse", "HEAD"], {
        cwd: ROOT,
        encoding: "utf8",
      })
      .trim(),
    source_sha256: sourceHashes,
    environment: {
      node: process.version,
      node_sha256: fileHash(process.execPath),
      python_binary_sha256: fileHash(pythonInfo.executable),
      pillow: pythonInfo.pillow,
      pillow_imaging_sha256: fileHash(pythonInfo.imaging),
      python: cp
        .execFileSync("python3", ["--version"], { encoding: "utf8" })
        .trim(),
      os: os.type() + " " + os.release() + " " + os.arch(),
      playwright: playwrightPackage.version,
      browser_launcher_sha256: fileHash(browser),
      browser_elf_sha256: fileHash(browserElf),
      distributions: before,
      fonts: Object.fromEntries(
        [
          "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
          "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        ].map((p) => [path.basename(p), fileHash(p)]),
      ),
      locale: "en-US",
      timezone: "UTC",
      viewport_emulation: false,
      device_scale_emulation: false,
      css_zoom_modified: false,
      sandbox_enabled_requested: true,
    },
    width_semantics:
      "requested native window width; actual outer/inner dimensions recorded. Additional640/780/1536/2880 target effective320/390/768/1440 CSSpixels at200percent.",
    cases: /** @type {Record<string, unknown>[]} */ ([]),
    sha256: /** @type {Record<string, string>} */ ({}),
    repeat_pixel_tolerance: /** @type {number | undefined} */ (undefined),
    failure: /** @type {string | undefined} */ (undefined),
    profiles_removed: 0,
  };
  /** @type {import("./native_progress_types").BrowserContext | null} */
  let context = null;
  let cancelled = false;
  const cancel = () => {
    cancelled = true;
    if (context) void context.close().catch(() => {});
  };
  process.on("SIGTERM", cancel);
  process.on("SIGINT", cancel);
  try {
    for (const width of [320, 390, 768, 1440, 640, 780, 1536, 2880]) {
      /** @type {Record<number, import("./native_progress_types").Metrics>} */
      const pair = {};
      for (const percent of [100, 200]) {
        /** @type {{actual: import("./native_progress_types").Metrics; pixels: import("./native_progress_types").Pixels; keyboard: string[]; expanded_focus: unknown; per_state_png_sha256: unknown} | undefined} */
        let first;
        for (const repeat of [1, 2]) {
          if (cancelled) throw Error("qualification cancelled");
          const profile = fs.mkdtempSync(
            path.join(os.tmpdir(), "tether-native-zoom-"),
          );
          fs.mkdirSync(path.join(profile, "Default"));
          const preferences = JSON.stringify(zoomPreferences(percent));
          fs.writeFileSync(
            path.join(profile, "Default", "Preferences"),
            preferences,
          );
          try {
            context = await chromium.launchPersistentContext(profile, {
              executablePath: browser,
              chromiumSandbox: true,
              headless: true,
              viewport: null,
              locale: "en-US",
              timezoneId: "UTC",
              colorScheme: "light",
              reducedMotion: "reduce",
              offline: true,
              timeout: 15000,
              args: [
                `--window-size=${width},900`,
                "--disable-background-networking",
              ],
            });
            /** @type {string[]} */
            const blocked = [];
            await context.route("**/*", (route) => {
              if (route.request().url().startsWith("file:"))
                return route.continue();
              blocked.push(route.request().url());
              return route.abort();
            });
            const page = context.pages()[0] || (await context.newPage());
            page.setDefaultTimeout(5000);
            await page.goto(
              pathToFileURL(path.join(output, "index.html")).href,
            );
            await page.evaluate(() => document.fonts.ready);
            const args = cp
              .execFileSync("ps", ["-eo", "args"], { encoding: "utf8" })
              .split("\n")
              .filter(
                (line) => line.includes(profile) && line.includes("chrome"),
              );
            assert.ok(
              args.length &&
                args.every(
                  (line) =>
                    !line.includes("--no-sandbox") &&
                    !line.includes("--disable-setuid-sandbox"),
                ),
              "sandbox must remain enabled",
            );
            const checks = await pageChecks(page, built.mapping, scenarios);
            const session = await context.newCDPSession(page);
            const full = await nativeBitmap(page, session, "full");
            const png = full.png;
            const filename = `native-window-${width}-zoom-${percent}.png`;
            const pixelDigest = full.pixels;
            /** @type {Record<string, unknown>} */
            const perState = {};
            if (width === 780 && percent === 200) {
              for (const scenario of built.mapping.scenarios) {
                const cardCapture = await nativeBitmap(
                  page,
                  session,
                  "card",
                  "#" + scenario.id,
                );
                const image = cardCapture.png;
                perState[scenario.id] = {
                  png_sha256: sha(image),
                  pixels: cardCapture.pixels,
                  capture: cardCapture.capture,
                };
                if (repeat === 1) {
                  const filename =
                    "native-200-effective-390-" + scenario.id + ".png";
                  fs.writeFileSync(path.join(output, filename), image);
                  receipt.sha256[filename] = sha(image);
                }
              }
            }
            /** @type {unknown} */
            let focused = null;
            const keyboard = await keyboardChecks(
              page,
              checks.expectedOrder,
              async (label, active) => {
                if (
                  width === 780 &&
                  percent === 200 &&
                  label === "Admitted plain-text version"
                ) {
                  const rect = await active.evaluate((e) => ({
                    rect: e.getBoundingClientRect().toJSON(),
                    height: innerHeight,
                    outline: getComputedStyle(e).outlineStyle,
                  }));
                  assert.ok(
                    rect.rect.top >= -1 &&
                      rect.rect.bottom <= rect.height + 1 &&
                      rect.outline !== "none",
                    "expanded focus obscured",
                  );
                  const focusCapture = await nativeBitmap(
                    page,
                    session,
                    "viewport",
                  );
                  const image = focusCapture.png;
                  focused = {
                    label,
                    rect,
                    png_sha256: sha(image),
                    pixels: focusCapture.pixels,
                    capture: focusCapture.capture,
                  };
                  if (repeat === 1) {
                    const filename =
                      "native-200-effective-390-expanded-focus.png";
                    fs.writeFileSync(path.join(output, filename), image);
                    receipt.sha256[filename] = sha(image);
                  }
                }
              },
            );
            assert.deepEqual(blocked, [], "unexpected outbound page request");
            let clippingMutation = "not_selected";
            if (width === 640 && percent === 200 && repeat === 1) {
              const mutant = await page.addStyleTag({
                content:
                  ".card header{flex-wrap:nowrap!important}.card header>div{flex:0 0 1px!important}",
              });
              let rejected = false;
              try {
                await pageChecks(page, built.mapping, scenarios);
              } catch (error) {
                if (/horizontal overflow|split status/.test(String(error)))
                  rejected = true;
                else throw error;
              } finally {
                await mutant.evaluate((e) => e.remove());
              }
              assert.ok(rejected, "deliberate clipping mutation escaped");
              await pageChecks(page, built.mapping, scenarios);
              clippingMutation = "rejected_and_restored";
            }
            const row = {
              full_capture: full.capture,
              per_state_png_sha256: perState,
              expanded_focus: focused,
              clipping_mutation: clippingMutation,
              requested_window_width: width,
              zoom_percent: percent,
              repeat,
              actual: checks.metrics,
              keyboard,
              scenarios: built.mapping.scenarios.map((r) => r.id),
              png_sha256: sha(png),
              pixels: pixelDigest,
              preferences_sha256: sha(preferences),
              native_preferences: zoomPreferences(percent),
              sandbox_disable_flags_absent: true,
              page_outbound_requests: 0,
              browser_version: context.browser()?.version(),
              actual_browser_argv: args[0]
                .split(profile)
                .join("<disposable-profile>"),
            };
            if (repeat === 1) {
              first = row;
              fs.writeFileSync(path.join(output, filename), png);
              receipt.sha256[filename] = sha(png);
              pair[percent] = checks.metrics;
            } else {
              assert.ok(first, "missing first repeat");
              assert.deepEqual(
                row.actual,
                first.actual,
                "repeat metrics drift",
              );
              assert.deepEqual(
                row.pixels,
                first.pixels,
                "repeat normalized pixels drift",
              );
              assert.deepEqual(
                row.keyboard,
                first.keyboard,
                "repeat keyboard drift",
              );
              assert.deepEqual(
                row.expanded_focus,
                first.expanded_focus,
                "repeat expanded focus drift",
              );
              assert.deepEqual(
                row.per_state_png_sha256,
                first.per_state_png_sha256,
                "repeat per-state pixels drift",
              );
            }
            receipt.cases.push(row);
          } finally {
            try {
              await closeContext(context);
            } finally {
              context = null;
              fs.rmSync(profile, { recursive: true, force: true });
              receipt.profiles_removed++;
            }
          }
        }
      }
      validatePair(pair[100], pair[200]);
    }
    for (const [name, digest] of Object.entries(sourceHashes))
      assert.equal(
        fileHash(path.join(ROOT, name)),
        digest,
        "source changed during run",
      );
    assert.deepEqual(inventory(packageRoot), before.playwright);
    assert.deepEqual(inventory(coreRoot), before.playwright_core);
    assert.deepEqual(inventory(path.dirname(browser)), before.browser);
    receipt.status = "passed";
    receipt.repeat_pixel_tolerance = 0;
  } catch (error) {
    receipt.status = "failed";
    receipt.failure = String(error);
    throw error;
  } finally {
    process.removeListener("SIGTERM", cancel);
    process.removeListener("SIGINT", cancel);
    await closeContext(context);
    for (const name of [
      "index.html",
      "plain-text.txt",
      "accepted-artifact.txt",
    ])
      receipt.sha256[name] = fileHash(path.join(output, name));
    fs.writeFileSync(
      path.join(output, "evidence.json"),
      JSON.stringify(receipt, null, 2) + "\n",
    );
  }
  return receipt;
}
/** @param {import("./native_progress_types").BrowserContext | null} context */
async function closeContext(context) {
  if (context) await context.close();
}
module.exports = { zoomPreferences, validatePair, validateBitmap };
if (require.main === module) {
  const args = process.argv.slice(2);
  assert.equal(
    args.length,
    6,
    "required --browser PATH --playwright DIRECTORY --output NEW_DIRECTORY",
  );
  /** @type {Record<string, string>} */
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    assert.ok(["--browser", "--playwright", "--output"].includes(args[i]));
    options[args[i].slice(2)] = args[i + 1];
  }
  assert.ok(options.browser && options.playwright && options.output);
  qualify({
    browser: options.browser,
    playwright: options.playwright,
    output: options.output,
  })
    .then((r) =>
      console.log(
        JSON.stringify({
          status: r.status,
          cases: r.cases.length,
          baseline_approval: r.baseline_approval,
        }),
      ),
    )
    .catch((e) => {
      console.error(String(e));
      process.exitCode = 1;
    });
}

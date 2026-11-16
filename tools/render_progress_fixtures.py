#!/usr/bin/env python3
"""Offline candidate references, never automatic regression-baseline approval."""

from __future__ import annotations

import argparse
import hashlib
import html
import importlib.metadata
import json
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tether.sanitization import Sanitizer

ROOT = Path(__file__).resolve().parents[1]
FONT = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
MONO = Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf")
CANARY = "SYNTHETIC_SECRET_CANARY"
ARTIFACT = b'Original synthetic accepted artifact. No real account or delivery.\n'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build() -> tuple[str, str, dict[str, Any]]:
    manifest = json.loads((ROOT / "visual/scenarios.json").read_text())
    sanitize = Sanitizer((CANARY,))
    cards, plain, mappings = ([], [], [])
    for index, row in enumerate(manifest["scenarios"], 1):
        payload = sanitize.project(row["payload"])
        text = "\n".join(
            (
                row["title"],
                payload["message"],
                "Task: " + row["task_id"],
                "Thread: " + row["thread_id"],
                "Message: " + row["message_id"],
                "Revision: " + str(row["revision"]),
                "Observed: " + row["timestamp"],
                "Delivery: " + row["outcome"],
                "Untrusted text: " + payload["arguments"]["untrusted"],
                "Inert reference: " + payload["url"],
            )
        )
        artifact = ""
        if row["artifact"]:
            text += '\nArtifact: ' + row["filename"] + '\nSHA-256: ' + sha(ARTIFACT)
            artifact = f'''<section class="artifact" aria-label="Accepted artifact metadata">
<strong>{html.escape(row["filename"])}</strong>
<p>Exact synthetic accepted bytes · {len(ARTIFACT)} bytes</p>
<p>
<span class="label">SHA-256</span>
<br>
<code>{sha(ARTIFACT)}</code>
</p>
<p>Preview unavailable. A preview would not prove exact-byte delivery.</p>
<a href="accepted-artifact.txt" download aria-label="{html.escape(row["title"])} exact synthetic artifact">Download exact synthetic artifact</a>
</section>'''
        plain.append(text)
        mappings.append(
            {
                "id": row["id"],
                "criterion": row["criterion"],
                "expected_visible": [
                    row["title"], row["task_id"], row["thread_id"],
                    row["message_id"], row["timestamp"], row["outcome"],
                ],
                "accessible_heading": row["title"],
                "plain_text_label": row["title"] + " plain-text version",
            }
        )
        cards.append(f'''<article class="card" id="{row["id"]}" aria-labelledby="heading-{row["id"]}">
<header>
<div>
<div class="number">{index:02d} / SYNTHETIC</div>
<h2 id="heading-{row["id"]}">{html.escape(row["title"])}</h2>
</div>
<span class="badge {row["tone"]}">{html.escape(row["outcome"])}</span>
</header>
<p class="message">{html.escape(payload["message"])}</p>
<dl class="meta">
<dt>Task</dt>
<dd>{row["task_id"]} · r{row["revision"]}</dd>
<dt>Thread</dt>
<dd>{row["thread_id"]}</dd>
<dt>Message</dt>
<dd>{row["message_id"]}</dd>
<dt>Observed</dt>
<dd>{row["timestamp"]}</dd>
</dl>
{artifact}<p class="boundary">Delivery: {html.escape(row["outcome"])}. Acceptance is not delivery; task completion is not delivery.</p>
<details>
<summary aria-label="{html.escape(row["title"])} plain-text version">Plain-text version</summary>
<pre>{html.escape(text)}</pre>
</details>
<code class="url" aria-label="Inert untrusted reference">{html.escape(payload["url"])}</code>
</article>''')
    source = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src file:; img-src file:; base-uri 'none'; form-action 'none'">
<title>Tether · Progress reference candidates</title>
<style>{(ROOT / "visual/progress.css").read_text()}</style>
</head>
<body>
<main>
<div class="eyebrow">TETHER / OUTPUT CONTRACT STUDIES</div>
<h1>Progress, without overclaiming.</h1>
<p class="intro">Synthetic message and attachment reference cards. Every state keeps identity, freshness and delivery uncertainty visible.</p>
<aside class="notice">
<strong>LOCAL RENDER APPROXIMATION</strong>Not a Slack screenshot. Candidate references, not approved baselines. Actual Slack rendering: NOT RUN.</aside>
<p>
<a href="#fallback">Open accessible text reference</a>
</p>
<section class="grid" aria-label="Synthetic progress scenarios">{"".join(cards)}</section>
<section id="fallback">
<h2>Accessible text reference</h2>
<p>Each card has an expandable plain-text equivalent. The same text is also supplied in plain-text.txt.</p>
</section>
<footer>Fixed synthetic observation · 16 November 2026, 12:00 UTC. No live provider, authorization, durability or delivery claim.</footer>
</main>
</body>
</html>"""
    if CANARY in source or CANARY in '\n'.join(plain):
        raise ValueError("unsanitized canary")
    return (source, '\n\n'.join(plain) + '\n', {"scenarios": mappings, "artifact_sha256": sha(ARTIFACT)})


def check_page(page: Any, mapping: dict[str, Any]) -> None:
    for row in mapping["scenarios"]:
        card = page.locator("#" + row["id"])
        for value in row["expected_visible"]:
            if value not in card.inner_text():
                raise AssertionError("missing visible label: " + row["id"])
        if card.get_attribute("aria-labelledby") != "heading-" + row["id"]:
            raise AssertionError("missing accessible label")
        if card.get_by_role("heading", name=row["accessible_heading"], exact=True).count() != 1:
            raise AssertionError("missing heading")
        if card.get_by_label(row["plain_text_label"], exact=True).count() != 1:
            raise AssertionError("missing plain text label")
    violations = page.evaluate("() => [...document.querySelectorAll('body,main,.card,.meta dd,.artifact,.badge')].filter(e=>e.scrollWidth>e.clientWidth+1).map(e=>e.id||e.className)")
    if violations:
        raise AssertionError("horizontal clipping: " + str(violations))
    if page.locator("script,iframe,img,form").count():
        raise AssertionError("active/unexpected content")
    if page.locator("a:not([href^=\"#\"]):not([href=\"accepted-artifact.txt\"])").count():
        raise AssertionError("active external link")
    if CANARY in page.content():
        raise AssertionError("secret escaped")


def render(directory: Path) -> dict[str, Any]:
    from PIL import Image, ImageDraw
    from playwright.sync_api import sync_playwright
    source, text, mapping = build()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "index.html").write_text(source)
    (directory / "plain-text.txt").write_text(text)
    (directory / "accepted-artifact.txt").write_bytes(ARTIFACT)
    screenshots = []
    blocked = []
    keyboard = []
    with sync_playwright() as engine:
        browser = engine.chromium.launch(
            executable_path="/usr/bin/chromium",
            headless=True,
            chromium_sandbox=True,
            args=["--disable-dev-shm-usage", "--disable-background-networking"],
        )
        try:
            for width, zoom in ((320, 1), (390, 1), (768, 1), (1440, 1), (390, 2)):
                context = browser.new_context(
                    viewport={"width": width, "height": 900},
                    device_scale_factor=1,
                    locale="en-US",
                    timezone_id="UTC",
                    color_scheme="light",
                    reduced_motion="reduce",
                    offline=True,
                )

                def deny(route: Any) -> None:
                    if route.request.url.startswith("file:"):
                        route.continue_()
                    else:
                        blocked.append(route.request.url)
                        route.abort()
                context.route("**/*", deny)
                page = context.new_page()
                page.goto((directory / "index.html").as_uri(), wait_until="load")
                page.evaluate("document.fonts.ready")
                if zoom == 2:
                    page.add_style_tag(content="html{font-size:32px}")
                check_page(page, mapping)
                name = f'progress-{width}' + ("-text-200pct" if zoom == 2 else "") + ".png"
                page.screenshot(path=str(directory / name), full_page=True, animations="disabled")
                screenshots.append(name)
                if width == 390 and zoom == 1:
                    for row in mapping["scenarios"]:
                        page.locator("#" + row["id"]).screenshot(path=str(directory / (row["id"] + ".png")))
                    page.keyboard.press("Tab")
                    expected_order = ["Open accessible text reference"]
                    for fixture in json.loads((ROOT / "visual/scenarios.json").read_text())["scenarios"]:
                        if fixture["artifact"]:
                            expected_order.append(fixture["title"] + " exact synthetic artifact")
                        expected_order.append(fixture["title"] + " plain-text version")
                    for expected in expected_order:
                        active = page.locator(":focus")
                        label = active.get_attribute("aria-label") or active.inner_text()
                        if label != expected:
                            raise AssertionError("keyboard order")
                        style = active.evaluate("(e)=>({outline:getComputedStyle(e).outlineStyle,rect:e.getBoundingClientRect().toJSON()})")
                        if (
                            style["outline"] == "none"
                            or style["rect"]["width"] <= 0
                            or style["rect"]["top"] < 0
                            or style["rect"]["bottom"] > 900
                        ):
                            raise AssertionError("missing keyboard focus")
                        keyboard.append(label)
                        page.keyboard.press("Tab")
                    page.locator("#admitted").evaluate("(e)=>e.removeAttribute(\"aria-labelledby\")")
                    try:
                        check_page(page, mapping)
                    except AssertionError:
                        pass
                    else:
                        raise AssertionError("missing-label mutant escaped")
                    page.locator("#admitted").evaluate("(e)=>e.setAttribute(\"aria-labelledby\",\"heading-admitted\")")
                    page.add_style_tag(content=".meta dd{white-space:nowrap;width:16px;overflow:hidden}")
                    try:
                        check_page(page, mapping)
                    except AssertionError:
                        pass
                    else:
                        raise AssertionError("clipping mutant escaped")
                context.close()
        finally:
            browser.close()
    if blocked:
        raise AssertionError("unexpected network requests")
    thumbs = []
    for row in mapping["scenarios"]:
        im = Image.open(directory / (row["id"] + ".png")).convert("RGB")
        im.thumbnail((280, 600))
        thumbs.append((row["id"], im.copy()))
    sheet = Image.new("RGB", (900, 4 * 650 + 55), "#eef2f6")
    draw = ImageDraw.Draw(sheet)
    draw.text((18, 15), "LOCAL RENDER APPROXIMATION / UNAPPROVED CANDIDATES", fill="#172b42")
    for index, (name, im) in enumerate(thumbs):
        x = 15 + index % 3 * 300
        y = 55 + index // 3 * 650
        draw.text((x, y), name, fill="#172b42")
        sheet.paste(im, (x, y + 25))
    sheet.save(directory / "contact-sheet.png")
    return {
        "mapping": mapping,
        "viewports": [320, 390, 768, 1440],
        "zoom_sample": (
            "390px with 200% root text sizing; text reflow, not browser chrome zoom"
        ),
        "keyboard": "automated traversal only",
        "keyboard_labels": keyboard,
        "mutants": {"missing_label": "detected", "clipping": "detected"},
        "unexpected_network_requests": 0,
        "screenshots": screenshots,
        "actual_slack": "not_run",
        "baseline_approval": "not_approved",
        "reviewer_disposition": "generated_pending_visual_review",
    }


def write_source(directory: Path) -> None:
    """Publish text sources only; never import or start a rendering engine."""
    if directory.exists() and any(directory.iterdir()):
        raise SystemExit("Refusing to overwrite existing fixture sources.")
    source, text, mapping = build()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "index.html").write_text(source)
    (directory / "plain-text.txt").write_text(text)
    (directory / "accepted-artifact.txt").write_bytes(ARTIFACT)
    (directory / "field-map.json").write_text(json.dumps(mapping, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output", type=Path, default=ROOT / "docs/visual-candidates"
    )
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="Write editable HTML/text/map/artifact without importing a browser.",
    )
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        raise SystemExit(
            "Refusing to overwrite candidates. Use a new output directory; "
            "baseline approval is separate."
        )
    if args.source_only:
        write_source(args.output)
        print(json.dumps({
            "status": "source_only_not_rendered",
            "output": str(args.output),
            "files": 4,
        }))
        return

    with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
        a, b = Path(first), Path(second)
        evidence = render(a)
        render(b)
        hashes = {p.name: sha(p.read_bytes()) for p in sorted(a.iterdir())}
        if hashes != {p.name: sha(p.read_bytes()) for p in sorted(b.iterdir())}:
            raise SystemExit("Repeat render mismatch; no references published.")
        args.output.mkdir(parents=True, exist_ok=True)
        for file in a.iterdir():
            shutil.copyfile(file, args.output / file.name)

    evidence.update({
        "repeat_render_hashes": "identical",
        "sha256": hashes,
        "chromium": subprocess.check_output(
            ["/usr/bin/chromium", "--version"], text=True
        ).strip(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "playwright": importlib.metadata.version("playwright"),
        "pillow": importlib.metadata.version("pillow"),
        "fonts": {str(p): sha(p.read_bytes()) for p in (FONT, MONO)},
        "source_sha256": {
            str(p.relative_to(ROOT)): sha(p.read_bytes())
            for p in (
                ROOT / "visual/scenarios.json",
                ROOT / "visual/progress.css",
                Path(__file__).resolve(),
            )
        },
        "locale": "en-US",
        "timezone": "UTC",
        "device_pixel_ratio": 1,
        "clock": "2026-11-16T12:00:00Z",
        "seed": "fixed scenarios; no random inputs",
        "animations": "disabled",
    })
    (args.output / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps({
        "status": "generated_candidates",
        "output": str(args.output),
        "files": len(hashes),
    }))


if __name__ == "__main__":
    main()

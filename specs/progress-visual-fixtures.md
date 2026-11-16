# Synthetic progress visual fixture sources (partial #6)

This is a source-only candidate package, not completed visual generation and not a
Slack-native screenshot or replacement application. No reference PNG or contact
sheet was generated. No visual baseline is approved, no image threshold selected,
and actual Slack rendering/accessibility remains not-run.

Editable `visual/scenarios.json` and `visual/progress.css` define twelve synthetic
states: admitted, running, blocked, cancellation requested, completed, unknown,
unsupported, stale, edited revision, delivered, failed and long content. Task,
thread, message, revision and fixed observation time remain visible. Delivery is
separate from task completion and artifact acceptance. Existing
`Sanitizer.project` processes the invented public-summary/final payloads; arbitrary
markup is escaped and reference URLs rendered inert. No hidden reasoning appears.
A local download contains exact invented accepted-artifact bytes, with SHA-256
attribution. Unavailable previews never imply delivery.

`docs/visual-source/index.html` is the locally editable/renderable approximation;
`plain-text.txt`, `field-map.json` and `accepted-artifact.txt` provide accessible
source fallback and state/field/criterion mapping. The HTML visibly declares
LOCAL RENDER APPROXIMATION, candidate-not-approved and actual Slack NOT RUN.
The scenario fixture intentionally contains an invented secret canary as sanitizer
input; generated HTML/plain text omit it. No real secrets or history are used.

## Execution boundary and blocker

The installed Chromium 156.0.8078.79 failed before opening any page with
`process_singleton_posix: socket() failed: Operation not permitted`. A bounded
sandbox-escalated retry failed at the same local socket boundary. A separate
supported browser attempt reported that `file://` navigation is disallowed and
only HTTP/HTTPS is accepted. No server, security setting change, extra permission
workaround or further bypass was attempted.

Consequently DOM/accessibility/keyboard assertions, screenshots, clipping and
missing-label mutations, repeat-render hashes, contact sheet and manual visual
review have NOT RUN. Only source contracts and declared palette contrast were
tested. Those tests cannot establish computed browser contrast, layout, semantics,
focus visibility, screen-reader behavior or any Slack compatibility.

## Source-only reproduction (no browser required)

```
PYTHONPATH=. python3 tools/render_progress_fixtures.py --source-only --output /tmp/tether-visual-new-source
```

This writes exact HTML, plain text, field map and artifact without importing
Playwright/Pillow or launching a browser, and refuses an existing nonempty output.
The source-only CLI is tested under denied browser imports and network attempts.
It does not generate or validate any images.

## Reproduction after an authorized renderer is available

```
PYTHONPATH=. python3 tools/render_progress_fixtures.py --output /tmp/tether-visual-new-candidates
python3 -m unittest discover -s tests -p test_progress_visual_source.py -v
python3 -O -m unittest discover -s tests -p test_progress_visual_source.py -v
```

The unqualified renderer requires Chromium sandboxing; no security-relaxation
flag is retained and rendering was not retried after this source correction.
It is written for local file input only, an offline browser
context and rejection of non-file requests. It specifies installed DejaVu Sans/
Mono, UTC/en-US, device scale 1, fixed fixture time, disabled animation and widths
320/390/768/1440. The fifth sample uses 200% root text sizing at 390px: this is a
text-reflow approximation, not browser-chrome zoom qualification. It attempts two
independent temporary renders and refuses output if their hashes differ; it also
refuses to overwrite any existing candidate directory. Both rules are source
intent, not verified rendering evidence. Temporary render directories are cleaned
on normal success/failure; generated candidate outputs require explicit review
and may be removed as ordinary scratch artifacts.

No browser/font assets are copied. Raster outputs, if later generated, use the
installed DejaVu font files whose hashes are recorded in source evidence. Original
synthetic copy/layout only; no proprietary Slack UI assets or user screenshots.
This work does not duplicate the H01/H07 or API-key references and establishes no
native UI/provider/authority/durability/deployment acceptance. Existing parent
criteria and issue #6's ungenerated image/visual-review gates remain open.

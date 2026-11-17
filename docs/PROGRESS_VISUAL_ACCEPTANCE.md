# Progress-message visual acceptance

Issue #6 owns a local synthetic presentation reference family, not a replacement Slack UI. Actual Slack delivery/rendering, native runtime capabilities and parent behavioral gates remain separately not run or blocked. The H01 API-key sibling reuses this family; no second live-visual family is introduced.

## Source families and preservation

- `visual/scenarios.json`, `visual/progress.css` and `tools/render_progress_fixtures.py` are the editable canonical twelve-state source.
- `visual/parent-criterion-map.json` explicitly binds every state to its Tether/H01/H07 parent criterion and identifies the existing live H01 sibling.
- `docs/visual-source` and `docs/progress-visual-source-evidence.json` retain the original source-only stage and its blocked renderer outcome. They are historical, not rewritten as passing evidence.
- `docs/visual-reference`, its `evidence.json`, and `docs/progress-visual-review.json` retain the reviewed Chrome 157/Python 3.14 reference family. Its CSS/text enlargement samples are not native browser zoom.
- The supplemental `docs/native-zoom-reference` family records measured native zoom, exact source/toolchain, layout assertions, repeated actual pixels and independent disposition. Its `review.json` binds evidence and artifact hashes with zero tolerance; the generator retains candidate approval status and cannot approve itself. It neither replaces the earlier family nor relabels emulation as native zoom.

## Acceptance map

| Required presentation | Canonical states and verification |
|---|---|
| Admitted/running/blocked/cancel-requested/terminal; unsupported/stale/edited/uncertain | Twelve named scenario cards; explicit textual status, observation time and unchanged identity; no hidden-reasoning claims |
| Accepted/delivered/failed/unknown distinctions | `terminal`, `delivered`, `failed`, `unknown`, `cancel-requested`; accepted bytes do not prove delivery |
| Compact and long identifiers/content | Task, thread, message and revision visible; long-content card and narrow-width assertions |
| Safe untrusted text/URLs; absent secret canary | Canonical sanitizer and HTML escaping; no active external links/scripts/forms; independently scanned output |
| Exact artifact metadata, long filename and unavailable preview | Fixed synthetic bytes with exact SHA-256; explicit unavailable-preview warning; delivery outcome remains independent |
| Accessible fallback and payload-label mapping | Plain-text output, per-card details, headings and ARIA mappings, keyboard order/focus and contrast checks |
| Reusable parent references | `visual/parent-criterion-map.json`; H01/H07 and existing API-key H01 sibling are links to the same family |
| Deterministic reference review | Historical named PNGs/contact sheet, second independent render, zero-diff overlay and explicit independent disposition retained |
| Mutations | Missing accessible label, clipping, split title/status words and changed pixel must fail, not silently update expected images |
| Native 200% zoom | Supplemental evidence must demonstrate doubled DPR and reduced CSS viewport with unchanged native window, CSS zoom 1 and visualViewport scale 1; measured dimensions, not requested dimensions, govern coverage |
| Reset/cleanup | Disposable profile/output roots, bounded processes, no-overwrite publication and cancellation cleanup; no persistent service |

## Reproduction and provenance

Historical-family reproduction requires its exact recorded Chrome 157 and Python/Playwright/Pillow/font/OS versions. A different environment is not a pixel-equivalent replay and must produce a separately reviewed family. `requirements-visual.txt` pins the Python renderer packages. `tools/progress_visual_provenance.py --browser-binary /absolute/path/to/actual/chrome` inventories renderer, imported sanitizer/initializer, requirements, Python executable, actual browser ELF and installed distribution file digests. Version mismatch or missing installed distribution file fails. This inventory is not proof of executed bytes or visual approval; caches listed by the distribution are included rather than silently omitted.

Source checks require no browser:

```sh
python3 -B -m unittest discover -s tests -p 'test_progress_visual*.py'
python3 -O -B -m unittest discover -s tests -p 'test_progress_visual*.py'
python3 tools/check_scaffold.py
```

The optional browser cancellation case must be reported as skipped/not-run unless its required renderer is supplied. Never count a skip as browser acceptance. Native-family commands and exact prerequisites accompany its separate execution receipt.

## Scope limits

These generated references demonstrate appearance, semantics, keyboard behavior and local rendering under recorded synthetic inputs. They do not prove Slack-native parity, authorization, delivery receipts, durable provider effects, native desktop support, backend persistence or production readiness. Existing broader aggregate failures remain failures; structural/source tests do not replace missing operational gates.

## Additive source verification

On the reviewed parent-mapping/provenance source (`45121cfc706a84f09ff6dfbe70415ec050358ead`, tree `e920ef34b3effb8497571ad99c2bc8a4909ad039`), four new provenance tests passed both normal and optimized Python. Full Tether suites passed 445 tests in each mode with one explicit optional browser-cancellation skip, using exact historical upload prerequisite `040b71f2213a34f34e6b6a40124ed1164b93ce30`. Strict typing, Ruff, scaffold/artifact checks and whitespace checks passed. The declared aggregate was run and failed `static-quality`; it is not a full green aggregate. New native-browser qualification is recorded separately rather than replacing that failed gate or the optional skipped Python-browser case.


## Completed native browser qualification

Frozen renderer source `0e3ee546ff9181871634f68d0e32d30191190c11` passed 32 contexts: eight native window sizes, 100% and 200%, twice each. Chrome 156.0.8078.79 and Node Playwright 1.56.1 are a separately pinned family, not an assumed replay of Chrome 157. The report records actual metrics: browser-level zoom doubles DPR and halves CSS width without changing the native window, CSS zoom or visual viewport scale. Requested 320/390 windows clamp to 500 actual pixels; this limitation is explicit. Physical widths 640/780/1536/2880 provide measured effective 320/390/768/1440 CSS widths at 200%.

All twelve states, footer/right edge and expanded keyboard focus were independently inspected in actual corrected images. Initial Playwright clipping/blank capture candidates were rejected, never baselined. Corrected capture uses Chrome CDP layout DIP coordinates, checks physical dimensions/nonblank content and includes half-width/half-height/blank regressions. Eleven Node tests pass. Repeated normalized pixels have zero difference. Twenty-nine PNGs have explicit separate reviewer approval; historical contact sheets, overlays and named references remain retained.

The actual cancellation probe sends SIGTERM after a real browser starts and verifies the owned browser identity and temporary profile are gone (`docs/native-zoom-cancellation.json`). This is bounded owned-process/profile cleanup evidence, not power-loss or all-descendant supervision qualification. No Chrome sandbox-disabling flags are used; no personal profile, live account or security-setting change is involved.

Native lane reproduction needs the recorded executable/package/font/OS inventory and a fresh output directory. The command does not install dependencies, approve images or overwrite a baseline:

```sh
node --test tests/native_progress_zoom.test.cjs
node tools/check_native_progress_zoom.cjs --browser /path/to/chrome --playwright /path/to/playwright --output /tmp/new-native-reference
python3 tools/check_native_progress_reference.py docs/native-zoom-reference /tmp/new-native-reference --review docs/native-zoom-reference/review.json
```

The final command requires Pillow and fails if it is missing. It verifies the trusted review, source/environment, complete artifact inventory and every RGBA channel without changing either directory. Five independent comparator tests cover exact admission, rehashed changed pixels, alpha, stale/unapproved review and missing artifacts. In ordinary non-visual discovery those tests explicitly skip without Pillow; that skip is not visual acceptance. They were actually executed here in both modes. Native source and its independently approved receipt remained unchanged while adding this comparator and prose audit.

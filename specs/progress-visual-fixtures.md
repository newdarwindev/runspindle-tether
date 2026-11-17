# Reviewed synthetic progress-message references

Issue #6 generation evidence is now available in
[the reference directory](../docs/visual-reference/) and its
[manifest](../docs/visual-reference/evidence.json). These are original local
render approximations, not Slack screenshots or production/runtime acceptance.
No real account, native session, provider, private history or proprietary UI
asset is used. Parent behavioral and live gates are unchanged.

## Scope and review

Twelve synthetic states cover admitted/running/blocked/cancellation requested,
terminal/accepted, uncertain send, unsupported source, stale update, edited
revision, delivered, failed and long content. Task/thread/message/revision/time,
explicit delivery state and unsupported/unknown labels remain visible. Exact
invented accepted bytes and their digest are available for local download;
unavailable previews never imply delivery. URLs are inert and configured secret
canaries are absent from HTML, text and accessibility output.

The package contains 25 named PNGs: twelve cards, six full-page viewport/zoom
samples, contact sheet, expanded keyboard-focus state, enlarged long-content
card, intentional clipping mutant, repeat contact sheet, overlay and diff.
Six accessibility snapshots plus editable HTML/plain text and the accepted
artifact are retained. Source fixtures, CSS and field mappings remain in
`visual/` and `docs/visual-source/`; evidence maps states to expected text,
accessible labels and parent criteria.

Independent pixel review found and rejected a narrow enlarged-header defect.
The revised header wraps its badge onto a separate row when needed and preserves
whole title/status words. The revised pixels passed independent review. Exact
zero normalized-RGB-pixel drift is the explicitly accepted threshold only for
this pinned local reference environment. Changed environments, fixtures,
thresholds or baselines require a new explicit review; the checker never writes
or regenerates its reference. Captured images retain their candidate-stage
caption. Their later approval disposition is recorded separately in the manifest,
not painted over the original capture.

## Checks and boundaries

Verified widths: 320, 390, 768 and 1440 CSS pixels. Additional 390px samples use
200% root text and CSS layout zoom 2. These exercise enlarged/reflowed references,
not browser-chrome zoom UI or Slack-native behavior. Computed text contrast is
at least 5.998:1. DOM checks cover visible identities, headings/accessibility
labels, word-preserving headers, no horizontal overflow, inert content/links and
canary exclusion. Keyboard traversal and Space expansion are asserted; a separate
assistant-directed interactive spot-check inspected Tab, Shift+Tab, Space and
Enter focus/expansion/scrolling screenshots. This is not human screen-reader
certification. Actual Slack and browser-chrome zoom remain not-run.

Two independent browser runs produced identical outputs. Missing-label, clipping
and split-header defects are deliberately injected and detected. A separate
one-pixel mutation proves the pixel comparison fails even if its file digest is
updated. File/source hashes reject accidental edits without rewriting baselines.

The renderer uses Chrome's normal sandbox, a fresh disposable context, local
files, offline mode, request denial, fixed data/clock, UTC/en-US, DPR 1, explicit
fonts and disabled animations/caret. Browser calls have bounded timeouts.
SIGTERM/SIGINT are deferred to safe checkpoints rather than unwinding an active
Playwright greenlet; browser owners close before exit. A real SIGTERM test after
the first frame verifies observed owned processes exit and no partial candidate
is published. Final output publication is atomic. No host settings are changed.

## Pinned reproduction

Prerequisites: Linux with Google Chrome **157.0.8103.38**, Python **3.14.8**,
the exact `requirements-visual.txt` packages and the DejaVu Sans/Mono font files
hashed in the manifest. OS, renderer, dependency and font pins are recorded;
changes require qualification rather than a silent new baseline. No fonts or
browser binaries are copied into the repository.

Example isolated package preparation (using an already installed pip):

```sh
python3 -m venv --without-pip /tmp/tether-visual-env
pip --python /tmp/tether-visual-env/bin/python install -r requirements-visual.txt
```

One bounded generation command; choose a fresh output path:

```sh
timeout --signal=TERM --kill-after=30 180 env PYTHONPATH=. \
  /tmp/tether-visual-env/bin/python tools/render_progress_fixtures.py \
  --browser /usr/bin/google-chrome --expected-browser-version 157.0.8103.38 \
  --output /tmp/tether-visual-actual
```

Then compare read-only:

```sh
python tools/check_progress_visual.py docs/visual-reference /tmp/tether-visual-actual
```

The generation command refuses a nonempty destination. Temporary browser/render
and staging directories are cleaned on normal failure/cancellation. The completed
output is an explicit retained artifact; remove only the scratch output you made
when finished. Baseline replacement is never part of generation or comparison.

Run source/artifact tests with `python -m unittest discover -s tests -p
 'test_progress_visual_*.py'`. To include the real cancellation test, set
`RUNSPINDLE_VISUAL_BROWSER=/usr/bin/google-chrome` and
`RUNSPINDLE_VISUAL_BROWSER_VERSION=157.0.8103.38` with pinned dependencies.
Full historical migration tests additionally require the exact old reader
`040b71f2213a34f34e6b6a40124ed1164b93ce30` via
`RUNSPINDLE_TETHER_V1_SOURCE`.

The earlier `docs/progress-visual-source-evidence.json` is retained as historical
source-only evidence, including its then-blocked renderer. It is not the current
render result; this manifest and reviewed reference package supersede that gap.

### Remaining issue acceptance

Issue #6 remains open: the real browser-surface 200% zoom criterion has not
been exercised. CSS layout zoom and root-text enlargement are supplemental
references, not substitutes. The available supported computer-use inventory on
the qualification machine exposed no browser or native app surface; no global
keyboard input was sent to a personal desktop. Keep this PR draft until genuine
browser zoom can be performed and its actual factor verified through supported
controls.

Accessibility snapshots are retained as raw Playwright text (`.aria.txt`), not
normalized or rewritten as manually authored YAML. The screenshot pixels remain
identical to the independently reviewed v3 images after static-check corrections.

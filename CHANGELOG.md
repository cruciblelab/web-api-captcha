# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] — Initial release

Split out of [discord-webapi](https://github.com/cruciblelab/discord-webapi)'s
`discord_webapi.captcha` — the module had grown into a self-contained
subsystem (adaptive escalation, behavioral scoring, replay detection,
multiple providers, a bundled widget) with almost no real dependency on
Discord or discord-webapi itself.

### Split-specific changes

- Standalone `Transport` Protocol + `InProcessTransport`, structurally
  compatible with discord-webapi's own transport (no adapter needed).
- `current_user_id_resolver` FastAPI dependency replacing the hard
  `DiscordUser` dependency for account-bound gates (`require_account=True`).
- Vendored `TokenBucketLimiter` (no cross-package dependency for rate
  limiting).
- Bundled widget UI translated from Turkish to English as the public
  default (~30 user-facing/debug strings).
- Renamed the `dwa_`/`dwa-` (discord-webapi) prefix to `wac_`/`wac-`
  across SQL table names, the visitor cookie name, CSS classes, JS
  event names, and the widget script filename.
- Full test suite carried over and adapted (241 tests), ruff and
  mypy --strict clean.

### Everything this release actually includes (built up before the split)

- **Verification layers, composable** (`CaptchaGate`): captcha-only,
  account-only, both ("safety mode"), or click-only, plus arbitrary
  `extra_checks` via a `PredicateCheck`/`VerificationCheck` Protocol.
- **`AdaptiveCaptchaGate`**: IP-reputation-driven escalation (the
  Cloudflare "Under Attack Mode" pattern) -- a clean IP never sees a
  challenge, a flagged one gets a real one, no manual two-tier chaining
  needed.
- **`PageGuard`**: the same adaptive decision applied to an arbitrary
  route rather than one minted link -- a visitor cookie (optionally
  bound to the connecting IP) so a verified visitor isn't asked again.
  `presets.build_cloudflare_style_guard()` wires up a sane default.
- **Providers**: `MathCaptchaProvider`/`TextCaptchaProvider` (self-hosted,
  real rendered PNGs, not SVG), `ProofOfWorkProvider` (Cloudflare
  Turnstile-style hashcash, invisible, constant server cost),
  `PathTraceProvider` (draw-the-line), `ReCaptchaProvider`/
  `HCaptchaProvider`/`TurnstileProvider` (third-party wrappers, only
  `httpx` needed), `FallbackCaptchaProvider` (tries several in order).
- **Behavioral scoring** (`SignalScoreCheck`): transparent, weighted
  heuristics over mouse kinematics collected as the user approaches the
  widget -- curvature ratio, velocity/timing variance, click-offset-
  from-center, a mouse-homing-correction signal, plus
  `navigator.webdriver`/missing-`Accept-Language` checks. Every
  heuristic and weight is overridable.
- **Replay detection** (`RepeatedMovementCheck`): a global, look-back
  check catching a recorded real human movement being replayed later
  under a different account/IP -- the one thing per-request kinematic
  analysis structurally can't catch on its own.
- **Anti-bot signals**: `honeypot_field_empty()`, `reject_headless_user_agent()`,
  `reject_webdriver()`, `require_min_interaction_ms()`,
  `require_signal_flag()`, `suspicious_user_agent()` for `PageGuard`.
- **Rate limiting**: IP-keyed limiters on challenge issuance and gate
  verification, independent of the per-token limiter.
- **Storage**: `Memory*` (zero infrastructure) and `SQL*` (any
  SQLAlchemy async engine) implementations for every store;
  `SQLCaptchaStore` optionally encrypts data at rest with Fernet
  (`MultiFernet` key-rotation supported) and exposes `purge_expired()`
  for a periodic cleanup job.
- **Bundled widget**: one `<div>` + one `<script>`, adapts its own UI to
  whatever the gate issues (checkbox, image+text, fully invisible PoW,
  embedded `<canvas>` for Path-Trace, or the relevant third-party
  widget), collects signals from page load, emits a `wac-captcha-widget-log`
  event for every step.

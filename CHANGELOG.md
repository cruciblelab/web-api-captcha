# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

- **Fixed**: the bundled widget's `renderImageChallenge()`
  (`webapi_captcha/widget.js`) string-concatenated
  `challenge.image_data_uri` straight into an `innerHTML` string. Safe
  today for the bundled providers (always a server-generated base64
  data URI), but a latent XSS path for anyone's own `CaptchaProvider`
  putting attacker-influenceable content in that field -- `innerHTML`
  would parse a crafted value (`x" onerror="..."`) as real markup. The
  image is now built via `document.createElement('img')` + assigning to
  the `.src` **property**, which never parses its value as markup.
  Purely a hardening fix -- identical rendered output for every existing
  provider.
- **`TrustTokenVerifier.verify()` accepts optional `expected_subject_id`/
  `required_purpose` binding checks.** Closes a gap flagged in a security
  self-review: by default a valid trust receipt from a trusted issuer was
  accepted for ANY `subject_id`, with binding it to the current visitor
  left entirely to the caller. Passing either now makes `verify()`
  enforce it itself (a mismatch fails closed, same as every other
  problem it already returns `None` for). Threaded through
  `AdaptiveCaptchaGate.is_currently_trusted()`/`get_info()`/`verify()`
  and `PageGuard.require_human()` as the same two optional keyword-only
  parameters. Purely additive -- omitting both is byte-for-byte today's
  behavior.
- **Fixed test-suite noise**: the SQL `engine` pytest fixture
  (`tests/test_captcha_stores.py`) never disposed its `AsyncEngine`,
  which could leave aiosqlite's background worker thread tearing down
  after pytest had already closed that test's event loop for the next
  test -- harmless in outcome, but a real, now-fixed source of spurious
  `PytestUnhandledThreadExceptionWarning`s in full-suite runs.
- **`ConditionalRiskSignal`** (`webapi_captcha.risk`): runs a `then`
  signal ONLY when a `when` signal flags first -- "if IP reputation is
  suspicious, THEN also run this deeper/more-expensive check",
  generalized to any two signals (neither has to be IP reputation), and
  chainable (`A → B → C`). Lets an expensive/paid/slow signal be gated
  behind a cheap one so it never runs on traffic the cheap check already
  cleared -- something `RiskEngine`'s own ordering/`short_circuit_on_
  override` couldn't express (those blend every signal; this skips the
  follow-up's call entirely).
- **`AdaptiveCaptchaGate` `reputation` is now optional.** Pass a
  `risk_engine` and omit `reputation` to drop the built-in IP-reputation
  path entirely and decide purely from your engine. `decision_store` and
  `escalation_provider` are optional too (a `MemoryAdaptiveDecisionStore`
  is created by default; a genuinely-needed-but-missing escalation
  provider now raises a clear `ValueError` instead of an `AttributeError`
  on `None`). Passing neither `reputation` nor `risk_engine` raises a
  `ValueError` at construction -- that combination could never escalate.
  Purely additive: existing positional `AdaptiveCaptchaGate(transport,
  store, reputation, provider, decision_store, ...)` calls are unchanged.
- **Fixed**: `ReCaptchaProvider`/`HCaptchaProvider`/`TurnstileProvider`
  opened a brand new `httpx.AsyncClient()` and closed it immediately
  after on every single `verify()` call (unless you passed your own
  `http_client=`) -- a full TCP+TLS handshake on every verification,
  real latency/resource cost under any real volume. Each provider now
  lazily creates and reuses ONE client across every call (new shared
  `webapi_captcha.providers._http._LazyHttpClientMixin`); a new
  `await provider.aclose()` closes it on shutdown. Purely a default-
  behavior fix -- passing `http_client=` yourself is unaffected (that
  client's lifecycle was and still is entirely yours).
- **`TieredTrustStore`/`TieredRunningRiskStore`** (`webapi_captcha.tiered`,
  new module): fast/slow cache-aside composition for any two
  `TrustStore`/`RunningRiskStore` implementations -- writes go to both
  tiers (fast tier's own TTL capped at `fast_ttl_cap`, so it evicts
  itself with no manual age bookkeeping), reads check the fast tier
  first and fall back to the slow tier on a miss. `TieredRunningRiskStore
  .bump()` reads the true current level across both tiers before writing
  (not a verbatim write to each), since `RunningRiskStore`'s "never
  regresses" contract would otherwise break if the fast tier's entry
  expired while the slow tier's hadn't. New **`webapi_captcha.redis_store`**
  (`RedisTrustStore`/`RedisRunningRiskStore`, behind a new `redis` extra,
  not part of `all` since `all` today implies no live external service)
  gives a concrete fast-tier implementation using Redis's native key
  expiry. Writes now go to `slow` FIRST, synchronously, then `fast`
  (not both concurrently via `asyncio.gather()`, an earlier design that
  had a confirmed gap: if `fast` failed, `gather()` propagated
  immediately while `slow`'s coroutine kept running unawaited in the
  background -- if `slow` *also* failed, that second, more important
  failure was silently discarded with no trace). Failures against the
  fast tier (read or write) never propagate and never block the slow
  tier -- the slow tier is the source of truth, the fast tier is
  disposable; a new `on_fast_tier_error` callback observes swallowed
  fast-tier failures without them affecting behavior.
- **`AdaptiveCaptchaGate.trusted_revalidation`**: an optional `RiskSignal`
  that keeps running even on an otherwise-trusted visitor (from either
  `trust_store` or a trust receipt) -- if it flags, `is_currently_
  trusted()` returns `False` for that call instead of an unconditional
  skip, so a compromised/stolen trust cookie or receipt doesn't grant
  indefinite immunity. Fails open like every other soft heuristic here;
  `trusted_revalidation=None` (the default) is unchanged behavior.
- **`webapi_captcha.receipts`** (new module): a v1, deliberately
  NON-anonymous cross-site trust receipt -- solve a captcha on one site,
  be recognized as already-verified on another site you've chosen to
  trust. `TrustTokenIssuer`/`TrustTokenVerifier` use Ed25519 asymmetric
  signing (already available via `cryptography`, no new dependency,
  chosen over Fernet because the trust model is one issuer/many
  verifiers, not a shared secret every relying site would need to hold).
  Deliberately NOT the anonymous IETF Privacy Pass / RSA Blind Signatures
  scheme (RFC 9576-9578/9474) -- no mature, audited Python implementation
  of that exists today, and this package won't roll its own
  blind-signature cryptography without one; `TrustReceipt.subject_id` is
  opaque but linkable, not anonymous, and this is documented prominently.
  `TrustTokenVerifier.verify()` fails **closed** on any ambiguity (bad
  signature, unknown issuer, expired, malformed input) -- the one
  deliberate exception to this package's usual fail-open philosophy,
  since a receipt grants trust outright rather than contributing a soft
  signal. Integrates as a second, alternate "already trusted" source
  alongside `TrustStore` (OR semantics, not a `RiskSignal` -- the engine
  can only escalate, never force a level down) via new optional
  `trust_token_verifier`/`trust_token` parameters on
  `AdaptiveCaptchaGate`/`PageGuard.require_human` -- this package never
  reads the token from a request itself; the caller extracts it from
  wherever it lives and passes the raw string in. How the token actually
  travels from one site's browser session to another's is explicitly out
  of scope.
- **`RiskEngine`** (`webapi_captcha.risk`, new module): a multi-signal,
  tiered replacement for `AdaptiveCaptchaGate`/`PageGuard`'s previous
  single binary "IP suspicious or not" decision, entirely additive
  (`risk_engine=None` keeps the exact old behavior). Combines IP
  reputation (`ReputationRiskSignal`), behavioral scoring
  (`BehaviorScoreRiskSignal`, wrapping `SignalScoreCheck`), and any
  custom `RiskSignal` into one ordered `RiskLevel`
  (`MINIMAL`/`LOW`/`ELEVATED`/`HIGH`). Three concrete new capabilities:
  a bad IP `hard_override`s straight to the strongest configured tier
  instead of being averaged away; `min_level_by_purpose` (and
  `PageGuard.require_human(..., min_level=...)`) lets a specific
  route/purpose demand extra scrutiny even on a clean IP; a new
  `RunningRiskStore` (`MemoryRunningRiskStore`/`SQLRunningRiskStore`) +
  `build_passive_risk_router()` lets passive signals collected *after* a
  visitor has already entered a guarded page still escalate them on a
  later request (a level only ever rises within its TTL, never drops).
  `escalation_providers: Mapping[RiskLevel, CaptchaProvider]` lets each
  tier use a different provider -- self-hosted for the low tiers,
  reCAPTCHA/hCaptcha/Turnstile only for the tier that's actually
  suspicious enough to be worth the third-party round trip.
  `ReputationRiskSignal`/`BehaviorScoreRiskSignal`'s `name`/`weight` are
  constructor keyword args, not fixed class attributes -- every part of
  the pipeline is tunable. `RiskEngine.add_signal()`/`remove_signal()`/
  `get_signal()` let signals be wired in/out or re-tuned at runtime
  (e.g. a feature flag turning a paid fraud-score signal on) without
  rebuilding the gate/`PageGuard` stack; `signals`/`level_thresholds`/
  `short_circuit_on_override` stay plain public attributes too, for
  anything the three methods don't cover.
- **`RiskEngine` extensions** (per-signal `enabled` toggle, corroboration,
  replay integration, a frontend beacon): every shipped `RiskSignal`
  (`ReputationRiskSignal`/`BehaviorScoreRiskSignal`/the two new ones
  below) now takes an `enabled: bool = True` kwarg, and `RiskEngine.
  assess()` skips a disabled signal entirely (no `assess()` call, no
  `contributions` entry) -- toggle one off at runtime via `engine.
  get_signal("x").enabled = False` without losing its position/config.
  New **`CorroboratedRiskSignal`** requires 2+ underlying signals to
  independently agree before firing an override, fixing
  `ReputationRiskSignal`'s own "a bad IP alone jumps straight to the
  strongest tier" behavior for deployments that want a second signal's
  agreement first (`min_agreements=` for k-of-n instead of strict AND).
  New **`ReplayRiskSignal`** bridges the existing cross-request replay
  defense (`RepeatedMovementCheck`/`TrajectoryFingerprintStore`) into
  `RiskEngine` so a detected replay can escalate `RiskLevel` too, not
  just fail its own separate `VerificationCheck` -- deliberately
  read-only (never calls `store.record()` itself, since `assess_risk()`
  runs far more often than a real verification completes and would
  otherwise poison the store from mere risk probes that never lead to a
  solve). `replay_guard.py`'s fingerprinting grid (`DEFAULT_GRID_PX`/
  `DEFAULT_GRID_MS`/`DEFAULT_MAX_FINGERPRINT_POINTS`/
  `DEFAULT_MIN_FINGERPRINT_POINTS`) is now a set of public constants and
  constructor/function keyword arguments on `fingerprint_trajectory()`/
  `RepeatedMovementCheck`/`ReplayRiskSignal`, not hardcoded private
  module constants. New **`webapi_captcha.beacon`** module
  (`build_passive_risk_beacon_router()` + a bundled `beacon.js`) closes
  the gap `build_passive_risk_router()` left open: a small, standalone
  frontend script that periodically posts passive signals to it, working
  even on pages with no captcha widget rendered at all (the normal case
  for a clean `PageGuard`-protected visitor) -- deliberately a new file
  pair rather than grafted onto the per-token `CaptchaWidget`, which
  structurally can't run with zero widget divs on the page.
- **`LoadAdaptiveDifficulty`** for `ProofOfWorkProvider`: pass it instead
  of a plain `int` difficulty to get mCaptcha-style load-adaptive PoW —
  difficulty tracks the recent rate of issued challenges and rises
  towards a ceiling during a traffic spike/DDoS, then relaxes back down
  once it passes. `ProofOfWorkProvider.difficulty` now accepts
  `int | Callable[[], int]`. Motivated by researching the open-source
  captcha/anti-bot landscape (ALTCHA, Cap.js, mCaptcha, FriendlyCaptcha,
  hCaptcha, reCAPTCHA v3, Cloudflare Turnstile) before this release: our
  own `ProofOfWorkProvider` had a static difficulty, unlike mCaptcha's
  headline differentiator.
- Documented (README, "Accessibility" section) that the no-visual-
  challenge providers (`ProofOfWorkProvider`, `SignalScoreCheck`,
  `RepeatedMovementCheck`, `PathTraceProvider`) give an identical
  experience to screen-reader/keyboard-only users by construction, not as
  a bolted-on mode — same pattern ALTCHA and Cap.js market as a core
  differentiator, backed by WebAIM's survey data on CAPTCHA being the
  most-cited screen-reader accessibility complaint.

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

# webapi-captcha

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-yellow.svg)](https://www.apache.org/licenses/LICENSE-2.0)

⭐ If you find this useful, consider starring the repo -- it helps others
discover it.

A pluggable, adaptive human-verification/captcha layer for FastAPI.

We designed it framework-only -- no assumption about who's connecting,
or how they log in. We originally built it as part of
[discord-webapi](https://github.com/cruciblelab/discord-webapi) and
split it out because none of it is actually Discord-specific: IP
reputation, behavioral scoring, replay detection, self-hosted and
third-party captcha providers, an adaptive "Cloudflare-style" page
guard, and a bundled JS widget all work the same whether your users
arrive via Discord OAuth, your own login, or no login at all.

License: Apache 2.0.

## Install

```bash
pip install webapi-captcha
# or, for the latest from GitHub, not yet on PyPI:
pip install "webapi-captcha @ git+https://github.com/cruciblelab/web-api-captcha"
```

Optional extras:

```bash
pip install "webapi-captcha[render]"      # Pillow -- MathCaptchaProvider/TextCaptchaProvider
pip install "webapi-captcha[sql]"         # SQLAlchemy async + sqlite/postgres/mysql drivers
pip install "webapi-captcha[sql-sqlite]"  # just aiosqlite
pip install "webapi-captcha[sql-postgres]"
pip install "webapi-captcha[sql-mysql]"
pip install "webapi-captcha[all]"         # render + sql
```

The third-party widget wrappers (`ReCaptchaProvider`, `HCaptchaProvider`,
`TurnstileProvider`) need only `httpx`, already a core dependency -- no
extra required for those.

## Quickstart -- plain web usage

Protect any point on your own site (a signup form, a comment box, ...)
with a self-hosted provider, no signed-in user involved at all:

```python
from fastapi import FastAPI
from webapi_captcha import MathCaptchaProvider, MemoryCaptchaStore, build_captcha_router

app = FastAPI()
provider = MathCaptchaProvider(MemoryCaptchaStore())
app.state.webapi_captcha_providers = {"math": provider}
app.include_router(build_captcha_router())
```

`GET /api/captcha/challenge?kind=math` returns a rendered PNG + a
`challenge_id`; `POST /api/captcha/verify` (`{"kind", "challenge_id",
"response"}`) verifies it.

## Quickstart -- gated verification

Tie a challenge to a `(user_id, purpose)` and get notified over a
pluggable `Transport` the moment it's solved -- no polling, works even if
the process minting the link and the process serving the verification
page are different (e.g. a bot process and a web process):

```python
from webapi_captcha import CaptchaGate, MemoryVerificationStore
from webapi_captcha.transport import InProcessTransport

transport = InProcessTransport()
gate = CaptchaGate(transport, MemoryVerificationStore(), provider)
app.state.webapi_captcha_gate = gate
app.include_router(build_captcha_router())

async def handle_verified(event):
    print(f"user {event.user_id} solved {event.metadata}")

gate.on_verified(handle_verified)

request = await gate.create_verification(
    user_id=123, purpose="signup", metadata={"plan": "pro"},
)
verify_url = f"https://yoursite.com/verify/{request.token}"
```

## Composable verification layers

A captcha alone answers "is this a human?", not "is this the *right*
human?" -- a forwarded link can be solved by anyone. `CaptchaGate` composes
independent, ANDed checks so you can require exactly what your scenario
needs:

```python
# captcha only (default): human, but no account bound to it
CaptchaGate(transport, store, provider)

# account only: no image, just "must be signed in as the account this
# link was issued for" -- wire current_user_id_resolver to your own auth
CaptchaGate(transport, store, require_captcha=False, require_account=True)

# both ("safety mode")
CaptchaGate(transport, store, provider, require_captcha=True, require_account=True)

# click only: possessing the one-time link is the only proof (lowest
# friction, weakest guarantee)
CaptchaGate(transport, store, require_captcha=False, require_account=False)

# add your own check alongside ours -- a fingerprint score, an account
# age threshold, anything: we provide the hook, you write the policy
async def my_check(ctx):
    return ctx.signals.get("fingerprint_score", 0) > 70

CaptchaGate(transport, store, provider, extra_checks=[PredicateCheck("fingerprint", my_check)])
```

`require_account=True` needs to know who's currently signed in -- we
don't ship a login system of our own, so you pass your own FastAPI
dependency as `current_user_id_resolver=` resolving to the signed-in
user's id (or `None`). See `webapi_captcha.api`'s module docstring for a
worked example wiring this up against
[discord-webapi](https://github.com/cruciblelab/discord-webapi)'s own
OAuth session (`discord_webapi.captcha.build_discord_captcha_router`
does this for you automatically if you use both packages together).

## Providers

All of them implement one `CaptchaProvider` Protocol (`issue()` +
`verify()`) -- bring your own by implementing the same Protocol, no
inheritance needed:

- **Self-hosted image captchas** -- `MathCaptchaProvider` (arithmetic
  question), `TextCaptchaProvider` (read distorted text). A real PNG per
  render with randomized color/rotation/noise (not SVG -- SVG text sits
  in the file as plain text). Needs the `render` extra (Pillow). Honest
  note: modern OCR/vision models solve these fairly easily -- treat them
  as a low/last-resort tier, not your main defense.
- **Invisible / low-cost layer** -- `ProofOfWorkProvider`: Cloudflare
  Turnstile-style, the user does nothing; the browser does a small
  hashcash search in the background while the page loads. The server
  verifies with a single hash -- no image render, no third-party call,
  minimal and constant server cost regardless of `difficulty`. Pass a
  `LoadAdaptiveDifficulty()` instance instead of a plain `int` for the
  mCaptcha-style pattern: difficulty tracks the recent rate of issued
  challenges and rises towards a ceiling during a traffic spike/DDoS
  (each extra bit doubles the client's expected work), then relaxes back
  down once it passes -- real visitors on a quiet site never notice,
  attackers pay a rising CPU tax that scales with their own volume.
- **Behavioral score** -- `SignalScoreCheck`: transparent, weighted
  heuristics over mouse kinematics collected client-side as the user
  approaches the widget (curvature ratio, velocity/timing variance,
  click-offset-from-center, `navigator.webdriver`, missing
  `Accept-Language`, ...). Every heuristic and weight is overridable; add
  your own signal + heuristic. Honest note: this is not a bot detector or
  ML model -- a bot that knows the rules, or one replaying a recorded
  human mouse trace, can pass it. Its value is raising the cost of
  low-effort automation, always layered with PoW (real cost) and/or
  account-binding (real identity), never alone.
- **Replay detection** (`RepeatedMovementCheck`) -- the one thing the
  kinematic heuristics structurally can't catch on their own: a recorded
  real human movement replayed later is genuine data, so it passes every
  per-request kinematic check. This is a global (not per-user/IP), *look
  back* check: fingerprints `mouse_trajectory` and flags a fingerprint
  seen recently under any account/IP. Fails open on missing/touch
  signals.
- **Third-party widgets** -- `ReCaptchaProvider`, `HCaptchaProvider`,
  `TurnstileProvider` (bring your own site/secret keys). Only `httpx`
  needed. Each lazily creates and reuses ONE `httpx.AsyncClient` across
  every `verify()` call (not a fresh one per call -- a real TCP+TLS
  handshake saved on every verification) -- pass your own `http_client=`
  to share a client across providers/your whole app instead, and call
  `await provider.aclose()` on shutdown if you didn't.
- **`FallbackCaptchaProvider`** -- tries several providers in order (e.g.
  Turnstile, falling back to a self-hosted one if the third-party service
  is unreachable).
- **`PathTraceProvider`** -- draw-the-line interaction friction, no
  visible image.

## Accessibility

CAPTCHA is the single most-cited accessibility barrier by screen-reader
users in WebAIM's ongoing survey -- ranked above ambiguous links, missing
alt text, and inaccessible search combined. Every provider here that
requires no visual/audio challenge (`ProofOfWorkProvider`,
`SignalScoreCheck`, `RepeatedMovementCheck`, `PathTraceProvider`'s
line-draw) is usable identically by a screen-reader user, a keyboard-only
user, and a sighted mouse user, because there is nothing to see or hear in
the first place -- not an accessibility mode bolted on afterwards. If you
need a fully self-hosted, zero-visual-challenge setup, compose those three
with `FallbackCaptchaProvider` and skip the image providers
(`MathCaptchaProvider`/`TextCaptchaProvider`) entirely, or keep them only
as a last-resort tier behind `AdaptiveCaptchaGate`'s escalation.

## Adaptive escalation and `PageGuard`

`AdaptiveCaptchaGate` makes the "show a captcha or not" decision
server-side from IP reputation: a clean IP never sees anything, a
flagged one gets a real challenge. `PageGuard` is the same idea applied
to an arbitrary route rather than one minted link -- drop it in front of
any page for a Cloudflare-style "checking your browser" interstitial,
complete with a visitor cookie so a verified visitor isn't asked again
(optionally bound to the same connecting IP). `presets.build_cloudflare_style_guard()`
wires up a sane default of both in one call.

### Risk-tiered escalation (`RiskEngine`)

By default the escalation decision above is a single binary question
(IP reputation suspicious or not). Pass a `RiskEngine` for a richer,
multi-signal version instead -- combine IP reputation
(`ReputationRiskSignal`), behavioral scoring (`BehaviorScoreRiskSignal`,
wrapping `SignalScoreCheck`), and any custom signal you write into one
ordered `RiskLevel` (`MINIMAL`/`LOW`/`ELEVATED`/`HIGH`):

```python
from webapi_captcha import (
    BehaviorScoreRiskSignal, ReputationRiskSignal, RiskEngine, RiskLevel,
)

risk_engine = RiskEngine([
    ReputationRiskSignal(my_reputation_source),  # a bad IP hard-overrides to HIGH
    BehaviorScoreRiskSignal(),                   # continuous, from posted signals
])
gate = AdaptiveCaptchaGate(
    ..., risk_engine=risk_engine,
    escalation_providers={RiskLevel.HIGH: turnstile_provider},  # a different/stricter
    min_level_by_purpose={"checkout": RiskLevel.ELEVATED},      # provider per tier
)
```

- **A bad IP skips straight to the strongest tier** -- `ReputationRiskSignal`
  returns a `hard_override`, not a blended score, so it doesn't get
  diluted by other signals looking clean.
- **A specific route/purpose can demand extra scrutiny even on a clean
  IP** -- `min_level_by_purpose` (or `PageGuard.require_human(...,
  min_level=...)` per call) raises the floor regardless of the computed
  score.
- **Passive signals gathered after a visitor has already entered a
  guarded page can still escalate them** -- pair a `RunningRiskStore`
  (`MemoryRunningRiskStore`/`SQLRunningRiskStore`) with
  `build_passive_risk_router()`: your frontend `POST`s accumulated
  signals periodically, and every subsequent `PageGuard.require_human()`
  call for that visitor picks up the new floor automatically (a level
  only ever rises within its TTL, never drops). This is the "stop
  calling reCAPTCHA/hCaptcha on every request" piece: this whole
  decision runs first and for free, and only the challenge that a
  configured tier actually needs (self-hosted or third-party) gets
  called at all. A bundled frontend "beacon" does the posting for you --
  `app.include_router(build_passive_risk_beacon_router())` plus one
  `<script src="/static/webapi-captcha-beacon.js"></script>` tag on any
  `PageGuard`-protected page (works even when no captcha widget is
  rendered on it at all, which is the normal case for a clean visitor).
- `risk_engine=None` (the default) keeps today's exact
  `reputation.is_suspicious()` behavior -- this is entirely additive.

Every signal (built-in or your own) supports a plain `enabled: bool`
attribute -- `engine.get_signal("behavior-score").enabled = False` turns
one off at runtime (a feature flag, an API you've stopped trusting)
without losing its position/config, and `RiskEngine.assess()` skips a
disabled signal entirely.

**Requiring more than one signal to agree** -- by default
`ReputationRiskSignal` unilaterally overrides to `HIGH` the moment its
reputation source flags an IP, with no corroboration. Wrap it (and
anything else) in `CorroboratedRiskSignal` if that's too blunt for your
deployment:

```python
from webapi_captcha import CorroboratedRiskSignal, ReputationRiskSignal, BehaviorScoreRiskSignal

risk_engine = RiskEngine([
    CorroboratedRiskSignal([
        ReputationRiskSignal(my_reputation_source),
        BehaviorScoreRiskSignal(),
    ]),  # a bad IP alone no longer forces HIGH -- needs a second signal to agree too
])
```
`min_agreements=` (default: every enabled child) lets you require k-of-n
instead of strict AND.

**Building your own conditional chains** -- `ConditionalRiskSignal(when=A,
then=B)` runs `B` ONLY when `A` flags first, so an expensive/paid check
(`B`) never runs on the traffic a cheap check (`A`) already cleared:

```python
from webapi_captcha import ConditionalRiskSignal, ReputationRiskSignal, RiskEngine

risk_engine = RiskEngine([
    ConditionalRiskSignal(
        when=ReputationRiskSignal(cheap_blocklist),  # cheap gatekeeper
        then=MyPaidFraudScoreSignal(api_key=...),     # only runs if the IP looks bad
    ),
])
```
Chainable (`when=A, then=ConditionalRiskSignal(when=B, then=C)` gives
`A → B → C`), and nothing here is hardcoded to IP reputation -- `when`
and `then` are any two signals you like.

**Dropping the built-in IP-reputation path entirely** -- `reputation` is
optional on `AdaptiveCaptchaGate`. Pass a `risk_engine` and omit it, and
the gate decides purely from your engine (which may or may not itself
include a `ReputationRiskSignal` -- your chain, your call):

```python
gate = AdaptiveCaptchaGate(
    transport, store,
    escalation_provider=provider,
    risk_engine=my_engine,   # no `reputation=` at all
)
```
(Passing neither `reputation` nor `risk_engine` is a config error -- with
neither, the gate could never escalate.)

**Replay detection feeding the same risk decision** -- `ReplayRiskSignal`
bridges the existing cross-request replay defense
(`RepeatedMovementCheck`/`TrajectoryFingerprintStore`) into `RiskEngine`,
so a detected replay can escalate `RiskLevel` too, not just fail its own
separate `VerificationCheck`. It's read-only (never records a
fingerprint itself -- that stays `RepeatedMovementCheck`'s job); mount
both against the *same* store:

```python
from webapi_captcha import ReplayRiskSignal, RepeatedMovementCheck, MemoryTrajectoryFingerprintStore

fp_store = MemoryTrajectoryFingerprintStore()
risk_engine = RiskEngine([ReplayRiskSignal(fp_store)])
gate = AdaptiveCaptchaGate(..., risk_engine=risk_engine, extra_checks=[RepeatedMovementCheck(fp_store)])
```

## Bundled widget

An optional, ready UI on top of the raw endpoints -- one `<div>` + one
`<script>`, no frontend of your own required:

```python
app.include_router(build_captcha_widget_router())
```

```html
<div class="wac-captcha-widget" data-token="{token}"></div>
<script src="/static/webapi-captcha-widget.js" data-callback="onVerified"></script>
<script>function onVerified(result) { /* result.verified, result.failed_check */ }</script>
```

The widget adapts its own UI to whatever the gate issues -- a plain
checkbox if no captcha is required, an image + text box for Math/Text, a
fully invisible flow for Proof-of-Work (runs the hashcash search itself
via `crypto.subtle.digest`), an embedded `<canvas>` for Path-Trace, or
the relevant third-party widget for reCAPTCHA/hCaptcha/Turnstile. It
collects mouse/touch signals starting the moment the page loads, no
extra code required, and emits a `wac-captcha-widget-log` `CustomEvent`
on `document` for every step if you want your own visible timeline.

## Storage

Every store is a Protocol with a `Memory*` implementation (zero
infrastructure, single process) and, behind the `sql` extra, a
`SQL*` implementation against any SQLAlchemy async engine (SQLite,
Postgres, MySQL) -- for multi-replica deployments where in-memory state
can't be shared. `SQLCaptchaStore` optionally encrypts stored data at
rest with Fernet (`MultiFernet` key-rotation supported) and exposes
`purge_expired()` for a periodic cleanup job.

**Fast/slow tiering** -- `TrustStore`/`RunningRiskStore` also compose
into `TieredTrustStore`/`TieredRunningRiskStore` (`webapi_captcha.tiered`,
no extra required): a fast tier (e.g. `RedisTrustStore`/
`RedisRunningRiskStore`, behind the `redis` extra) in front of a slower,
durable one (SQL), so the vast majority of lookups (recent visitors) stay
cheap without giving up long-term retention.

```python
from webapi_captcha import RedisTrustStore, SQLTrustStore, TieredTrustStore
from datetime import timedelta

trust_store = TieredTrustStore(
    fast=RedisTrustStore(redis_client),
    slow=SQLTrustStore(engine),
    fast_ttl_cap=timedelta(hours=6),  # recent entries live in Redis for up to 6h,
)                                     # older ones fall back to SQL automatically
```

Writes go to both tiers (the fast tier's own TTL capped at
`fast_ttl_cap`, so it evicts itself with no manual bookkeeping); reads
check the fast tier first, falling back to the slow tier on a miss.
`redis` is not part of the `all` extra -- unlike SQLite, it's a real
service you have to run, so it stays an explicit opt-in.

**The slow tier is the source of truth; the fast tier is disposable.**
Writes go to `slow` first (a failure there always propagates -- that's
real data at risk), then `fast` (a failure there is swallowed -- a
crashed/unreachable cache degrades performance, never correctness).
Reads that fail against the fast tier fall back to the slow tier the
same way. Pass `on_fast_tier_error=` to observe swallowed fast-tier
failures (logging, metrics) without them affecting behavior.

## Trust isn't necessarily an unconditional bypass

`AdaptiveCaptchaGate`'s optional `trusted_revalidation` keeps one cheap
`RiskSignal` running even on an otherwise-trusted visitor (from either
`trust_store` or a trust receipt) -- so a compromised/stolen trust
cookie or receipt doesn't grant indefinite immunity:

```python
gate = AdaptiveCaptchaGate(
    ..., trust_store=trust_store,
    trusted_revalidation=ReputationRiskSignal(my_reputation_source),
    trusted_revalidation_threshold=0.5,  # default
)
```

If it flags (a `hard_override`, or `suspicion >=
trusted_revalidation_threshold`), `is_currently_trusted()` returns
`False` for that call -- the normal risk-assessment flow runs instead of
being skipped. Fails open like every other soft heuristic here (an
exception in the revalidation check does not revoke trust) --
`trusted_revalidation=None` (the default) preserves today's "trusted is
an unconditional skip" behavior exactly.

## Cross-site trust receipts (v1, non-anonymous)

A visitor who already cleared a captcha on one site can be recognized as
already-verified on another site you've chosen to trust -- without
re-solving. `webapi_captcha.receipts` issues and verifies Ed25519-signed
`TrustReceipt`s: one issuer signs, any number of independent verifiers
hold only that issuer's public key and can verify without ever being
able to forge new ones.

```python
from webapi_captcha import AdaptiveCaptchaGate, TrustTokenIssuer, TrustTokenVerifier

# Site A (issuer), after a successful verification:
issuer = TrustTokenIssuer(private_key, issuer_id="site-a")
token = issuer.issue(subject_id, ttl=timedelta(hours=24))
# hand `token` back to the visitor's own browser/session -- how it
# travels from site A to site B is up to your application (a redirect
# handoff, a same-site-set arrangement, ...); this package does not
# solve cross-site transport.

# Site B (verifier), configured to trust site A:
verifier = TrustTokenVerifier({"site-a": site_a_public_key})
gate = AdaptiveCaptchaGate(..., trust_token_verifier=verifier)
# Wherever your route extracts the token from (a header, a cookie, ...):
await guard.require_human(request, trust_token=extracted_token)
```

**Read before using this.** `TrustReceipt.subject_id` is opaque but NOT
anonymous -- two sites that both see the same `subject_id` can correlate
that it's the same visitor. This is deliberately NOT the IETF Privacy
Pass / RSA Blind Signatures scheme (RFC 9576-9578/9474) -- no mature,
audited Python implementation of that exists today, and this package
won't roll its own blind-signature cryptography without one. `verify()`
also fails **closed** (any invalid/expired/unknown-issuer/malformed token
returns `None`), the one deliberate exception to this package's usual
fail-open philosophy, since a receipt grants trust outright rather than
contributing a soft signal.

## Using this with discord-webapi

If you're also using [discord-webapi](https://github.com/cruciblelab/discord-webapi),
its own `discord_webapi.captcha` module is a thin re-export of this
package (install with `pip install discord-webapi[captcha]`) plus two
small additions: `resolve_discord_user_id` (a ready
`current_user_id_resolver` wired to discord-webapi's own OAuth session)
and `build_discord_captcha_router` (this package's `build_captcha_router`
with it pre-wired) -- so an account-bound gate checked against a signed-in
Discord user needs zero extra wiring. discord-webapi's own
`InProcessTransport`/`RedisTransport` are structurally compatible with
this package's `Transport` Protocol, so they interoperate without any
adapter.

Using this on its own, with a different framework's login, or with no
login at all? None of the above applies -- we built everything here to
work standalone, with no dependency on discord-webapi whatsoever.

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
  minimal and constant server cost regardless of `difficulty`.
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
  needed.
- **`FallbackCaptchaProvider`** -- tries several providers in order (e.g.
  Turnstile, falling back to a self-hosted one if the third-party service
  is unreachable).
- **`PathTraceProvider`** -- draw-the-line interaction friction, no
  visible image.

## Adaptive escalation and `PageGuard`

`AdaptiveCaptchaGate` makes the "show a captcha or not" decision
server-side from IP reputation: a clean IP never sees anything, a
flagged one gets a real challenge. `PageGuard` is the same idea applied
to an arbitrary route rather than one minted link -- drop it in front of
any page for a Cloudflare-style "checking your browser" interstitial,
complete with a visitor cookie so a verified visitor isn't asked again
(optionally bound to the same connecting IP). `presets.build_cloudflare_style_guard()`
wires up a sane default of both in one call.

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

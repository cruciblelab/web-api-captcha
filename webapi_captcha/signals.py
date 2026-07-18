"""Ready-made `PredicateCheck`s for client *instrumentation* signals -- the
"is this a real browser" half of an invisible layer (the other half being
`ProofOfWorkProvider`).

Be clear-eyed about what this is. Browser instrumentation -- reading
`navigator.webdriver`, event timings, pointer entropy, and so on -- happens
in the client's JavaScript, which you write and which the client can lie
about. The server can only receive whatever the client chose to send (in
the gate verify request's `signals` bag) and apply a *transparent* rule to
it. These helpers are exactly that: small, honest, easily-bypassed rules --
a speed bump against low-effort automation, not a bot detector. Anything
that claims to reliably tell a human from a bot purely server-side from
client-submitted signals is lying to you.

Use them as one cheap layer in a gate, alongside proof-of-work (real cost)
and account binding (real identity):

    gate = CaptchaGate(
        transport, store,
        require_captcha=False,
        extra_checks=[reject_webdriver(), require_min_interaction_ms(400)],
    )

...and write your own `PredicateCheck` for anything more sophisticated
(your own fingerprint scoring, an external anti-fraud service, ...).
"""

from __future__ import annotations

from webapi_captcha.checks import CheckOutcome, PredicateCheck, VerificationContext


def reject_webdriver(name: str = "no-webdriver") -> PredicateCheck:
    """Fails if the client reported `navigator.webdriver === true`
    (`signals["webdriver"]`). Trivially spoofable -- an automated browser
    can just not send it -- but it's free and catches the laziest tools."""

    async def _check(ctx: VerificationContext) -> CheckOutcome:
        if ctx.signals.get("webdriver") is True:
            return CheckOutcome(False, "navigator.webdriver was true")
        return CheckOutcome(True)

    return PredicateCheck(name, _check)


def require_signal_flag(flag: str, *, name: str | None = None) -> PredicateCheck:
    """Fails unless the client sent `signals[flag] is True`. Use for your
    own client-side attestation ("passed my JS instrumentation") -- again,
    only as trustworthy as your JS and the fact the client can forge it."""

    async def _check(ctx: VerificationContext) -> CheckOutcome:
        if ctx.signals.get(flag) is True:
            return CheckOutcome(True)
        return CheckOutcome(False, f"required signal {flag!r} was not set")

    return PredicateCheck(name or f"signal-{flag}", _check)


def require_min_interaction_ms(minimum_ms: int, *, name: str = "min-interaction") -> PredicateCheck:
    """Fails if the client-reported interaction time
    (`signals["interaction_ms"]`) is under `minimum_ms` -- a form solved in
    3ms is suspicious. Spoofable (the client picks the number), so it's a
    heuristic, not a gate on its own."""

    async def _check(ctx: VerificationContext) -> CheckOutcome:
        value = ctx.signals.get("interaction_ms")
        if isinstance(value, int | float) and value >= minimum_ms:
            return CheckOutcome(True)
        return CheckOutcome(False, f"interaction was faster than {minimum_ms}ms (or not reported)")

    return PredicateCheck(name, _check)


def honeypot_field_empty(field_name: str, *, name: str | None = None) -> PredicateCheck:
    """A classic anti-spam trick, generalized to this package's `signals`
    bag: put a form field in your page that's hidden from real users
    (`display: none`, off-screen positioning, whatever your CSS already
    does elsewhere -- this library renders no forms of its own, so it has
    no opinion on *how* you hide it) but that a form-filling bot, which
    reads the DOM rather than looks at the rendered page, tends to fill in
    like any other field anyway. Send its value as
    `signals[field_name]`; this fails whenever it's non-empty.

    Same honesty as everything else here: a bot author aware of this
    specific field will simply skip it. Cheap, free of any legitimate-user
    friction (a human never sees the field, so never fills it), and
    catches unsophisticated form-filling bots that fill in every visible
    -- to *them* -- input indiscriminately.
    """

    async def _check(ctx: VerificationContext) -> CheckOutcome:
        value = ctx.signals.get(field_name)
        if value:
            return CheckOutcome(False, f"honeypot field {field_name!r} was filled in")
        return CheckOutcome(True)

    return PredicateCheck(name or f"honeypot-{field_name}", _check)


# Substrings of a `User-Agent` header that identify a well-known headless
# browser or browser-automation tool. Deliberately narrow -- these are
# unambiguous automation-tool self-identifications, not a generic "looks
# like a bot" guess, so this stays a low-false-positive check rather than
# a source of blocking legitimate (if unusual) real browsers. Extend or
# replace via the `patterns=` argument for your own denylist.
DEFAULT_HEADLESS_UA_PATTERNS = (
    "headlesschrome",
    "phantomjs",
    "puppeteer",
    "playwright",
    "selenium",
    "electron",
)


def reject_headless_user_agent(
    patterns: tuple[str, ...] | None = None, *, name: str = "no-headless-user-agent"
) -> PredicateCheck:
    """Fails if `ctx.user_agent` (the request's own `User-Agent` header --
    server-observed, see `VerificationContext.user_agent`, not something
    the client's JavaScript reports in `signals`) contains one of
    `patterns` (case-insensitive substring match; defaults to a short list
    of well-known headless-browser/automation-tool self-identifications).

    Same honest caveat as `reject_webdriver`: any HTTP client can set
    `User-Agent` to anything, so a bot author who knows this check exists
    just picks an ordinary-looking one instead. This only catches
    automation run with its tooling's *default*, unmodified identity --
    which is a real and common case (most scripted abuse doesn't bother
    spoofing this until it has to), not a guaranteed detector.
    """
    needles = tuple(p.lower() for p in (patterns or DEFAULT_HEADLESS_UA_PATTERNS))

    async def _check(ctx: VerificationContext) -> CheckOutcome:
        ua = (ctx.user_agent or "").lower()
        if not ua:
            # No User-Agent at all is itself unusual for a real browser,
            # but plenty of legitimate non-browser clients (a mobile app's
            # webview misconfigured, some corporate proxies) also strip
            # it -- treated as "nothing to go on", not a failure, same
            # abstain-don't-punish stance as the rest of this package.
            return CheckOutcome(True)
        hit = next((needle for needle in needles if needle in ua), None)
        if hit is not None:
            return CheckOutcome(False, f"user-agent identifies as automation tooling ({hit!r})")
        return CheckOutcome(True)

    return PredicateCheck(name, _check)

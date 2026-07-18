# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] — Initial release

Split out of [discord-webapi](https://github.com/cruciblelab/discord-webapi)'s
`discord_webapi.captcha` — the module had grown into a self-contained
subsystem (adaptive escalation, behavioral scoring, replay detection,
multiple providers, a bundled widget) with almost no real dependency on
Discord or discord-webapi itself.

- Standalone `Transport` Protocol + `InProcessTransport`, structurally
  compatible with discord-webapi's own transport (no adapter needed).
- `current_user_id_resolver` FastAPI dependency replacing the hard
  `DiscordUser` dependency for account-bound gates (`require_account=True`).
- Vendored `TokenBucketLimiter` (no cross-package dependency for rate
  limiting).
- Bundled widget UI translated from Turkish to English as the public
  default.
- Full test suite carried over and adapted (241 tests), ruff and
  mypy --strict clean.

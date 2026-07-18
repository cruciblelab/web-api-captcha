"""Captcha providers -- pluggable backends implementing
`webapi_captcha.base.CaptchaProvider`. Two self-hosted (Math, Text),
two interactive/invisible ones (proof-of-work, path-trace), three
third-party widget wrappers (reCAPTCHA, hCaptcha, Turnstile), and a
composite (`FallbackCaptchaProvider`, trying several in order) ship
here; write your own for anything else (a different service, your own
challenge type) by implementing that same Protocol.
"""

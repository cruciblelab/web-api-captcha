"""Exercises the real Pillow-based rendering (not a mock) -- decodes the
returned PNG and checks it actually is one, sizes correctly, and varies
between calls (the "different colors each time" anti-memorization
hardening)."""

import base64

from PIL import Image

from webapi_captcha.rendering import _CHAR_ADVANCE, render_captcha_image


def _decode(uri: str) -> Image.Image:
    assert uri.startswith("data:image/png;base64,")
    raw = base64.b64decode(uri.split(",", 1)[1])
    return Image.open(__import__("io").BytesIO(raw))


def test_renders_a_real_png() -> None:
    uri = render_captcha_image("42")

    image = _decode(uri)
    assert image.format == "PNG"


def test_width_scales_with_text_length() -> None:
    short = _decode(render_captcha_image("42"))
    long = _decode(render_captcha_image("20 * 15 = ?"))

    assert long.width > short.width
    # roughly _CHAR_ADVANCE px per character, not some fixed unrelated width
    assert long.width == len("20 * 15 = ?") * _CHAR_ADVANCE + 20


def test_two_renders_of_the_same_text_are_not_pixel_identical() -> None:
    """Re-randomized per call (colors, rotation, noise) -- rendering the
    exact same image for the same text every time would let a scraper
    memorize image -> answer pairs across requests."""
    first = base64.b64decode(render_captcha_image("SAMEANSWER").split(",", 1)[1])
    second = base64.b64decode(render_captcha_image("SAMEANSWER").split(",", 1)[1])

    assert first != second


def test_image_is_not_blank() -> None:
    """A sanity check that something was actually drawn, not just a solid
    background rectangle."""
    image = _decode(render_captcha_image("7")).convert("RGB")
    colors = image.getcolors(maxcolors=1_000_000)

    assert colors is not None
    assert len(colors) > 2  # background + noise + at least one text color

"""Distorted-text image rendering shared by the self-hosted captcha
providers (`MathCaptchaProvider`, `TextCaptchaProvider`). Renders to a
real raster PNG on purpose, never SVG: SVG's text lives in the file as a
real `<text>` node, so anyone (a scraper, an "AI") can just read the
answer straight out of the markup -- that would defeat a captcha entirely.
A PNG's pixels carry no such structured text, which is the whole point.

Needs the `discord-webapi[captcha]` extra (Pillow) -- imported lazily
(inside the function, not at module load) so importing this package never
requires Pillow unless you actually construct a self-hosted provider.
"""

from __future__ import annotations

import base64
import io
import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PIL.ImageDraw import ImageDraw

_HEIGHT = 90
_CHAR_ADVANCE = 30  # average horizontal space claimed per character
_NOISE_LINES = 4
_NOISE_DOTS = 60


def _random_light_color() -> tuple[int, int, int]:
    return (random.randint(215, 250), random.randint(215, 250), random.randint(215, 250))


def _random_dark_color() -> tuple[int, int, int]:
    return (random.randint(0, 110), random.randint(0, 110), random.randint(0, 110))


def _add_noise(draw: ImageDraw, width: int, height: int) -> None:
    # Short local squiggles rather than corner-to-corner diagonals -- long
    # lines tend to cut across several characters at once and hurt
    # legibility more than they add anti-OCR value.
    for _ in range(_NOISE_LINES):
        start = (random.randint(0, width), random.randint(0, height))
        end = (
            max(0, min(width, start[0] + random.randint(-40, 40))),
            max(0, min(height, start[1] + random.randint(-20, 20))),
        )
        draw.line([start, end], fill=_random_dark_color(), width=1)
    for _ in range(_NOISE_DOTS):
        point = (random.randint(0, width - 1), random.randint(0, height - 1))
        draw.point(point, fill=_random_dark_color())


def render_captcha_image(text: str, *, height: int = _HEIGHT) -> str:
    """Renders `text` as a distorted PNG, returns a
    `data:image/png;base64,...` URI ready for an `<img src="...">`.

    Width is sized to fit `text` (a fixed width would either clip a long
    math expression or overlap its characters into an unreadable mess).
    Distortion is deliberately re-randomized on every call for the same
    text: per-character rotation, a fresh random (but still legible)
    foreground/background color pair each time, per-character vertical
    jitter, plus a light scattering of noise lines/dots drawn *before* the
    text (not on top of it, or they'd obscure it instead of just cluttering
    the background). Rendering the exact same-looking image for the same
    text every time would let a scraper memorize image -> answer pairs
    across requests; varying the colors and layout per render (this is
    the "different colors so it can't be recognized" hardening) defeats
    that.
    """
    from PIL import Image, ImageDraw, ImageFont

    width = len(text) * _CHAR_ADVANCE + 20
    background = _random_light_color()
    image = Image.new("RGB", (width, height), background)
    draw = ImageDraw.Draw(image)
    _add_noise(draw, width, height)

    x = 10
    for char in text:
        font = ImageFont.load_default(size=random.randint(36, 44))
        color = _random_dark_color()
        char_canvas = Image.new("RGBA", (48, 64), (0, 0, 0, 0))
        char_draw = ImageDraw.Draw(char_canvas)
        char_draw.text((6, 4), char, font=font, fill=(*color, 255))
        rotated = char_canvas.rotate(
            random.uniform(-18, 18), expand=True, resample=Image.Resampling.BICUBIC
        )
        y = random.randint(4, max(5, height - 60))
        image.paste(rotated, (x, y), rotated)
        x += _CHAR_ADVANCE

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"

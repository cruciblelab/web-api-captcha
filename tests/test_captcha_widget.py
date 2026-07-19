"""Exercises `build_captcha_widget_router` -- just the serving contract
(content-type, that it's the real bundled script). The widget's actual
frontend behavior is exercised manually/with a real browser, not
something a unit test can drive."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from webapi_captcha.widget import DEFAULT_WIDGET_MOUNT_PATH, build_captcha_widget_router


def test_widget_script_is_served_at_the_default_mount_path() -> None:
    app = FastAPI()
    app.include_router(build_captcha_widget_router())
    client = TestClient(app)

    resp = client.get(DEFAULT_WIDGET_MOUNT_PATH)

    assert resp.status_code == 200
    assert "javascript" in resp.headers["content-type"]
    assert "wac-captcha-widget" in resp.text
    assert "wac-captcha-widget-log" in resp.text


def test_widget_script_can_be_mounted_at_a_custom_path() -> None:
    app = FastAPI()
    app.include_router(build_captcha_widget_router(mount_path="/assets/widget.js"))
    client = TestClient(app)

    resp = client.get("/assets/widget.js")

    assert resp.status_code == 200
    assert resp.status_code != 404


def test_widget_script_talks_to_the_gate_endpoints() -> None:
    """Sanity check that the bundled JS actually targets the real
    CaptchaGate endpoints it documents, not stale/renamed ones."""
    app = FastAPI()
    app.include_router(build_captcha_widget_router())
    client = TestClient(app)

    text = client.get(DEFAULT_WIDGET_MOUNT_PATH).text

    assert "/api/captcha/gate/" in text
    assert "/verify" in text


def test_widget_script_never_string_concatenates_the_challenge_image_into_html() -> None:
    """Regression guard for a fixed XSS-shaped bug: `image_data_uri`
    (safe for the bundled providers, but attacker-influenceable for a
    custom `CaptchaProvider`) must be assigned via the DOM `.src`
    property, never concatenated into an `innerHTML` string -- the
    latter would let a crafted value (e.g. `x" onerror="...`) execute as
    real markup/script."""
    app = FastAPI()
    app.include_router(build_captcha_widget_router())
    client = TestClient(app)

    text = client.get(DEFAULT_WIDGET_MOUNT_PATH).text

    assert 'img.src = challenge.image_data_uri' in text
    assert '<img src="' not in text

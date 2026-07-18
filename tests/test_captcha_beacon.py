"""Exercises `build_passive_risk_beacon_router` -- just the serving
contract (content-type, that it's the real bundled script, that it
targets the real passive-signal endpoint). The beacon's actual frontend
behavior is exercised manually/with a real browser, not something a unit
test can drive."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from webapi_captcha.beacon import DEFAULT_BEACON_MOUNT_PATH, build_passive_risk_beacon_router


def test_beacon_script_is_served_at_the_default_mount_path() -> None:
    app = FastAPI()
    app.include_router(build_passive_risk_beacon_router())
    client = TestClient(app)

    resp = client.get(DEFAULT_BEACON_MOUNT_PATH)

    assert resp.status_code == 200
    assert "javascript" in resp.headers["content-type"]
    assert "wac-passive-beacon-log" in resp.text


def test_beacon_script_can_be_mounted_at_a_custom_path() -> None:
    app = FastAPI()
    app.include_router(build_passive_risk_beacon_router(mount_path="/assets/beacon.js"))
    client = TestClient(app)

    resp = client.get("/assets/beacon.js")

    assert resp.status_code == 200
    assert resp.status_code != 404


def test_beacon_script_targets_the_passive_signal_endpoint_by_default() -> None:
    """Sanity check that the bundled JS's default endpoint actually
    matches build_passive_risk_router's own default mount path, not a
    stale/renamed one -- this is what makes the zero-attribute drop-in
    case work."""
    app = FastAPI()
    app.include_router(build_passive_risk_beacon_router())
    client = TestClient(app)

    text = client.get(DEFAULT_BEACON_MOUNT_PATH).text

    assert "/api/captcha/passive-signal" in text

/*
 * webapi-captcha passive-risk beacon.
 *
 * Drop-in usage (any page, with or without a captcha widget rendered):
 *   <script src="/static/webapi-captcha-beacon.js"></script>
 *
 * Optional attributes:
 *   data-endpoint      -- default "/api/captcha/passive-signal"
 *   data-api-base      -- prefix prepended to data-endpoint, same
 *                          convention as the bundled captcha widget's
 *                          data-api-base
 *   data-interval-ms    -- default 15000
 *
 * Relies on the browser sending the visitor's session/visitor cookie
 * automatically (same-origin fetch) -- no extra wiring needed for the
 * server to resolve who this is the same way PageGuard.require_human()
 * would. Fires a `wac-passive-beacon-log` CustomEvent on `document` with
 * `{ ok, detail }` for each send attempt, if a page wants visibility into
 * it -- entirely optional, same convention as the captcha widget's own
 * `wac-captcha-widget-log`.
 *
 * No UI, no DOM writes, no interaction with `.wac-captcha-widget`
 * elements or the captcha widget's own script at all -- this is purely a
 * background reporter, and every failure (network error, non-2xx,
 * endpoint not mounted) is swallowed silently, matching PageGuard's own
 * "invisible when clean" philosophy: there is nothing to show an error
 * into.
 */
(function () {
  'use strict';

  var SCRIPT_TAG = document.currentScript;
  var API_BASE = (SCRIPT_TAG && SCRIPT_TAG.getAttribute('data-api-base')) || '';
  var ENDPOINT = (SCRIPT_TAG && SCRIPT_TAG.getAttribute('data-endpoint')) || '/api/captcha/passive-signal';
  var INTERVAL_MS = parseInt((SCRIPT_TAG && SCRIPT_TAG.getAttribute('data-interval-ms')) || '15000', 10);
  var MAX_TRAJECTORY = 500;
  var URL = API_BASE + ENDPOINT;

  var pageLoadedAt = performance.now();
  var trajectory = [];
  var lastPointerType = 'mouse';

  function emit(ok, detail) {
    document.dispatchEvent(new CustomEvent('wac-passive-beacon-log', {
      detail: { ok: ok === undefined ? null : ok, detail: detail || null },
    }));
  }

  function push(e) {
    lastPointerType = e.pointerType;
    trajectory.push([e.clientX, e.clientY, performance.now()]);
    if (trajectory.length > MAX_TRAJECTORY) trajectory.shift();
  }
  window.addEventListener('pointermove', push);
  window.addEventListener('pointerdown', push);

  function collect() {
    return {
      webdriver: navigator.webdriver === true,
      language: navigator.language,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      pointer_type: lastPointerType,
      pointer_moves: trajectory.length,
      mouse_trajectory: trajectory.slice(),
      interaction_ms: performance.now() - pageLoadedAt,
    };
  }

  function report() {
    fetch(URL, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ signals: collect() }),
    }).then(function (resp) {
      emit(resp.ok, 'status ' + resp.status);
    }).catch(function (e) {
      emit(false, String(e));
    });
  }

  // A short-lived visit (many automated hits never survive one full
  // interval tick -- 15s by default) would otherwise leave zero passive
  // report ever, undercutting the whole point of this beacon for
  // exactly the traffic it exists to catch. sendBeacon survives page
  // teardown; a Blob typed application/json sets the resulting
  // request's Content-Type correctly, so the server parses it the same
  // way as the regular fetch() path, no branching needed there.
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState !== 'hidden') return;
    try {
      var blob = new Blob([JSON.stringify({ signals: collect() })], { type: 'application/json' });
      navigator.sendBeacon(URL, blob);
      emit(null, 'sendBeacon on visibilitychange');
    } catch (e) {
      emit(false, String(e));
    }
  });

  setInterval(report, INTERVAL_MS);
})();

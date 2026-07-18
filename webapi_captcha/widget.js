/*
 * webapi-captcha bundled widget.
 *
 * Drop-in usage:
 *   <div class="wac-captcha-widget" data-token="{gate_token}"></div>
 *   <script src="/static/webapi-captcha-widget.js" data-callback="onVerified"></script>
 *   <script>function onVerified(result) { ... result.verified, result.failed_check ... }</script>
 *
 * Every internal step (approach, click, animation, raw signals sent,
 * per-check pass/fail, final verdict) also fires a
 * `wac-captcha-widget-log` CustomEvent on `document` with
 * `{ token, message, ok, detail }` -- listen for it if your page wants
 * its own visible timeline instead of (or in addition to) the
 * `onVerified` callback.
 */
(function () {
  'use strict';

  var SCRIPT_TAG = document.currentScript;
  var CALLBACK_NAME = SCRIPT_TAG ? SCRIPT_TAG.getAttribute('data-callback') : null;
  var MAX_TRAJECTORY = 500;

  function emit(token, message, ok, detail) {
    document.dispatchEvent(new CustomEvent('wac-captcha-widget-log', {
      detail: { token: token, message: message, ok: ok === undefined ? null : ok, detail: detail || null },
    }));
  }

  function fireCallback(token, result) {
    if (CALLBACK_NAME && typeof window[CALLBACK_NAME] === 'function') {
      window[CALLBACK_NAME](Object.assign({ token: token }, result));
    }
  }

  function injectStyles() {
    if (document.getElementById('wac-captcha-widget-styles')) return;
    var style = document.createElement('style');
    style.id = 'wac-captcha-widget-styles';
    style.textContent = [
      '.wac-captcha-widget{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;',
      'max-width:300px;color:#1a1a1a;}',
      '.wac-cw-box{display:flex;align-items:center;gap:12px;padding:14px 16px;',
      'border:1px solid #e3e3e8;border-radius:12px;background:#fff;cursor:pointer;',
      'user-select:none;box-shadow:0 1px 3px rgba(0,0,0,.06);transition:box-shadow .15s ease,border-color .15s ease;}',
      '.wac-cw-box:hover{box-shadow:0 2px 8px rgba(0,0,0,.09);border-color:#d0d0d8;}',
      '.wac-cw-box.wac-cw-done{cursor:default;}',
      '.wac-cw-checkbox{flex:0 0 auto;width:24px;height:24px;border-radius:7px;',
      'border:2px solid #b7b7c2;background:#fff;display:flex;align-items:center;justify-content:center;',
      'transition:all .18s ease;}',
      '.wac-cw-checkbox svg{width:15px;height:15px;opacity:0;transform:scale(.5);transition:all .18s ease;}',
      '.wac-cw-checkbox.wac-cw-ok{background:#1fa564;border-color:#1fa564;}',
      '.wac-cw-checkbox.wac-cw-ok svg{opacity:1;transform:scale(1);}',
      '.wac-cw-checkbox.wac-cw-fail{background:#e5484d;border-color:#e5484d;}',
      '.wac-cw-checkbox.wac-cw-fail svg{opacity:1;transform:scale(1);}',
      '.wac-cw-spinner{width:18px;height:18px;border-radius:50%;',
      'background:conic-gradient(from 0deg,#2b6fff,transparent 70%);',
      '-webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 3px),#000 calc(100% - 3px));',
      'mask:radial-gradient(farthest-side,transparent calc(100% - 3px),#000 calc(100% - 3px));',
      'animation:wac-cw-spin .8s linear infinite;display:none;}',
      '@keyframes wac-cw-spin{to{transform:rotate(360deg);}}',
      '.wac-cw-label{font-size:.92rem;color:#3a3a42;}',
      '.wac-cw-expand{margin-top:12px;padding-top:12px;border-top:1px solid #ececf0;',
      'display:none;font-size:.85rem;}',
      '.wac-cw-expand.wac-cw-shown{display:block;}',
      '.wac-cw-expand img{max-width:100%;border-radius:6px;display:block;margin-bottom:8px;}',
      '.wac-cw-expand input[type=text]{padding:6px 8px;width:60%;border:1px solid #ccc;border-radius:6px;}',
      '.wac-cw-expand button{padding:6px 12px;border:1px solid #ccc;border-radius:6px;background:#f4f4f7;',
      'cursor:pointer;margin-left:6px;}',
      '.wac-cw-canvas{touch-action:none;cursor:crosshair;border:1px solid #ddd;border-radius:6px;}',
      '@media (prefers-color-scheme: dark){',
      '.wac-captcha-widget{color:#e6e6ea;}',
      '.wac-cw-box{background:#1e1e24;border-color:#33333c;}',
      '.wac-cw-box:hover{border-color:#45454f;}',
      '.wac-cw-checkbox{background:#1e1e24;border-color:#55555f;}',
      '.wac-cw-label{color:#c7c7d1;}',
      '.wac-cw-expand{border-top-color:#33333c;}',
      '.wac-cw-expand button{background:#2a2a32;border-color:#45454f;color:#e6e6ea;}',
      '}',
    ].join('');
    document.head.appendChild(style);
  }

  var CHECK_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3" ' +
    'stroke-linecap="round" stroke-linejoin="round"><path d="M4 12l5 5L20 6"/></svg>';
  var CROSS_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3" ' +
    'stroke-linecap="round" stroke-linejoin="round"><path d="M5 5l14 14M19 5L5 19"/></svg>';

  // -- path-trace geometry, mirrors webapi_captcha/providers/path_trace.py --
  function distPointToSegment(p, a, b) {
    var dx = b[0] - a[0], dy = b[1] - a[1];
    if (dx === 0 && dy === 0) return Math.hypot(p[0] - a[0], p[1] - a[1]);
    var t = ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / (dx * dx + dy * dy);
    t = Math.max(0, Math.min(1, t));
    return Math.hypot(p[0] - (a[0] + t * dx), p[1] - (a[1] + t * dy));
  }
  function distPointToPolyline(p, poly) {
    var best = Infinity;
    for (var i = 0; i < poly.length - 1; i++) best = Math.min(best, distPointToSegment(p, poly[i], poly[i + 1]));
    return best;
  }

  async function sha256LeadingZeroBits(text) {
    var buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    var bytes = new Uint8Array(buf);
    var bits = 0;
    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] === 0) { bits += 8; continue; }
      var leading = 0;
      for (var b = 7; b >= 0; b--) { if ((bytes[i] >> b) & 1) break; leading++; }
      bits += leading;
      break;
    }
    return bits;
  }

  function CaptchaWidget(el) {
    this.el = el;
    this.token = el.getAttribute('data-token');
    // Only needed when build_captcha_router(gate=...) is mounted more
    // than once (one prefix per CaptchaGate purpose) instead of the
    // single unprefixed app.state.webapi_captcha_gate -- point
    // this at the matching prefix, e.g. data-api-base="/giveaway".
    this.apiBase = el.getAttribute('data-api-base') || '';
    this.pageLoadedAt = performance.now();
    this.trajectory = [];
    this.lastPointerType = 'mouse';
    this.clickOffset = null;
    this.captchaResponse = null;
    this.needsExplicitAnswer = false;
    this.busy = false;
    this.verified = false;
    this.approached = false;
    this.build();
    this.trackMovement();
    this.loadInfo();
  }

  CaptchaWidget.prototype.since = function (t) { return Math.round(t - this.pageLoadedAt); };

  CaptchaWidget.prototype.build = function () {
    this.el.innerHTML =
      '<div class="wac-cw-box"><div class="wac-cw-checkbox">' + CHECK_SVG.replace('<svg', '<svg style="display:none"') + '</div>' +
      '<div class="wac-cw-spinner"></div><span class="wac-cw-label">Verify I\'m human</span></div>' +
      '<div class="wac-cw-expand"></div>';
    this.boxEl = this.el.querySelector('.wac-cw-box');
    this.checkboxEl = this.el.querySelector('.wac-cw-checkbox');
    this.spinnerEl = this.el.querySelector('.wac-cw-spinner');
    this.labelEl = this.el.querySelector('.wac-cw-label');
    this.expandEl = this.el.querySelector('.wac-cw-expand');
    this.checkboxEl.innerHTML = '';

    var self = this;
    this.boxEl.addEventListener('pointerenter', function (e) {
      self.lastSeenPointerType = e.pointerType;
      if (self.approached) return;
      self.approached = true;
      emit(self.token, 'widget: approached', null, self.since(performance.now()) + 'ms, pointer_type=' + e.pointerType);
    });
    this.boxEl.addEventListener('pointerleave', function (e) {
      if (self.approached && !self.busy && e.pointerType !== 'touch' && e.pointerType !== 'pen') {
        emit(self.token, 'widget: left (not clicked yet)', null, self.since(performance.now()) + 'ms');
      }
    });
    this.boxEl.addEventListener('click', function (e) { self.onBoxClick(e); });
  };

  CaptchaWidget.prototype.trackMovement = function () {
    var self = this;
    function push(e) {
      self.lastPointerType = e.pointerType;
      self.trajectory.push([e.clientX, e.clientY, performance.now()]);
      if (self.trajectory.length > MAX_TRAJECTORY) self.trajectory.shift();
    }
    window.addEventListener('pointermove', push);
    window.addEventListener('pointerdown', push);
  };

  CaptchaWidget.prototype.currentSignals = function () {
    return {
      webdriver: navigator.webdriver === true,
      language: navigator.language,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      pointer_type: this.lastPointerType,
      pointer_moves: this.trajectory.length,
      mouse_trajectory: this.trajectory.slice(),
      click_offset: this.clickOffset,
      interaction_ms: performance.now() - this.pageLoadedAt,
    };
  };

  CaptchaWidget.prototype.loadInfo = async function () {
    try {
      var resp = await fetch(this.apiBase + '/api/captcha/gate/' + this.token);
      if (!resp.ok) { this.showFatalError('This verification link is invalid or has expired.'); return; }
      this.info = await resp.json();
    } catch (e) {
      this.showFatalError('Could not reach the server.');
      return;
    }
    if (this.info.verified) {
      // A page reload (or any re-fetch of /api/captcha/gate/{token}) after
      // a successful verification hits this same endpoint again -- without
      // this branch it fell into the `!resp.ok` case above (the server
      // used to return 404 for an already-verified token, indistinguishable
      // from a truly expired one) and showed the wrong, confusing "invalid
      // or expired" message for a link that actually already succeeded.
      // Show the real state instead: already done, nothing left to click.
      this.showAlreadyVerified();
      return;
    }
    if (this.info.requires_captcha && this.info.challenge) {
      this.renderChallenge(this.info.challenge);
    }
  };

  CaptchaWidget.prototype.showAlreadyVerified = function () {
    this.verified = true;
    this.busy = true;
    this.checkboxEl.classList.add('wac-cw-ok');
    this.checkboxEl.innerHTML = CHECK_SVG;
    this.labelEl.textContent = 'Already verified';
    this.boxEl.style.cursor = 'default';
    this.boxEl.classList.add('wac-cw-done');
    emit(this.token, 'widget: already verified', true, 'page reloaded, this link was already used');
    fireCallback(this.token, { verified: true, failed_check: null, detail: null });
  };

  CaptchaWidget.prototype.showFatalError = function (msg) {
    this.labelEl.textContent = msg;
    this.boxEl.style.cursor = 'default';
    this.boxEl.removeEventListener('click', this.onBoxClick);
    emit(this.token, 'widget: error', false, msg);
  };

  CaptchaWidget.prototype.showExpand = function (html) {
    this.expandEl.innerHTML = html;
    this.expandEl.classList.add('wac-cw-shown');
  };

  CaptchaWidget.prototype.renderChallenge = function (challenge) {
    if (challenge.kind === 'math' || challenge.kind === 'text') this.renderImageChallenge(challenge);
    else if (challenge.kind === 'pow') this.renderPowChallenge(challenge);
    else if (challenge.kind === 'path-trace') this.renderPathTraceChallenge(challenge);
    else if (challenge.kind === 'recaptcha') this.renderThirdParty(challenge, 'recaptcha', 'https://www.google.com/recaptcha/api.js', 'g-recaptcha');
    else if (challenge.kind === 'hcaptcha') this.renderThirdParty(challenge, 'hcaptcha', 'https://js.hcaptcha.com/1/api.js', 'h-captcha');
  };

  // -- math / text: image + text input + its own submit button --
  CaptchaWidget.prototype.renderImageChallenge = function (challenge) {
    this.needsExplicitAnswer = true;
    this.labelEl.textContent = 'Solve the question below';
    this.showExpand(
      '<img src="' + challenge.image_data_uri + '" alt="captcha" />' +
      '<input type="text" class="wac-cw-answer" placeholder="your answer" />' +
      '<button type="button" class="wac-cw-submit">Verify</button>'
    );
    var self = this;
    this.expandEl.querySelector('.wac-cw-submit').addEventListener('click', function (e) {
      e.stopPropagation();
      self.captchaResponse = self.expandEl.querySelector('.wac-cw-answer').value;
      emit(self.token, 'widget: sending answer', null, 'entered answer: "' + self.captchaResponse + '"');
      self.runVerification(e);
    });
    emit(this.token, 'widget: image captcha loaded', null, challenge.prompt);
  };

  // -- proof-of-work: fully automatic, no UI, runs before the click even matters --
  CaptchaWidget.prototype.renderPowChallenge = function (challenge) {
    var self = this;
    this.labelEl.textContent = 'Preparing...';
    this.boxEl.style.pointerEvents = 'none';
    var prefix = challenge.params.prefix, difficulty = challenge.params.difficulty;
    emit(this.token, 'widget: searching for proof-of-work', null, 'difficulty ' + difficulty + ' bits');
    (async function () {
      var start = performance.now();
      var nonce = 0;
      while (true) {
        var bits = await sha256LeadingZeroBits(prefix + nonce);
        if (bits >= difficulty) break;
        nonce++;
        if (nonce % 500 === 0) await new Promise(function (r) { setTimeout(r, 0); });
      }
      self.captchaResponse = String(nonce);
      self.labelEl.textContent = 'Verify I\'m human';
      self.boxEl.style.pointerEvents = '';
      emit(self.token, 'widget: proof-of-work complete', null,
        nonce + ' attempts, ' + Math.round(performance.now() - start) + 'ms');
    })();
  };

  // -- path-trace: inline canvas, its own submit button --
  CaptchaWidget.prototype.renderPathTraceChallenge = function (challenge) {
    this.needsExplicitAnswer = true;
    this.labelEl.textContent = 'Trace the line';
    var p = challenge.params;
    this.showExpand(
      '<canvas class="wac-cw-canvas" width="' + p.width + '" height="' + p.height + '"></canvas><br/>' +
      '<button type="button" class="wac-cw-submit">Verify</button>'
    );
    var canvas = this.expandEl.querySelector('canvas');
    var ctx = canvas.getContext('2d');
    var tracePoints = [];
    var tracing = false;
    function redraw() {
      ctx.clearRect(0, 0, p.width, p.height);
      ctx.strokeStyle = '#c9c9d2'; ctx.lineWidth = p.tolerance * 2;
      ctx.lineCap = 'round'; ctx.lineJoin = 'round';
      ctx.beginPath();
      p.path.forEach(function (pt, i) { i === 0 ? ctx.moveTo(pt[0], pt[1]) : ctx.lineTo(pt[0], pt[1]); });
      ctx.stroke();
      ctx.strokeStyle = '#2b6fff'; ctx.lineWidth = 2;
      ctx.beginPath();
      tracePoints.forEach(function (pt, i) { i === 0 ? ctx.moveTo(pt[0], pt[1]) : ctx.lineTo(pt[0], pt[1]); });
      ctx.stroke();
    }
    redraw();
    // Map a pointer event to the canvas's OWN drawing coordinate space
    // (the `width`/`height` HTML attributes, i.e. what `p.path` and the
    // server's tolerance check are both in pixels of), not the CSS box
    // it happens to render at. Those two can differ -- `.wac-captcha-
    // widget{max-width:300px}` is narrower than this canvas's native
    // 320px, and a host page's own CSS (a `canvas{max-width:100%}`-style
    // reset, a narrower container, browser zoom, ...) can shrink or
    // stretch the rendered box further. Without this scale correction, a
    // real user's faithfully-traced line gets recorded in the WRONG
    // coordinate space -- systematically offset/distorted relative to
    // the reference path -- and can fail tolerance checks that a
    // perfectly good trace should pass (a rendered-vs-native size
    // mismatch looks exactly like the line being subtly flattened/warped
    // relative to what the user actually drew).
    function toCanvasPoint(e) {
      var r = canvas.getBoundingClientRect();
      var scaleX = canvas.width / r.width;
      var scaleY = canvas.height / r.height;
      // The 3rd element (performance.now(), a monotonic clock, same as
      // mouse_trajectory's t_ms elsewhere) lets the server tell a
      // suspiciously constant-speed/constant-interval trace -- a script
      // stepping along the known path at fixed increments -- apart from
      // natural hand motion, which never holds perfectly steady speed or
      // timing. See PathTraceProvider's docstring.
      return [(e.clientX - r.left) * scaleX, (e.clientY - r.top) * scaleY, performance.now()];
    }
    canvas.addEventListener('pointerdown', function (e) {
      tracing = true; tracePoints = [];
      tracePoints.push(toCanvasPoint(e));
      redraw();
    });
    canvas.addEventListener('pointermove', function (e) {
      if (!tracing) return;
      tracePoints.push(toCanvasPoint(e));
      redraw();
    });
    window.addEventListener('pointerup', function () { tracing = false; });

    var self = this;
    this.expandEl.querySelector('.wac-cw-submit').addEventListener('click', function (e) {
      e.stopPropagation();
      if (tracePoints.length === 0) {
        emit(self.token, 'widget: trace could not be submitted', false, 'no points were traced');
        return;
      }
      var maxDev = Math.max.apply(null, tracePoints.map(function (pt) { return distPointToPolyline(pt, p.path); }));
      var uncovered = p.path.filter(function (v) {
        return Math.min.apply(null, tracePoints.map(function (pt) { return Math.hypot(pt[0] - v[0], pt[1] - v[1]); })) > p.tolerance;
      }).length;
      emit(self.token, 'widget: submitting trace', null,
        tracePoints.length + ' points, max deviation ' + maxDev.toFixed(1) + 'px (tolerance ' + p.tolerance + 'px), uncovered vertices ' + uncovered + '/' + p.path.length);
      self.captchaResponse = JSON.stringify(tracePoints);
      self.runVerification(e);
    });
    emit(this.token, 'widget: path-trace loaded', null, p.path.length + ' points, tolerance ' + p.tolerance + 'px');
  };

  // -- reCAPTCHA / hCaptcha: embed the real widget, our own submit button reads its token --
  CaptchaWidget.prototype.renderThirdParty = function (challenge, kind, scriptUrl, cssClass) {
    this.needsExplicitAnswer = true;
    this.labelEl.textContent = 'Complete the verification below';
    this.showExpand('<div class="' + cssClass + '" data-sitekey="' + challenge.site_key + '"></div>' +
      '<button type="button" class="wac-cw-submit">Verify</button>');
    if (!document.querySelector('script[data-wac-' + kind + ']')) {
      var s = document.createElement('script');
      s.src = scriptUrl; s.async = true; s.defer = true; s.setAttribute('data-wac-' + kind, '1');
      document.body.appendChild(s);
    }
    var self = this;
    this.expandEl.querySelector('.wac-cw-submit').addEventListener('click', function (e) {
      e.stopPropagation();
      if (kind === 'recaptcha') {
        self.captchaResponse = window.grecaptcha ? window.grecaptcha.getResponse() : '';
      } else {
        var el = document.querySelector('[name="h-captcha-response"]');
        self.captchaResponse = el ? el.value : '';
      }
      emit(self.token, 'widget: ' + kind + ' submitting response', null);
      self.runVerification(e);
    });
    emit(this.token, 'widget: ' + kind + ' loaded', null);
  };

  CaptchaWidget.prototype.onBoxClick = function (e) {
    if (this.busy || this.verified) return;
    if (this.needsExplicitAnswer) {
      // Image/canvas/3rd-party challenges are solved and submitted from
      // their own button in the expanded panel below -- clicking the
      // checkbox itself does nothing but isn't an error either.
      return;
    }
    this.runVerification(e);
  };

  CaptchaWidget.prototype.runVerification = async function (e) {
    if (this.busy || this.verified) return;
    this.busy = true;
    var rect = this.boxEl.getBoundingClientRect();
    var cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
    this.clickOffset = Math.hypot(e.clientX - cx, e.clientY - cy);
    var touchNote = (this.lastSeenPointerType === 'touch' || this.lastSeenPointerType === 'pen')
      ? ' [touch: approach+click are part of the same touch, this is normal]' : '';
    emit(this.token, 'widget: verification triggered', null,
      'offset from center=' + this.clickOffset.toFixed(1) + 'px, ' + this.since(performance.now()) + 'ms' + touchNote);

    this.spinnerEl.style.display = 'inline-block';
    this.labelEl.textContent = 'Checking...';
    var frozenSignals = this.currentSignals();
    await new Promise(function (r) { setTimeout(r, 600); });

    emit(this.token, 'widget: sending to server', null,
      'pointer_type=' + frozenSignals.pointer_type + ', pointer_moves=' + frozenSignals.pointer_moves +
      ', interaction_ms=' + frozenSignals.interaction_ms.toFixed(0));

    var resp = await fetch(this.apiBase + '/api/captcha/gate/' + this.token + '/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ captcha_response: this.captchaResponse, signals: frozenSignals }),
    });
    var result = await resp.json();
    this.spinnerEl.style.display = 'none';
    this.boxEl.classList.add('wac-cw-done');

    if (result.verified) {
      // Freeze permanently in the verified state -- do NOT re-arm. A
      // verified token is one-time-use server-side (re-posting it just
      // returns the same success idempotently, without re-running any
      // check), so resetting the widget back to "click me" only invites
      // the user to solve the same captcha over and over into an
      // already-done result. Once it's green, it stays green.
      this.verified = true;
      this.checkboxEl.classList.add('wac-cw-ok');
      this.checkboxEl.innerHTML = CHECK_SVG;
      this.labelEl.textContent = 'Verified';
      this.boxEl.style.cursor = 'default';
      // Collapse any challenge panel (math image / trace canvas / 3rd
      // party) so its now-spent submit button can't be clicked again.
      this.expandEl.classList.remove('wac-cw-shown');
      this.expandEl.innerHTML = '';
      emit(this.token, 'widget: verification result', true);
      fireCallback(this.token, result);
      return;  // leave busy=true forever: no further clicks do anything
    }

    this.checkboxEl.classList.add('wac-cw-fail');
    this.checkboxEl.innerHTML = CROSS_SVG;
    this.labelEl.textContent = result.detail || 'Verification failed';
    emit(this.token, 'widget: verification result', false, result.failed_check || result.detail);
    fireCallback(this.token, result);

    // Only re-arm after a FAILURE, so a genuine retry (wrong math answer,
    // a sloppy trace) is still possible.
    var self = this;
    setTimeout(function () {
      self.busy = false;
      self.boxEl.classList.remove('wac-cw-done');
      self.checkboxEl.className = 'wac-cw-checkbox';
      self.checkboxEl.innerHTML = '';
      self.labelEl.textContent = self.needsExplicitAnswer ? 'Try again' : 'Verify I\'m human';
    }, 2500);
  };

  function init() {
    var nodes = document.querySelectorAll('.wac-captcha-widget:not([data-wac-initialized])');
    if (nodes.length === 0) return;
    injectStyles();
    nodes.forEach(function (el) {
      el.setAttribute('data-wac-initialized', 'true');
      new CaptchaWidget(el);
    });
  }

  // Exposed so a page that injects `.wac-captcha-widget` divs dynamically
  // (a fresh token after the initial page load, an SPA route change, ...)
  // can (re)scan for new ones without a full page reload.
  window.wacCaptchaWidgetInit = init;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

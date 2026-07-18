"""`webapi_captcha` -- pluggable, adaptive human-verification/captcha for
FastAPI, usable two ways:

- **Plain web usage**: mount `build_captcha_router()`, register one or
  more `CaptchaProvider`s by name, protect any point on your own site.
- **Gated verification**: `CaptchaGate` ties a challenge to a
  (user_id, purpose) and publishes a Transport event the moment
  it's solved -- see `webapi_captcha.gate` for the giveaway-bot
  scenario this was built for.

Two self-hosted providers ship here (`MathCaptchaProvider`,
`TextCaptchaProvider` -- both need the `webapi-captcha[render]` extra,
Pillow, for real distorted-image rendering), plus three third-party widget
wrappers (`ReCaptchaProvider`, `HCaptchaProvider`, `TurnstileProvider` --
need only `httpx`, already a core dependency). Write your own provider for
anything else by implementing `CaptchaProvider` -- no inheritance needed,
same "bring your own" pattern as every Store in this package.

Nothing here assumes Discord, or any particular login system -- see
`webapi_captcha.api.build_captcha_router`'s `current_user_id_resolver`
for how account-binding (`AccountMatchCheck`) plugs into whatever auth
your app already has.
"""

from typing import TYPE_CHECKING

from webapi_captcha.adaptive import (
    AdaptiveCaptchaGate,
    AdaptiveDecision,
    AdaptiveDecisionStore,
    MemoryAdaptiveDecisionStore,
    MemoryTrustStore,
    TrustStore,
)
from webapi_captcha.api import build_captcha_router
from webapi_captcha.base import CaptchaProvider, CaptchaStore, VerificationStore
from webapi_captcha.beacon import DEFAULT_BEACON_MOUNT_PATH, build_passive_risk_beacon_router
from webapi_captcha.checks import (
    AccountMatchCheck,
    CaptchaCheck,
    CheckOutcome,
    PredicateCheck,
    VerificationCheck,
    VerificationContext,
)
from webapi_captcha.events import EVENT_TYPE_CAPTCHA_VERIFIED, CaptchaVerified
from webapi_captcha.gate import CaptchaGate, CheckResult
from webapi_captcha.memory import MemoryCaptchaStore, MemoryVerificationStore
from webapi_captcha.models import CaptchaChallenge, PendingCaptcha, VerificationRequest
from webapi_captcha.pageguard import (
    DEFAULT_COOKIE_MAX_AGE,
    DEFAULT_COOKIE_NAME,
    PageGuard,
    PageGuardRedirect,
    build_passive_risk_router,
    missing_accept_language,
    suspicious_user_agent,
)
from webapi_captcha.presets import CloudflareStyleGuard, build_cloudflare_style_guard
from webapi_captcha.providers.fallback import FallbackCaptchaProvider
from webapi_captcha.providers.hcaptcha import HCaptchaProvider
from webapi_captcha.providers.math_captcha import MathCaptchaProvider
from webapi_captcha.providers.path_trace import PathTraceProvider
from webapi_captcha.providers.proof_of_work import LoadAdaptiveDifficulty, ProofOfWorkProvider
from webapi_captcha.providers.recaptcha import ReCaptchaProvider
from webapi_captcha.providers.text_captcha import TextCaptchaProvider
from webapi_captcha.providers.turnstile import TurnstileProvider
from webapi_captcha.receipts import TrustReceipt, TrustTokenIssuer, TrustTokenVerifier
from webapi_captcha.replay_guard import (
    DEFAULT_GRID_MS,
    DEFAULT_GRID_PX,
    DEFAULT_MAX_FINGERPRINT_POINTS,
    DEFAULT_MIN_FINGERPRINT_POINTS,
    MemoryTrajectoryFingerprintStore,
    RepeatedMovementCheck,
    TrajectoryFingerprintStore,
    fingerprint_trajectory,
)
from webapi_captcha.reputation import IPReputationChecker, StaticBlocklistReputationChecker
from webapi_captcha.risk import (
    BehaviorScoreRiskSignal,
    CorroboratedRiskSignal,
    MemoryRunningRiskStore,
    ReplayRiskSignal,
    ReputationRiskSignal,
    RiskAssessment,
    RiskContext,
    RiskContribution,
    RiskEngine,
    RiskLevel,
    RiskSignal,
    RunningRiskStore,
)
from webapi_captcha.scoring import (
    ScoringHeuristic,
    SignalScoreCheck,
    default_behavior_heuristics,
)
from webapi_captcha.signals import (
    DEFAULT_HEADLESS_UA_PATTERNS,
    honeypot_field_empty,
    reject_headless_user_agent,
    reject_webdriver,
    require_min_interaction_ms,
    require_signal_flag,
)
from webapi_captcha.tiered import TieredRunningRiskStore, TieredTrustStore
from webapi_captcha.transport import Event, Transport
from webapi_captcha.widget import DEFAULT_WIDGET_MOUNT_PATH, build_captcha_widget_router

if TYPE_CHECKING:
    from webapi_captcha.redis_store import RedisRunningRiskStore, RedisTrustStore
    from webapi_captcha.sql import (
        SQLAdaptiveDecisionStore,
        SQLCaptchaStore,
        SQLRunningRiskStore,
        SQLTrajectoryFingerprintStore,
        SQLTrustStore,
        SQLVerificationStore,
    )

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_BEACON_MOUNT_PATH",
    "DEFAULT_COOKIE_MAX_AGE",
    "DEFAULT_COOKIE_NAME",
    "DEFAULT_GRID_MS",
    "DEFAULT_GRID_PX",
    "DEFAULT_HEADLESS_UA_PATTERNS",
    "DEFAULT_MAX_FINGERPRINT_POINTS",
    "DEFAULT_MIN_FINGERPRINT_POINTS",
    "DEFAULT_WIDGET_MOUNT_PATH",
    "EVENT_TYPE_CAPTCHA_VERIFIED",
    "AccountMatchCheck",
    "AdaptiveCaptchaGate",
    "AdaptiveDecision",
    "AdaptiveDecisionStore",
    "BehaviorScoreRiskSignal",
    "CaptchaChallenge",
    "CaptchaCheck",
    "CaptchaGate",
    "CaptchaProvider",
    "CaptchaStore",
    "CaptchaVerified",
    "CheckOutcome",
    "CheckResult",
    "CloudflareStyleGuard",
    "CorroboratedRiskSignal",
    "Event",
    "FallbackCaptchaProvider",
    "HCaptchaProvider",
    "IPReputationChecker",
    "MathCaptchaProvider",
    "MemoryAdaptiveDecisionStore",
    "MemoryCaptchaStore",
    "MemoryRunningRiskStore",
    "MemoryTrajectoryFingerprintStore",
    "MemoryTrustStore",
    "MemoryVerificationStore",
    "PageGuard",
    "PageGuardRedirect",
    "PathTraceProvider",
    "PendingCaptcha",
    "PredicateCheck",
    "LoadAdaptiveDifficulty",
    "ProofOfWorkProvider",
    "ReCaptchaProvider",
    "RedisRunningRiskStore",
    "RedisTrustStore",
    "RepeatedMovementCheck",
    "ReplayRiskSignal",
    "ReputationRiskSignal",
    "RiskAssessment",
    "RiskContext",
    "RiskContribution",
    "RiskEngine",
    "RiskLevel",
    "RiskSignal",
    "RunningRiskStore",
    "SQLAdaptiveDecisionStore",
    "SQLCaptchaStore",
    "SQLRunningRiskStore",
    "SQLTrajectoryFingerprintStore",
    "SQLTrustStore",
    "SQLVerificationStore",
    "ScoringHeuristic",
    "SignalScoreCheck",
    "StaticBlocklistReputationChecker",
    "TextCaptchaProvider",
    "TieredRunningRiskStore",
    "TieredTrustStore",
    "TrajectoryFingerprintStore",
    "Transport",
    "TrustReceipt",
    "TrustStore",
    "TrustTokenIssuer",
    "TrustTokenVerifier",
    "TurnstileProvider",
    "VerificationCheck",
    "VerificationContext",
    "VerificationRequest",
    "VerificationStore",
    "build_captcha_router",
    "build_captcha_widget_router",
    "build_cloudflare_style_guard",
    "build_passive_risk_beacon_router",
    "build_passive_risk_router",
    "default_behavior_heuristics",
    "fingerprint_trajectory",
    "honeypot_field_empty",
    "missing_accept_language",
    "reject_headless_user_agent",
    "reject_webdriver",
    "require_min_interaction_ms",
    "require_signal_flag",
    "suspicious_user_agent",
]


def __getattr__(name: str) -> object:
    # SQL* stores need the optional `sql` extra (`webapi-captcha[sql]`) --
    # imported lazily so the base package never requires SQLAlchemy.
    if name in (
        "SQLCaptchaStore",
        "SQLVerificationStore",
        "SQLTrajectoryFingerprintStore",
        "SQLAdaptiveDecisionStore",
        "SQLTrustStore",
        "SQLRunningRiskStore",
    ):
        from webapi_captcha import sql

        return getattr(sql, name)
    # Redis* stores need the optional `redis` extra (`webapi-captcha
    # [redis]`) -- imported lazily so the base package never requires
    # redis-py.
    if name in ("RedisTrustStore", "RedisRunningRiskStore"):
        from webapi_captcha import redis_store

        return getattr(redis_store, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

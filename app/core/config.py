"""
core/config.py
──────────────
Single source of truth for all application settings.
Every value can be overridden via the .env file.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    # ── Application ────────────────────────────────────────────────
    APP_NAME: str = "Adaptive Auth System"
    ENVIRONMENT: str = "development"          # development | production
    DEBUG: bool = False
    ALLOWED_ORIGINS: str = "http://localhost:8000"  # comma-separated in .env

    # ── Database ───────────────────────────────────────────────────
    DB_HOST: str = "localhost"
    DB_PORT: int = 3306
    DB_NAME: str = "adaptive_auth"
    DB_USER: str = "root"
    DB_PASSWORD: str = "password"

    # ── Redis ──────────────────────────────────────────────────────
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str = ""               # empty = no auth (local dev)

    # ── JWT ────────────────────────────────────────────────────────
    SECRET_KEY: str = Field(default="change-me-in-production-use-a-strong-random-string")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── Account Lockout ────────────────────────────────────────────
    MAX_FAILED_LOGINS: int = 5            # lock after this many failures
    LOCKOUT_DURATION_MINUTES: int = 15    # locked for this many minutes

    # ── Password Policy ────────────────────────────────────────────
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_REQUIRE_UPPER: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True

    # ── MFA ────────────────────────────────────────────────────────
    MFA_CHALLENGE_TTL_SECONDS: int = 300   # challenge expires after 5 min
    MFA_MAX_ACTIVE_CHALLENGES: int = 3     # max pending challenges per user

    # ── Behaviour Monitoring Windows (seconds) ─────────────────────
    MFA_WINDOW_SECONDS: int = 120
    LOGIN_WINDOW_SECONDS: int = 300
    APPROVAL_WINDOW_SECONDS: int = 120

    # ── Behaviour Trigger Counts ───────────────────────────────────
    MFA_REQUEST_LIMIT: int = 3
    LOGIN_ATTEMPT_LIMIT: int = 5
    APPROVAL_LIMIT: int = 3

    # ── Risk Score Weights ─────────────────────────────────────────
    WEIGHT_EXCESS_MFA: int = 30
    WEIGHT_RAPID_LOGIN: int = 20
    WEIGHT_REPEATED_APPROVALS: int = 25
    WEIGHT_NEW_DEVICE: int = 20
    WEIGHT_IP_CHANGE: int = 15
    WEIGHT_IMPOSSIBLE_TRAVEL: int = 40
    WEIGHT_OFF_HOURS: int = 10

    # ── Decision Thresholds ────────────────────────────────────────
    THRESHOLD_ALLOW: int = 39
    THRESHOLD_VERIFY: int = 69

    # ── Rate Limiting ──────────────────────────────────────────────
    RATE_LIMIT_LOGIN: str = "10/minute"
    RATE_LIMIT_REGISTER: str = "5/minute"
    RATE_LIMIT_MFA: str = "20/minute"

    # ── Off-Hours Definition ───────────────────────────────────────
    OFF_HOURS_START: int = 22              # 10 PM
    OFF_HOURS_END: int = 6                 # 6 AM

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )

    @property
    def REDIS_URL(self) -> str:
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",")]


settings = Settings()

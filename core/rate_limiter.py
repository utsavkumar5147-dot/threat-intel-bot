from datetime import datetime, timedelta, timezone

from investigation_store import connect

# Conservative local safety limits.
# Adjust these only after checking your provider plan.
PROVIDER_LIMITS = {
    "abuseipdb": {
        "interval_seconds": 60,
        "daily_limit": 100
    },
    "virustotal": {
        "interval_seconds": 60,
        "daily_limit": 100
    }
}


def initialize_rate_limiter():
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS api_rate_limits (
                provider TEXT PRIMARY KEY,
                last_request_at REAL NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS api_request_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                requested_at REAL NOT NULL
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_api_request_log
            ON api_request_log(provider, requested_at)
        """)


def acquire_permission(provider):
    initialize_rate_limiter()

    if provider not in PROVIDER_LIMITS:
        raise ValueError("Unknown provider")

    config = PROVIDER_LIMITS[provider]
    now = datetime.now(timezone.utc).timestamp()
    day_ago = now - 86400

    with connect() as db:
        db.execute("BEGIN IMMEDIATE")

        db.execute("""
            CREATE TABLE IF NOT EXISTS api_provider_cooldowns (
                provider TEXT PRIMARY KEY,
                blocked_until REAL NOT NULL
            )
        """)

        cooldown = db.execute("""
            SELECT blocked_until
            FROM api_provider_cooldowns
            WHERE provider = ?
        """, (provider,)).fetchone()

        if cooldown and cooldown["blocked_until"] > now:
            return False, round(
                cooldown["blocked_until"] - now, 2
            )

        # Enforce the existing per-request cooldown.
        row = db.execute("""
            SELECT last_request_at
            FROM api_rate_limits
            WHERE provider = ?
        """, (provider,)).fetchone()

        if row:
            wait = (
                config["interval_seconds"]
                - (now - row["last_request_at"])
            )

            if wait > 0:
                return False, round(wait, 2)

        # Enforce a rolling 24-hour request limit.
        usage = db.execute("""
            SELECT COUNT(*) AS total
            FROM api_request_log
            WHERE provider = ?
              AND requested_at > ?
        """, (provider, day_ago)).fetchone()["total"]

        if usage >= config["daily_limit"]:
            oldest = db.execute("""
                SELECT requested_at
                FROM api_request_log
                WHERE provider = ?
                  AND requested_at > ?
                ORDER BY requested_at ASC
                LIMIT 1
            """, (provider, day_ago)).fetchone()

            wait = max(
                1,
                oldest["requested_at"] + 86400 - now
            )

            return False, round(wait, 2)

        # Reserve the request before the HTTP call.
        db.execute("""
            INSERT INTO api_request_log (
                provider, requested_at
            )
            VALUES (?, ?)
        """, (provider, now))

        db.execute("""
            INSERT INTO api_rate_limits (
                provider, last_request_at
            )
            VALUES (?, ?)
            ON CONFLICT(provider)
            DO UPDATE SET
                last_request_at = excluded.last_request_at
        """, (provider, now))

        return True, 0


def get_quota_status():
    initialize_rate_limiter()

    now = datetime.now(timezone.utc).timestamp()
    result = {}

    with connect() as db:
        for provider, config in PROVIDER_LIMITS.items():
            used = db.execute("""
                SELECT COUNT(*) AS total
                FROM api_request_log
                WHERE provider = ?
                  AND requested_at > ?
            """, (
                provider,
                now - 86400
            )).fetchone()["total"]

            result[provider] = {
                "used": used,
                "limit": config["daily_limit"],
                "remaining": max(
                    0,
                    config["daily_limit"] - used
                )
            }

    return result


def set_provider_cooldown(provider, seconds):
    """Store a provider-requested cooldown in SQLite."""
    if provider not in PROVIDER_LIMITS:
        raise ValueError("Unknown provider")

    initialize_rate_limiter()

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).timestamp()
    until = now + max(0, min(float(seconds), 86400))

    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS api_provider_cooldowns (
                provider TEXT PRIMARY KEY,
                blocked_until REAL NOT NULL
            )
        """)

        db.execute("""
            INSERT INTO api_provider_cooldowns
                (provider, blocked_until)
            VALUES (?, ?)
            ON CONFLICT(provider) DO UPDATE SET
                blocked_until = MAX(
                    api_provider_cooldowns.blocked_until,
                    excluded.blocked_until
                )
        """, (provider, until))


def get_provider_cooldown(provider):
    """Return remaining provider cooldown in seconds."""
    if provider not in PROVIDER_LIMITS:
        raise ValueError("Unknown provider")

    initialize_rate_limiter()

    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS api_provider_cooldowns (
                provider TEXT PRIMARY KEY,
                blocked_until REAL NOT NULL
            )
        """)

        row = db.execute("""
            SELECT blocked_until
            FROM api_provider_cooldowns
            WHERE provider = ?
        """, (provider,)).fetchone()

    if row is None:
        return 0

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).timestamp()

    return max(0, round(row["blocked_until"] - now, 2))


def parse_retry_after(value, default=300):
    """Parse Retry-After seconds or HTTP-date safely."""
    from datetime import datetime, timezone
    from email.utils import parsedate_to_datetime
    import math

    if value is None:
        return default

    try:
        seconds = float(value)

        if math.isfinite(seconds):
            return max(1, min(math.ceil(seconds), 86400))
    except (TypeError, ValueError, OverflowError):
        pass

    try:
        target = parsedate_to_datetime(str(value))

        if target.tzinfo is None:
            target = target.replace(tzinfo=timezone.utc)

        seconds = (
            target - datetime.now(timezone.utc)
        ).total_seconds()

        return max(1, min(math.ceil(seconds), 86400))

    except (TypeError, ValueError, OverflowError):
        return default

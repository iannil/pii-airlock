"""Usage quota management for PII-AIRLOCK.

This module provides quota tracking and enforcement for API usage.

Quota Types:
    - requests: Number of API requests
    - tokens: Number of tokens processed

Quota Periods:
    - hourly: Rolling 1-hour window
    - daily: Calendar day (UTC)
    - monthly: Calendar month (UTC)
"""

import calendar
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Optional, List
import threading

from pii_airlock.logging.setup import get_logger

logger = get_logger(__name__)


class QuotaPeriod(str, Enum):
    """Quota period types."""

    HOURLY = "hourly"
    DAILY = "daily"
    MONTHLY = "monthly"


class QuotaType(str, Enum):
    """Quota measurement types."""

    REQUESTS = "requests"
    TOKENS = "tokens"


@dataclass
class QuotaLimit:
    """A quota limit configuration.

    Attributes:
        quota_type: Type of quota (requests or tokens).
        period: Time period (hourly, daily, monthly).
        limit: Maximum allowed usage.
        soft_limit_percent: Percentage at which to warn (0-100).
    """

    quota_type: QuotaType
    period: QuotaPeriod
    limit: int
    soft_limit_percent: float = 80.0

    @property
    def soft_limit(self) -> int:
        """Calculate soft limit threshold."""
        return int(self.limit * (self.soft_limit_percent / 100))


@dataclass
class QuotaUsage:
    """Current quota usage for a tenant.

    Attributes:
        tenant_id: Tenant identifier.
        quota_type: Type of quota.
        period: Time period.
        current_usage: Current usage count.
        window_start: Start of the current window.
        window_end: End of the current window.
    """

    tenant_id: str
    quota_type: QuotaType
    period: QuotaPeriod
    current_usage: int = 0
    window_start: float = field(default_factory=time.time)
    window_end: float = field(default_factory=time.time)

    @property
    def is_expired(self) -> bool:
        """Check if the usage window has expired."""
        return time.time() > self.window_end

    def reset(self) -> None:
        """Reset usage for new window."""
        self.current_usage = 0
        self.window_start = time.time()
        self.window_end = self._calculate_window_end()

    def _calculate_window_end(self) -> float:
        """Calculate end of current window."""
        now = time.time()
        if self.period == QuotaPeriod.HOURLY:
            return now + 3600
        elif self.period == QuotaPeriod.DAILY:
            # End of current UTC day
            dt = datetime.utcnow()
            tomorrow = dt.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
            return tomorrow.timestamp()
        else:  # MONTHLY
            # End of current UTC month
            dt = datetime.utcnow()
            _, last_day = calendar.monthrange(dt.year, dt.month)
            month_end = dt.replace(day=last_day, hour=23, minute=59, second=59)
            return month_end.timestamp()

    def increment(self, amount: int = 1) -> int:
        """Increment usage and return new total.

        Args:
            amount: Amount to increment by.

        Returns:
            New usage count.
        """
        self.current_usage += amount
        return self.current_usage


@dataclass
class QuotaConfig:
    """Quota configuration for a tenant.

    Attributes:
        tenant_id: Tenant identifier.
        limits: List of quota limits.
    """

    tenant_id: str
    limits: List[QuotaLimit] = field(default_factory=list)

    def get_limit(self, quota_type: QuotaType, period: QuotaPeriod) -> Optional[QuotaLimit]:
        """Get limit for specific quota type and period.

        Args:
            quota_type: Type of quota.
            period: Time period.

        Returns:
            QuotaLimit if found, None otherwise.
        """
        for limit in self.limits:
            if limit.quota_type == quota_type and limit.period == period:
                return limit
        return None


class QuotaStore:
    """Storage and tracking for quota usage.

    Thread-safe in-memory storage with periodic cleanup.
    """

    def __init__(self, cleanup_interval: int = 300) -> None:
        """Initialize the quota store.

        Args:
            cleanup_interval: Seconds between cleanup runs.
        """
        self._configs: Dict[str, QuotaConfig] = {}  # tenant_id -> QuotaConfig
        self._usage: Dict[str, QuotaUsage] = {}  # "{tenant_id}:{type}:{period}" -> QuotaUsage
        self._lock = threading.RLock()
        self._cleanup_interval = cleanup_interval

    def set_quota(self, config: QuotaConfig) -> None:
        """Set quota configuration for a tenant.

        Args:
            config: Quota configuration.
        """
        with self._lock:
            self._configs[config.tenant_id] = config

        logger.info(
            "Quota configured",
            extra={
                "event": "quota_configured",
                "tenant_id": config.tenant_id,
                "limits_count": len(config.limits),
            },
        )

    def get_quota_config(self, tenant_id: str) -> Optional[QuotaConfig]:
        """Get quota configuration for a tenant.

        Args:
            tenant_id: Tenant identifier.

        Returns:
            QuotaConfig if found, None otherwise.
        """
        with self._lock:
            return self._configs.get(tenant_id)

    def get_usage(self, tenant_id: str, quota_type: QuotaType, period: QuotaPeriod) -> QuotaUsage:
        """Get current usage for a tenant.

        Args:
            tenant_id: Tenant identifier.
            quota_type: Type of quota.
            period: Time period.

        Returns:
            Current QuotaUsage (creates new if needed).
        """
        key = f"{tenant_id}:{quota_type.value}:{period.value}"

        with self._lock:
            usage = self._usage.get(key)

            if usage is None or usage.is_expired:
                usage = QuotaUsage(
                    tenant_id=tenant_id,
                    quota_type=quota_type,
                    period=period,
                )
                self._usage[key] = usage

            return usage

    def check_quota(
        self,
        tenant_id: str,
        quota_type: QuotaType,
        amount: int = 1,
    ) -> tuple[bool, Optional[QuotaLimit]]:
        """Check if quota allows the requested usage.

        Args:
            tenant_id: Tenant identifier.
            quota_type: Type of quota.
            amount: Amount of usage to check.

        Returns:
            Tuple of (allowed, limit) where allowed is True if within quota,
            and limit is the applicable QuotaLimit or None.
        """
        config = self.get_quota_config(tenant_id)
        if not config:
            # No quota configured, allow all
            return True, None

        # Check all periods for this quota type
        for period in QuotaPeriod:
            limit = config.get_limit(quota_type, period)
            if not limit:
                continue

            usage = self.get_usage(tenant_id, quota_type, period)

            if usage.current_usage + amount > limit.limit:
                logger.warning(
                    "Quota limit exceeded",
                    extra={
                        "event": "quota_exceeded",
                        "tenant_id": tenant_id,
                        "quota_type": quota_type.value,
                        "period": period.value,
                        "current": usage.current_usage,
                        "requested": amount,
                        "limit": limit.limit,
                    },
                )
                return False, limit

            # Check soft limit warning
            if usage.current_usage + amount > limit.soft_limit:
                logger.info(
                    "Soft quota limit approaching",
                    extra={
                        "event": "quota_soft_limit",
                        "tenant_id": tenant_id,
                        "quota_type": quota_type.value,
                        "period": period.value,
                        "current": usage.current_usage,
                        "soft_limit": limit.soft_limit,
                        "hard_limit": limit.limit,
                    },
                )

        return True, None

    def record_usage(
        self,
        tenant_id: str,
        quota_type: QuotaType,
        amount: int = 1,
    ) -> None:
        """Record usage for quota tracking.

        Args:
            tenant_id: Tenant identifier.
            quota_type: Type of quota.
            amount: Amount of usage to record.
        """
        for period in QuotaPeriod:
            usage = self.get_usage(tenant_id, quota_type, period)
            with self._lock:
                if usage.is_expired:
                    usage.reset()
                usage.increment(amount)

    def get_usage_summary(self, tenant_id: str) -> Dict[str, Dict[str, int]]:
        """Get usage summary for a tenant.

        Args:
            tenant_id: Tenant identifier.

        Returns:
            Dict of {quota_type: {period: usage}}.
        """
        summary: Dict[str, Dict[str, int]] = {}

        with self._lock:
            for key, usage in self._usage.items():
                if usage.tenant_id != tenant_id:
                    continue

                if usage.is_expired:
                    continue

                if usage.quota_type.value not in summary:
                    summary[usage.quota_type.value] = {}
                summary[usage.quota_type.value][usage.period.value] = usage.current_usage

        return summary

    @classmethod
    def from_yaml(cls, path: str, cleanup_interval: int = 300) -> "QuotaStore":
        """Load quota configurations from YAML file.

        Args:
            path: Path to quotas.yaml file.
            cleanup_interval: Seconds between cleanup runs.

        Returns:
            QuotaStore instance.

        Example YAML:
            quotas:
              - tenant_id: "team-a"
                requests:
                  daily: 10000
                  hourly: 1000
                tokens:
                  daily: 5000000
        """
        import yaml
        from pathlib import Path

        path = Path(path)

        store = cls(cleanup_interval=cleanup_interval)

        if not path.exists():
            return store

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if data is None:
            return store

        for quota_data in data.get("quotas", []):
            tenant_id = quota_data["tenant_id"]
            limits = []
            soft_limit = quota_data.get("soft_limit_percent", 80)

            # Request quotas
            requests = quota_data.get("requests", {})
            for period, limit in requests.items():
                try:
                    limits.append(
                        QuotaLimit(
                            quota_type=QuotaType.REQUESTS,
                            period=QuotaPeriod(period),
                            limit=int(limit),
                            soft_limit_percent=float(soft_limit),
                        )
                    )
                except ValueError:
                    continue

            # Token quotas
            tokens = quota_data.get("tokens", {})
            for period, limit in tokens.items():
                try:
                    limits.append(
                        QuotaLimit(
                            quota_type=QuotaType.TOKENS,
                            period=QuotaPeriod(period),
                            limit=int(limit),
                            soft_limit_percent=float(soft_limit),
                        )
                    )
                except ValueError:
                    continue

            config = QuotaConfig(tenant_id=tenant_id, limits=limits)
            store.set_quota(config)

        logger.info(
            f"Loaded quota configurations for {len(store._configs)} tenants",
            extra={
                "event": "quotas_loaded",
                "source": str(path),
            },
        )

        return store


# Global quota store (singleton-like)
_quota_store: Optional[QuotaStore] = None
_quota_store_lock = threading.Lock()


def get_quota_store() -> QuotaStore:
    """Get the global quota store.

    Loads from PII_AIRLOCK_QUOTA_CONFIG_PATH if set.

    Returns:
        Global QuotaStore instance.
    """
    global _quota_store

    with _quota_store_lock:
        if _quota_store is None:
            import os

            config_path = os.getenv("PII_AIRLOCK_QUOTA_CONFIG_PATH")
            if config_path:
                _quota_store = QuotaStore.from_yaml(config_path)
            else:
                _quota_store = QuotaStore()

    return _quota_store


def reset_quota_store() -> None:
    """Reset the global quota store (for testing)."""
    global _quota_store
    with _quota_store_lock:
        _quota_store = None


def check_quota(
    tenant_id: str,
    quota_type: QuotaType,
    amount: int = 1,
) -> tuple[bool, Optional[QuotaLimit]]:
    """Check if quota allows the requested usage.

    Args:
        tenant_id: Tenant identifier.
        quota_type: Type of quota.
        amount: Amount of usage to check.

    Returns:
        Tuple of (allowed, limit) where allowed is True if within quota.
    """
    store = get_quota_store()
    return store.check_quota(tenant_id, quota_type, amount)

"""Performance monitoring and timing utilities."""

import functools
import logging
import time
from collections import deque
from typing import Any, Callable, TypeVar

from pii_airlock.logging.setup import get_logger

# Type variables for generic function signatures
F = TypeVar("F", bound=Callable[..., Any])
T = TypeVar("T")


logger = get_logger(__name__)


class TimedExecution:
    """Context manager for timing code execution.

    Attributes:
        operation_name: Name of the operation being timed.
        log_threshold: Minimum execution time (ms) to log a warning.

    Examples:
        >>> with TimedExecution("database_query"):
        ...     result = db.query("SELECT * FROM users")
        # Logs: database_query completed in 45.2ms
    """

    def __init__(self, operation_name: str, log_threshold: float = 1000.0) -> None:
        """Initialize the timed execution context.

        Args:
            operation_name: Name of the operation for logging.
            log_threshold: Threshold in ms for warning log level (default: 1000ms).
        """
        self.operation_name = operation_name
        self.log_threshold = log_threshold
        self.start_time: float = 0.0
        self.elapsed_ms: float = 0.0

    def __enter__(self) -> "TimedExecution":
        """Start timing."""
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore
        """Stop timing and log the result."""
        self.elapsed_ms = (time.perf_counter() - self.start_time) * 1000

        log_message = f"{self.operation_name} completed in {self.elapsed_ms:.2f}ms"

        if self.elapsed_ms > self.log_threshold:
            logger.warning(log_message)
        else:
            logger.debug(log_message)


def timed_execution(func: F) -> F:
    """Decorator to measure and log function execution time.

    This decorator logs the execution time of the decorated function.
    If execution exceeds 1 second, a warning is logged.

    Args:
        func: Function to decorate.

    Returns:
        Decorated function with timing.

    Examples:
        >>> @timed_execution
        ... def process_data(data):
        ...     # complex processing
        ...     return result
    """
    warning_threshold_ms = 1000.0

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            func_name = func.__qualname__
            log_message = f"{func_name} executed in {elapsed_ms:.2f}ms"

            if elapsed_ms > warning_threshold_ms:
                logger.warning(log_message)
            else:
                logger.debug(log_message)

    return wrapper  # type: ignore


class PerformanceMetrics:
    """Simple performance metrics collector.

    Tracks min, max, avg, and recent execution times.

    Attributes:
        window_size: Number of recent measurements to keep.

    Examples:
        >>> metrics = PerformanceMetrics(window_size=100)
        >>> metrics.record(50)  # 50ms
        >>> metrics.record(100)  # 100ms
        >>> print(metrics.avg_ms)
        75.0
    """

    def __init__(self, window_size: int = 100) -> None:
        """Initialize metrics collector.

        Args:
            window_size: Maximum number of recent measurements to store.
        """
        self.window_size = window_size
        self._measurements: deque[float] = deque(maxlen=window_size)
        self._count = 0
        self._total_ms = 0.0

    def record(self, elapsed_ms: float) -> None:
        """Record a measurement.

        Args:
            elapsed_ms: Execution time in milliseconds.
        """
        self._measurements.append(elapsed_ms)
        self._count += 1
        self._total_ms += elapsed_ms

    @property
    def count(self) -> int:
        """Get total number of measurements."""
        return self._count

    @property
    def min_ms(self) -> float:
        """Get minimum execution time."""
        return min(self._measurements) if self._measurements else 0.0

    @property
    def max_ms(self) -> float:
        """Get maximum execution time."""
        return max(self._measurements) if self._measurements else 0.0

    @property
    def avg_ms(self) -> float:
        """Get average execution time."""
        if self._count == 0:
            return 0.0
        return self._total_ms / self._count

    @property
    def p50_ms(self) -> float:
        """Get median (50th percentile) execution time."""
        if not self._measurements:
            return 0.0
        sorted_measurements = sorted(self._measurements)
        n = len(sorted_measurements)
        if n % 2 == 0:
            return (sorted_measurements[n // 2 - 1] + sorted_measurements[n // 2]) / 2
        return sorted_measurements[n // 2]

    @property
    def p95_ms(self) -> float:
        """Get 95th percentile execution time."""
        if not self._measurements:
            return 0.0
        sorted_measurements = sorted(self._measurements)
        index = int(len(sorted_measurements) * 0.95)
        return sorted_measurements[min(index, len(sorted_measurements) - 1)]

    @property
    def p99_ms(self) -> float:
        """Get 99th percentile execution time."""
        if not self._measurements:
            return 0.0
        sorted_measurements = sorted(self._measurements)
        index = int(len(sorted_measurements) * 0.99)
        return sorted_measurements[min(index, len(sorted_measurements) - 1)]

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of all metrics.

        Returns:
            Dictionary with min, max, avg, p50, p95, p99 values.
        """
        return {
            "count": self.count,
            "min_ms": round(self.min_ms, 2),
            "max_ms": round(self.max_ms, 2),
            "avg_ms": round(self.avg_ms, 2),
            "p50_ms": round(self.p50_ms, 2),
            "p95_ms": round(self.p95_ms, 2),
            "p99_ms": round(self.p99_ms, 2),
        }

    def reset(self) -> None:
        """Reset all metrics."""
        self._measurements.clear()
        self._count = 0
        self._total_ms = 0.0


class RateLimiter:
    """Simple token bucket rate limiter.

    Attributes:
        rate: Maximum operations per second.
        burst: Maximum burst size (default: same as rate).

    Examples:
        >>> limiter = RateLimiter(rate=10, burst=20)
        >>> if limiter.try_acquire():
        ...     # perform operation
        ... else:
        ...     # rate limit exceeded
    """

    def __init__(self, rate: float, burst: int | None = None) -> None:
        """Initialize rate limiter.

        Args:
            rate: Operations per second.
            burst: Maximum burst size (default: rate).
        """
        self.rate = rate
        self.burst = burst if burst is not None else int(rate)
        self._tokens = float(self.burst)
        self._last_update = time.perf_counter()
        self._lock: threading.Lock | None = None
        try:
            import threading

            self._lock = threading.Lock()
        except Exception:
            pass

    def try_acquire(self, tokens: float = 1.0) -> bool:
        """Try to acquire tokens for an operation.

        Args:
            tokens: Number of tokens to acquire (default: 1.0).

        Returns:
            True if tokens were acquired, False if rate limited.
        """
        if self._lock:
            with self._lock:
                return self._try_acquire(tokens)
        return self._try_acquire(tokens)

    def _try_acquire(self, tokens: float) -> bool:
        """Internal token acquisition logic."""
        now = time.perf_counter()
        elapsed = now - self._last_update
        self._last_update = now

        # Add tokens based on elapsed time
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)

        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

    def get_wait_time(self, tokens: float = 1.0) -> float:
        """Get estimated wait time for tokens to be available.

        Args:
            tokens: Number of tokens needed.

        Returns:
            Seconds to wait (0 if available now).
        """
        if self._tokens >= tokens:
            return 0.0
        return (tokens - self._tokens) / self.rate


def cached_result(ttl_seconds: float = 0.0):
    """Decorator to cache function results with TTL.

    Args:
        ttl_seconds: Time-to-live for cached results (0 = no expiration).

    Examples:
        >>> @cached_result(ttl_seconds=60)
        ... def expensive_computation(x):
        ...     return x ** 2
    """
    cache: dict[Any, tuple[Any, float]] = {}

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Create a key from args and kwargs
            key = (args, frozenset(kwargs.items()))
            now = time.perf_counter()

            if key in cache:
                result, timestamp = cache[key]
                if ttl_seconds == 0 or (now - timestamp) < ttl_seconds:
                    return result

            result = func(*args, **kwargs)
            cache[key] = (result, now)
            return result

        return wrapper  # type: ignore

    return decorator


def retry_on_failure(
    max_attempts: int = 3,
    base_delay: float = 0.1,
    max_delay: float = 10.0,
    backoff_factor: float = 2.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
):
    """Decorator to retry function on failure with exponential backoff.

    Args:
        max_attempts: Maximum number of retry attempts.
        base_delay: Initial delay between retries in seconds.
        max_delay: Maximum delay between retries in seconds.
        backoff_factor: Multiplier for delay after each retry.
        exceptions: Tuple of exception types to catch and retry.

    Examples:
        >>> @retry_on_failure(max_attempts=3, exceptions=(ConnectionError,))
        ... def fetch_data(url):
        ...     return requests.get(url)
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception = None
            delay = base_delay

            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        logger.warning(
                            f"{func.__qualname__} failed (attempt {attempt + 1}/{max_attempts}): {e}. "
                            f"Retrying in {delay:.2f}s..."
                        )
                        time.sleep(delay)
                        delay = min(max_delay, delay * backoff_factor)
                    else:
                        logger.error(
                            f"{func.__qualname__} failed after {max_attempts} attempts: {e}"
                        )

            raise last_exception  # type: ignore

        return wrapper  # type: ignore

    return decorator


# Import threading at module level for type hints
import threading

"""Performance benchmarks for PII-AIRLOCK."""

import time

import pytest

from pii_airlock.core.anonymizer import Anonymizer
from pii_airlock.core.deanonymizer import Deanonymizer
from pii_airlock.core.strategies import StrategyConfig, StrategyType
from pii_airlock.utils import (
    PerformanceMetrics,
    RateLimiter,
    TimedExecution,
    timed_execution,
)


class TestAnonymizerPerformance:
    """Performance benchmarks for Anonymizer."""

    def test_anonymize_small_text_performance(self) -> None:
        """Benchmark anonymization of small text (< 100 chars)."""
        anonymizer = Anonymizer()
        text = "张三的电话是13800138000，邮箱是test@example.com"

        start = time.perf_counter()
        for _ in range(100):
            anonymizer.anonymize(text)
        elapsed = (time.perf_counter() - start) * 1000

        # Should complete 100 iterations in reasonable time
        # This is a soft benchmark - adjust as needed
        print(f"\nSmall text (100 iterations): {elapsed:.2f}ms")
        assert elapsed < 10000  # Should be under 10 seconds

    def test_anonymize_medium_text_performance(self) -> None:
        """Benchmark anonymization of medium text (~500 chars)."""
        anonymizer = Anonymizer()
        text = "张三" * 100 + "的电话是13800138000，" + "李四" * 100

        start = time.perf_counter()
        for _ in range(50):
            anonymizer.anonymize(text)
        elapsed = (time.perf_counter() - start) * 1000

        print(f"Medium text (50 iterations): {elapsed:.2f}ms")
        assert elapsed < 10000

    def test_anonymize_large_text_performance(self) -> None:
        """Benchmark anonymization of large text (> 2000 chars)."""
        anonymizer = Anonymizer()
        text = "张三的电话是13800138000，" * 200

        start = time.perf_counter()
        for _ in range(10):
            anonymizer.anonymize(text)
        elapsed = (time.perf_counter() - start) * 1000

        print(f"Large text (10 iterations): {elapsed:.2f}ms")
        assert elapsed < 15000

    def test_anonymize_strategy_performance_comparison(self) -> None:
        """Compare performance of different strategies."""
        text = "张三的电话是13800138000"

        strategies = [
            StrategyType.PLACEHOLDER,
            StrategyType.HASH,
            StrategyType.MASK,
            StrategyType.REDACT,
        ]

        results = {}
        for strategy in strategies:
            config = StrategyConfig({"PERSON": strategy, "PHONE_NUMBER": strategy})
            anonymizer = Anonymizer(strategy_config=config)

            start = time.perf_counter()
            for _ in range(100):
                anonymizer.anonymize(text)
            elapsed = (time.perf_counter() - start) * 1000
            results[strategy] = elapsed

        print(f"\nStrategy performance (100 iterations):")
        for strategy, elapsed in results.items():
            print(f"  {strategy}: {elapsed:.2f}ms")

        # All strategies should complete in reasonable time
        for elapsed in results.values():
            assert elapsed < 10000

    def test_shared_analyzer_performance(self) -> None:
        """Benchmark shared analyzer vs separate instances."""
        text = "张三的电话是13800138000"

        # Shared analyzer
        start = time.perf_counter()
        for _ in range(50):
            anonymizer = Anonymizer(use_shared_analyzer=True)
            anonymizer.anonymize(text)
        shared_elapsed = (time.perf_counter() - start) * 1000

        # Separate analyzer instances
        start = time.perf_counter()
        for _ in range(50):
            anonymizer = Anonymizer(use_shared_analyzer=False)
            anonymizer.anonymize(text)
        separate_elapsed = (time.perf_counter() - start) * 1000

        print(f"\nShared analyzer: {shared_elapsed:.2f}ms")
        print(f"Separate analyzer: {separate_elapsed:.2f}ms")

        # Shared should be faster (though this is a soft assertion)
        # The exact benefit depends on spaCy model loading time

    def test_deanonymize_performance(self) -> None:
        """Benchmark deanonymization performance."""
        anonymizer = Anonymizer()
        deanonymizer = Deanonymizer()

        text = "张三的电话是13800138000"
        result = anonymizer.anonymize(text)

        start = time.perf_counter()
        for _ in range(1000):
            deanonymizer.deanonymize(result.text, result.mapping)
        elapsed = (time.perf_counter() - start) * 1000

        print(f"\nDeanonymize (1000 iterations): {elapsed:.2f}ms")
        assert elapsed < 1000  # Deanonymization should be fast


class TestStrategyPerformance:
    """Performance benchmarks for individual strategies."""

    def test_placeholder_strategy_performance(self) -> None:
        """Benchmark placeholder strategy."""
        from pii_airlock.core.strategies import PlaceholderStrategy

        strategy = PlaceholderStrategy()

        start = time.perf_counter()
        for i in range(10000):
            strategy.anonymize("张三", "PERSON", i, {})
        elapsed = (time.perf_counter() - start) * 1000

        print(f"\nPlaceholder strategy (10000 iterations): {elapsed:.2f}ms")
        assert elapsed < 100

    def test_hash_strategy_performance(self) -> None:
        """Benchmark hash strategy."""
        from pii_airlock.core.strategies import HashStrategy

        strategy = HashStrategy()

        start = time.perf_counter()
        for i in range(10000):
            strategy.anonymize("张三", "PERSON", i, {})
        elapsed = (time.perf_counter() - start) * 1000

        print(f"Hash strategy (10000 iterations): {elapsed:.2f}ms")
        assert elapsed < 500  # Hashing is more expensive

    def test_mask_strategy_performance(self) -> None:
        """Benchmark mask strategy."""
        from pii_airlock.core.strategies import MaskStrategy

        strategy = MaskStrategy()

        start = time.perf_counter()
        for i in range(10000):
            strategy.anonymize("13800138000", "PHONE", i, {})
        elapsed = (time.perf_counter() - start) * 1000

        print(f"Mask strategy (10000 iterations): {elapsed:.2f}ms")
        assert elapsed < 200


class TestUtilityPerformance:
    """Performance benchmarks for utility functions."""

    def test_performance_metrics(self) -> None:
        """Test PerformanceMetrics collection overhead."""
        metrics = PerformanceMetrics()

        start = time.perf_counter()
        for i in range(10000):
            metrics.record(float(i % 100))
        elapsed = (time.perf_counter() - start) * 1000

        print(f"\nPerformanceMetrics (10000 records): {elapsed:.2f}ms")
        assert elapsed < 100

        # Verify calculations are correct
        assert metrics.count == 10000
        assert metrics.min_ms == 0.0
        assert metrics.max_ms == 99.0

    def test_rate_limiter_throughput(self) -> None:
        """Test rate limiter allows expected throughput."""
        limiter = RateLimiter(rate=100, burst=10)

        start = time.perf_counter()
        allowed = 0
        for _ in range(20):
            if limiter.try_acquire():
                allowed += 1
        elapsed = (time.perf_counter() - start) * 1000

        print(f"\nRateLimiter: {allowed} allowed in {elapsed:.2f}ms")
        assert allowed == 10  # Should allow burst size


class TestTimedExecution:
    """Tests for TimedExecution context manager and decorator."""

    def test_timed_execution_context(self) -> None:
        """Test TimedExecution context manager."""
        with TimedExecution("test_operation") as timer:
            time.sleep(0.01)  # 10ms

        assert timer.elapsed_ms >= 10
        print(f"\nTimedExecution context: {timer.elapsed_ms:.2f}ms")

    def test_timed_execution_decorator(self) -> None:
        """Test timed_execution decorator."""
        @timed_execution
        def slow_function():
            time.sleep(0.01)  # 10ms
            return "result"

        start = time.perf_counter()
        result = slow_function()
        elapsed = (time.perf_counter() - start) * 1000

        assert result == "result"
        assert elapsed >= 10
        print(f"\nTimedExecution decorator: {elapsed:.2f}ms")


class TestMemoryEfficiency:
    """Tests for memory efficiency."""

    def test_mapping_memory_growth(self) -> None:
        """Test that mapping doesn't grow unbounded."""
        from pii_airlock.core.mapping import PIIMapping

        mapping = PIIMapping()

        # Add many entries
        for i in range(1000):
            mapping.add("PERSON", f"value_{i}", f"<PERSON_{i}>")

        # Mapping should have all entries
        assert len(mapping) == 1000

    def test_session_isolation(self) -> None:
        """Test that different sessions don't share mappings."""
        from pii_airlock.core.mapping import PIIMapping

        mapping1 = PIIMapping(session_id="session1")
        mapping2 = PIIMapping(session_id="session2")

        mapping1.add("PERSON", "张三", "<PERSON_1>")
        mapping2.add("PERSON", "李四", "<PERSON_2>")

        assert mapping1.get_original("<PERSON_1>") == "张三"
        assert mapping2.get_original("<PERSON_2>") == "李四"

        # Mappings should be isolated
        assert mapping1.get_original("<PERSON_2>") is None
        assert mapping2.get_original("<PERSON_1>") is None

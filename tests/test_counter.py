"""Unit tests for the Counter module."""

import pytest
from pii_airlock.core.counter import PlaceholderCounter


class TestPlaceholderCounter:
    """Tests for PlaceholderCounter class."""

    def test_next_increments(self):
        """Test that next() increments counter."""
        counter = PlaceholderCounter()

        assert counter.next("PERSON") == 1
        assert counter.next("PERSON") == 2
        assert counter.next("PERSON") == 3

    def test_independent_types(self):
        """Test that different types have independent counters."""
        counter = PlaceholderCounter()

        assert counter.next("PERSON") == 1
        assert counter.next("PHONE") == 1
        assert counter.next("PERSON") == 2
        assert counter.next("EMAIL") == 1
        assert counter.next("PHONE") == 2

    def test_current(self):
        """Test current() returns current value without incrementing."""
        counter = PlaceholderCounter()

        assert counter.current("PERSON") == 0
        counter.next("PERSON")
        assert counter.current("PERSON") == 1
        assert counter.current("PERSON") == 1  # Doesn't increment

    def test_reset_single_type(self):
        """Test resetting a single type."""
        counter = PlaceholderCounter()

        counter.next("PERSON")
        counter.next("PERSON")
        counter.next("PHONE")

        counter.reset("PERSON")

        assert counter.current("PERSON") == 0
        assert counter.current("PHONE") == 1

    def test_reset_all(self):
        """Test resetting all types."""
        counter = PlaceholderCounter()

        counter.next("PERSON")
        counter.next("PHONE")
        counter.next("EMAIL")

        counter.reset()

        assert counter.current("PERSON") == 0
        assert counter.current("PHONE") == 0
        assert counter.current("EMAIL") == 0

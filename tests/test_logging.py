"""Tests for logging configuration."""

import io
import json
import logging
import sys
from unittest.mock import patch

import pytest

from pii_airlock.logging.setup import (
    setup_logging,
    get_logger,
    set_request_id,
    get_request_id,
    request_id_var,
    CustomJsonFormatter,
    RequestContextFilter,
)


class TestRequestContextFilter:
    """Tests for RequestContextFilter."""

    def test_adds_request_id_to_record(self):
        """Test that request_id is added to log records."""
        filter_ = RequestContextFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test message",
            args=(),
            exc_info=None,
        )

        # Set a request ID
        token = request_id_var.set("test-123")
        try:
            result = filter_.filter(record)
            assert result is True
            assert hasattr(record, "request_id")
            assert record.request_id == "test-123"
        finally:
            request_id_var.reset(token)

    def test_default_request_id(self):
        """Test that default request_id is '-' when not set."""
        filter_ = RequestContextFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test message",
            args=(),
            exc_info=None,
        )

        # Ensure no request ID is set
        token = request_id_var.set("")
        try:
            filter_.filter(record)
            assert record.request_id == "-"
        finally:
            request_id_var.reset(token)


class TestCustomJsonFormatter:
    """Tests for CustomJsonFormatter."""

    def test_adds_service_field(self):
        """Test that service field is added to log records."""
        formatter = CustomJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test message",
            args=(),
            exc_info=None,
        )
        record.request_id = "test-123"

        log_record = {}
        formatter.add_fields(log_record, record, {})

        assert log_record.get("service") == "pii-airlock"

    def test_renames_levelname_to_level(self):
        """Test that levelname is renamed to level."""
        formatter = CustomJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test message",
            args=(),
            exc_info=None,
        )
        record.request_id = "test-123"

        log_record = {"levelname": "INFO"}
        formatter.add_fields(log_record, record, {})

        assert "levelname" not in log_record
        assert log_record.get("level") == "INFO"


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_setup_json_format(self):
        """Test that JSON format logging works."""
        # Clear any existing handlers
        root_logger = logging.getLogger()
        root_logger.handlers.clear()

        # Capture output
        stream = io.StringIO()
        with patch("sys.stdout", stream):
            setup_logging(level="INFO", json_format=True)

        # Get a logger and write a message
        logger = get_logger("test_json")
        logger.info("Test message", extra={"custom_field": "value"})

        # Verify handlers were added
        assert len(root_logger.handlers) > 0

    def test_setup_text_format(self):
        """Test that text format logging works."""
        # Clear any existing handlers
        root_logger = logging.getLogger()
        root_logger.handlers.clear()

        setup_logging(level="DEBUG", json_format=False)

        # Verify handlers were added
        assert len(root_logger.handlers) > 0

    def test_setup_from_environment(self):
        """Test that logging reads from environment variables."""
        root_logger = logging.getLogger()
        root_logger.handlers.clear()

        with patch.dict(
            "os.environ",
            {
                "PII_AIRLOCK_LOG_LEVEL": "WARNING",
                "PII_AIRLOCK_LOG_FORMAT": "text",
            },
        ):
            setup_logging()

        assert root_logger.level == logging.WARNING


class TestRequestIdHelpers:
    """Tests for request ID helper functions."""

    def test_set_and_get_request_id(self):
        """Test setting and getting request ID."""
        set_request_id("my-request-123")
        assert get_request_id() == "my-request-123"

    def test_default_request_id(self):
        """Test default request ID is empty string."""
        # Reset to default
        token = request_id_var.set("")
        try:
            assert get_request_id() == ""
        finally:
            request_id_var.reset(token)


class TestGetLogger:
    """Tests for get_logger function."""

    def test_returns_logger(self):
        """Test that get_logger returns a logger instance."""
        logger = get_logger("test_module")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_module"

    def test_logger_has_filter(self):
        """Test that returned logger has request context filter."""
        # Clear and setup
        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        setup_logging()

        logger = get_logger("test_module2")

        # The filter is added to the root logger handlers
        assert len(root_logger.handlers) > 0
        handler = root_logger.handlers[0]
        filter_names = [type(f).__name__ for f in handler.filters]
        assert "RequestContextFilter" in filter_names

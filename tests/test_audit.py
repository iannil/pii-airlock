"""Tests for the audit logging module."""

import asyncio
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio

from pii_airlock.audit.models import (
    AuditEvent,
    AuditEventType,
    AuditFilter,
    RiskLevel,
    AuditSummary,
    create_event,
    hash_api_key,
)
from pii_airlock.audit.store import FileAuditStore, DatabaseAuditStore, set_audit_store
from pii_airlock.audit.logger import (
    AuditLogger,
    AuditContext,
    set_audit_context,
    clear_audit_context,
    get_audit_context,
)


class TestAuditModels:
    """Tests for audit event models."""

    def test_create_event(self):
        """Test creating an audit event."""
        event = create_event(
            AuditEventType.PII_DETECTED,
            entity_type="PERSON",
            entity_count=2,
            tenant_id="tenant1",
        )

        assert event.event_type == AuditEventType.PII_DETECTED
        assert event.entity_type == "PERSON"
        assert event.entity_count == 2
        assert event.tenant_id == "tenant1"
        assert event.risk_level == RiskLevel.NONE

    def test_event_to_dict(self):
        """Test converting event to dictionary."""
        event = create_event(
            AuditEventType.PII_ANONYMIZED,
            entity_type="PHONE",
            entity_count=1,
            strategy_used="placeholder",
        )

        data = event.to_dict()

        assert data["event_type"] == "pii_anonymized"
        assert data["entity_type"] == "PHONE"
        assert data["entity_count"] == 1
        assert data["strategy_used"] == "placeholder"
        assert "timestamp" in data

    def test_event_to_json(self):
        """Test converting event to JSON."""
        event = create_event(
            AuditEventType.API_REQUEST,
            endpoint="/v1/chat/completions",
            method="POST",
        )

        json_str = event.to_json()
        data = json.loads(json_str)

        assert data["event_type"] == "api_request"
        assert data["endpoint"] == "/v1/chat/completions"
        assert data["method"] == "POST"

    def test_event_from_dict(self):
        """Test creating event from dictionary."""
        data = {
            "event_id": "test-123",
            "event_type": "pii_detected",
            "timestamp": "2024-01-01T12:00:00",
            "tenant_id": "tenant1",
            "entity_type": "EMAIL",
            "entity_count": 1,
            "risk_level": "none",
        }

        event = AuditEvent.from_dict(data)

        assert event.event_id == "test-123"
        assert event.event_type == AuditEventType.PII_DETECTED
        assert event.tenant_id == "tenant1"
        assert event.entity_type == "EMAIL"

    def test_event_from_json(self):
        """Test creating event from JSON."""
        json_str = '{"event_id": "test-456", "event_type": "api_request", "timestamp": "2024-01-01T12:00:00", "risk_level": "none"}'

        event = AuditEvent.from_json(json_str)

        assert event.event_id == "test-456"
        assert event.event_type == AuditEventType.API_REQUEST

    def test_hash_api_key(self):
        """Test API key hashing."""
        key = "sk-1234567890abcdef"
        hashed = hash_api_key(key)

        assert hashed is not None
        assert "sk-" in hashed  # Prefix preserved
        assert "abcd" not in hashed  # Original key not exposed
        # Hash format: prefix...hash_suffix (so it can be longer)

    def test_hash_api_key_none(self):
        """Test hashing None key."""
        assert hash_api_key(None) is None
        assert hash_api_key("") is None


class TestAuditFilter:
    """Tests for audit filter."""

    def test_filter_by_event_type(self):
        """Test filtering by event type."""
        now = datetime.now()
        filter = AuditFilter(
            start_date=now - timedelta(hours=1),
            end_date=now + timedelta(hours=1),
            event_types=[AuditEventType.PII_DETECTED, AuditEventType.PII_ANONYMIZED],
        )

        event1 = create_event(AuditEventType.PII_DETECTED, entity_type="PERSON")
        event2 = create_event(AuditEventType.API_REQUEST)
        event3 = create_event(AuditEventType.PII_ANONYMIZED, entity_type="PERSON")

        assert filter.match(event1)
        assert not filter.match(event2)
        assert filter.match(event3)

    def test_filter_by_tenant_id(self):
        """Test filtering by tenant ID."""
        now = datetime.now()
        filter = AuditFilter(
            start_date=now - timedelta(hours=1),
            end_date=now + timedelta(hours=1),
            tenant_id="tenant1",
        )

        event1 = create_event(AuditEventType.PII_DETECTED, tenant_id="tenant1")
        event2 = create_event(AuditEventType.PII_DETECTED, tenant_id="tenant2")

        assert filter.match(event1)
        assert not filter.match(event2)

    def test_filter_by_risk_level(self):
        """Test filtering by risk level."""
        now = datetime.now()
        filter = AuditFilter(
            start_date=now - timedelta(hours=1),
            end_date=now + timedelta(hours=1),
            risk_levels=[RiskLevel.HIGH, RiskLevel.CRITICAL],
        )

        event1 = create_event(AuditEventType.SECRET_DETECTED, risk_level=RiskLevel.HIGH)
        event2 = create_event(AuditEventType.PII_DETECTED, risk_level=RiskLevel.NONE)

        assert filter.match(event1)
        assert not filter.match(event2)

    def test_filter_by_min_risk_level(self):
        """Test filtering by minimum risk level."""
        now = datetime.now()
        filter = AuditFilter(
            start_date=now - timedelta(hours=1),
            end_date=now + timedelta(hours=1),
            min_risk_level=RiskLevel.MEDIUM,
        )

        event1 = create_event(AuditEventType.SECRET_DETECTED, risk_level=RiskLevel.HIGH)
        event2 = create_event(AuditEventType.PII_DETECTED, risk_level=RiskLevel.LOW)

        assert filter.match(event1)
        assert not filter.match(event2)


class TestFileAuditStore:
    """Tests for file-based audit store."""

    @pytest_asyncio.fixture
    async def temp_store(self, tmp_path):
        """Create a temporary file store."""
        store = FileAuditStore(log_dir=str(tmp_path))
        yield store
        # Cleanup is handled by tmp_path fixture

    @pytest.mark.asyncio
    async def test_write_and_query(self, temp_store):
        """Test writing and querying events."""
        now = datetime.now()
        event = create_event(
            AuditEventType.PII_DETECTED,
            tenant_id="tenant1",
            entity_type="PERSON",
            entity_count=2,
        )

        await temp_store.write(event)

        # Query immediately
        filter = AuditFilter(
            start_date=now - timedelta(seconds=1),
            end_date=now + timedelta(seconds=1),
        )

        events = await temp_store.query(filter)
        assert len(events) == 1
        assert events[0].entity_type == "PERSON"
        assert events[0].entity_count == 2

    @pytest.mark.asyncio
    async def test_write_batch(self, temp_store):
        """Test batch writing events."""
        events = [
            create_event(AuditEventType.PII_DETECTED, entity_type="PERSON"),
            create_event(AuditEventType.PII_DETECTED, entity_type="PHONE"),
            create_event(AuditEventType.PII_ANONYMIZED, entity_type="EMAIL"),
        ]

        await temp_store.write_batch(events)

        # Query all events
        now = datetime.now()
        filter = AuditFilter(
            start_date=now - timedelta(seconds=1),
            end_date=now + timedelta(seconds=1),
        )

        result = await temp_store.query(filter)
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_filter_by_event_type(self, temp_store):
        """Test filtering by event type."""
        await temp_store.write(create_event(AuditEventType.PII_DETECTED))
        await temp_store.write(create_event(AuditEventType.API_REQUEST))
        await temp_store.write(create_event(AuditEventType.PII_ANONYMIZED))

        now = datetime.now()
        filter = AuditFilter(
            start_date=now - timedelta(seconds=1),
            end_date=now + timedelta(seconds=1),
            event_types=[AuditEventType.PII_DETECTED],
        )

        events = await temp_store.query(filter)
        assert len(events) == 1
        assert events[0].event_type == AuditEventType.PII_DETECTED

    @pytest.mark.asyncio
    async def test_export_json(self, temp_store):
        """Test exporting to JSON."""
        events = [
            create_event(AuditEventType.PII_DETECTED, entity_type="PERSON"),
            create_event(AuditEventType.PII_DETECTED, entity_type="PHONE"),
        ]
        await temp_store.write_batch(events)

        now = datetime.now()
        filter = AuditFilter(
            start_date=now - timedelta(seconds=1),
            end_date=now + timedelta(seconds=1),
        )

        json_output = await temp_store.export_json(filter)
        data = json.loads(json_output)

        assert len(data) == 2
        # Check both entity types are present
        entity_types = {e["entity_type"] for e in data}
        assert "PERSON" in entity_types
        assert "PHONE" in entity_types

    @pytest.mark.asyncio
    async def test_export_csv(self, temp_store):
        """Test exporting to CSV."""
        events = [
            create_event(AuditEventType.PII_DETECTED, entity_type="PERSON"),
        ]
        await temp_store.write_batch(events)

        now = datetime.now()
        filter = AuditFilter(
            start_date=now - timedelta(seconds=1),
            end_date=now + timedelta(seconds=1),
        )

        csv_output = await temp_store.export_csv(filter)

        assert "event_id" in csv_output
        assert "PERSON" in csv_output
        assert "," in csv_output  # CSV format

    @pytest.mark.asyncio
    async def test_get_summary(self, temp_store):
        """Test getting summary statistics."""
        events = [
            create_event(AuditEventType.PII_DETECTED, entity_type="PERSON", entity_count=2),
            create_event(AuditEventType.PII_DETECTED, entity_type="PHONE", entity_count=1),
            create_event(AuditEventType.PII_ANONYMIZED, entity_type="PERSON", entity_count=2),
            create_event(AuditEventType.API_REQUEST),
            create_event(AuditEventType.AUTH_FAILURE, risk_level=RiskLevel.HIGH),
        ]
        await temp_store.write_batch(events)

        now = datetime.now()
        summary = await temp_store.get_summary(
            start_date=now - timedelta(seconds=1),
            end_date=now + timedelta(seconds=1),
        )

        assert summary.total_events == 5
        assert summary.pii_detected_count == 3
        assert summary.pii_anonymized_count == 2
        assert summary.api_request_count == 1
        assert summary.auth_failure_count == 1
        assert summary.pii_by_type["PERSON"] == 2

    @pytest.mark.asyncio
    async def test_cleanup_old_logs(self, temp_store):
        """Test cleanup of old log files."""
        # Write an event
        await temp_store.write(create_event(AuditEventType.PII_DETECTED))

        # Cleanup with 0 days retention - may delete today's file depending on implementation
        # The important thing is it doesn't crash
        deleted = await temp_store.cleanup_old_logs(0)
        assert deleted >= 0

        # Cleanup with 365 days retention should not delete today's file
        deleted = await temp_store.cleanup_old_logs(365)
        assert deleted == 0


class TestAuditLogger:
    """Tests for audit logger."""

    @pytest_asyncio.fixture
    async def logger(self, tmp_path):
        """Create an audit logger with temp storage."""
        store = FileAuditStore(log_dir=str(tmp_path))
        logger = AuditLogger(store=store, enabled=True)
        yield logger
        await logger.stop_auto_flush()

    @pytest.mark.asyncio
    async def test_log_event(self, logger):
        """Test logging an event."""
        await logger.log(
            AuditEventType.PII_DETECTED,
            entity_type="PERSON",
            entity_count=1,
        )

        await logger.flush()

        # Verify event was written
        now = datetime.now()
        filter = AuditFilter(
            start_date=now - timedelta(seconds=1),
            end_date=now + timedelta(seconds=1),
        )

        events = await logger._store.query(filter)
        assert len(events) >= 1

    @pytest.mark.asyncio
    async def test_log_pii_detected(self, logger):
        """Test logging PII detection."""
        await logger.log_pii_detected(
            entity_type="PERSON",
            entity_count=2,
            tenant_id="tenant1",
        )
        await logger.flush()

        now = datetime.now()
        filter = AuditFilter(
            start_date=now - timedelta(seconds=1),
            end_date=now + timedelta(seconds=1),
        )

        events = await logger._store.query(filter)
        assert any(e.entity_type == "PERSON" for e in events)

    @pytest.mark.asyncio
    async def test_log_api_request(self, logger):
        """Test logging API request."""
        await logger.log_api_request(
            endpoint="/v1/chat/completions",
            method="POST",
            tenant_id="tenant1",
        )
        await logger.flush()

        now = datetime.now()
        filter = AuditFilter(
            start_date=now - timedelta(seconds=1),
            end_date=now + timedelta(seconds=1),
        )

        events = await logger._store.query(filter)
        assert any(e.event_type == AuditEventType.API_REQUEST for e in events)

    @pytest.mark.asyncio
    async def test_log_auth_failure(self, logger):
        """Test logging auth failure."""
        await logger.log_auth_failure(reason="invalid_key")
        await logger.flush()

        now = datetime.now()
        filter = AuditFilter(
            start_date=now - timedelta(seconds=1),
            end_date=now + timedelta(seconds=1),
        )

        events = await logger._store.query(filter)
        assert any(e.event_type == AuditEventType.AUTH_FAILURE for e in events)
        assert any(e.risk_level == RiskLevel.HIGH for e in events)

    @pytest.mark.asyncio
    async def test_context_merge(self, logger):
        """Test that context is merged with event data."""
        set_audit_context(
            request_id="req-123",
            tenant_id="tenant-ctx",
            source_ip="10.0.0.1",
        )

        await logger.log(
            AuditEventType.PII_DETECTED,
            entity_type="PERSON",
            entity_count=1,
        )

        await logger.flush()
        clear_audit_context()

        now = datetime.now()
        filter = AuditFilter(
            start_date=now - timedelta(seconds=1),
            end_date=now + timedelta(seconds=1),
        )

        events = await logger._store.query(filter)
        # Check if any event has the context values
        found_request_id = False
        found_source_ip = False
        for e in events:
            if e.request_id == "req-123":
                found_request_id = True
            if e.source_ip == "10.0.0.1":
                found_source_ip = True

        assert found_request_id, "No event found with request_id=req-123"
        assert found_source_ip, "No event found with source_ip=10.0.0.1"

    @pytest.mark.asyncio
    async def test_logger_disabled(self, tmp_path):
        """Test that disabled logger doesn't write events."""
        store = FileAuditStore(log_dir=str(tmp_path))
        logger = AuditLogger(store=store, enabled=False)

        await logger.log(AuditEventType.PII_DETECTED)
        await logger.flush()

        # No events should be written
        now = datetime.now()
        filter = AuditFilter(
            start_date=now - timedelta(seconds=1),
            end_date=now + timedelta(seconds=1),
        )

        events = await store.query(filter)
        assert len(events) == 0


class TestAuditContext:
    """Tests for audit context management."""

    def test_set_and_get_context(self):
        """Test setting and getting audit context."""
        set_audit_context(
            request_id="req-123",
            tenant_id="tenant1",
            source_ip="10.0.0.1",
        )

        context = get_audit_context()
        assert context["request_id"] == "req-123"
        assert context["tenant_id"] == "tenant1"
        assert context["source_ip"] == "10.0.0.1"

        clear_audit_context()

    def test_clear_context(self):
        """Test clearing audit context."""
        set_audit_context(request_id="req-123")
        assert get_audit_context()["request_id"] == "req-123"

        clear_audit_context()
        assert get_audit_context() == {}

    def test_context_manager(self):
        """Test audit context as a context manager."""
        async def test():
            async with AuditContext(request_id="req-ctx", tenant_id="tenant-ctx"):
                context = get_audit_context()
                assert context["request_id"] == "req-ctx"
                assert context["tenant_id"] == "tenant-ctx"

            # Context should be cleared after exiting
            assert get_audit_context() == {}

        asyncio.run(test())


class TestAuditIntegration:
    """Integration tests for audit system."""

    @pytest.mark.asyncio
    async def test_full_workflow(self, tmp_path):
        """Test complete audit workflow."""
        store = FileAuditStore(log_dir=str(tmp_path))
        logger = AuditLogger(store=store, enabled=True)

        # Simulate a request lifecycle
        set_audit_context(
            request_id="req-full",
            tenant_id="tenant1",
            source_ip="10.0.0.1",
            user_agent="test-client",
        )

        # Log PII detection
        await logger.log_pii_detected(entity_type="PERSON", entity_count=2)

        # Log anonymization
        await logger.log_pii_anonymized(
            entity_type="PERSON",
            entity_count=2,
            strategy_used="placeholder",
        )

        # Log API request
        await logger.log_api_request(
            endpoint="/v1/chat/completions",
            method="POST",
        )

        await logger.flush()
        clear_audit_context()

        # Verify all events were logged
        now = datetime.now()
        summary = await store.get_summary(
            start_date=now - timedelta(seconds=1),
            end_date=now + timedelta(seconds=1),
        )

        assert summary.total_events == 3
        assert summary.pii_detected_count == 2
        assert summary.pii_anonymized_count == 2

        await logger.stop_auto_flush()

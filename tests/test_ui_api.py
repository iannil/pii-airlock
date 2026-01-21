"""Unit tests for UI and test API endpoints."""

import pytest
from fastapi.testclient import TestClient

from pii_airlock.api.routes import app


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


class TestUIEndpoint:
    """Tests for the /ui endpoint."""

    def test_ui_returns_html(self, client):
        """Test that /ui returns HTML content."""
        response = client.get("/ui")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")

    def test_ui_contains_title(self, client):
        """Test that UI contains the expected title."""
        response = client.get("/ui")
        assert "PII-AIRLOCK" in response.text

    def test_ui_contains_form_elements(self, client):
        """Test that UI contains expected form elements."""
        response = client.get("/ui")
        assert "<textarea" in response.text
        assert "id=\"input\"" in response.text
        assert "<button" in response.text

    def test_ui_contains_version(self, client):
        """Test that UI contains version information."""
        response = client.get("/ui")
        assert "PII-AIRLOCK v" in response.text


class TestAnonymizeEndpoint:
    """Tests for the /api/test/anonymize endpoint."""

    def test_anonymize_simple_text(self, client):
        """Test anonymizing simple text."""
        response = client.post(
            "/api/test/anonymize",
            json={"text": "Hello world"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["original"] == "Hello world"
        assert data["anonymized"] == "Hello world"  # No PII, unchanged
        assert data["mapping"] == {}

    def test_anonymize_with_phone(self, client):
        """Test anonymizing text with phone number."""
        response = client.post(
            "/api/test/anonymize",
            json={"text": "我的电话是13800138000"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["original"] == "我的电话是13800138000"
        assert "<PHONE_1>" in data["anonymized"]
        assert "13800138000" not in data["anonymized"]
        assert "<PHONE_1>" in data["mapping"]
        assert data["mapping"]["<PHONE_1>"] == "13800138000"

    def test_anonymize_with_email(self, client):
        """Test anonymizing text with email."""
        response = client.post(
            "/api/test/anonymize",
            json={"text": "邮箱test@example.com"},
        )
        assert response.status_code == 200
        data = response.json()
        # Check that some EMAIL placeholder exists
        assert "<EMAIL_1>" in data["anonymized"] or any(
            "EMAIL" in k for k in data["mapping"].keys()
        )
        # Check that email was detected and is in the mapping values
        assert "test@example.com" in str(data["mapping"].values())

    def test_anonymize_multiple_pii(self, client):
        """Test anonymizing text with multiple PII."""
        response = client.post(
            "/api/test/anonymize",
            json={"text": "电话13800138000，邮箱test@example.com"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "<PHONE_1>" in data["anonymized"]
        assert "<EMAIL_1>" in data["anonymized"]
        assert len(data["mapping"]) == 2

    def test_anonymize_empty_text(self, client):
        """Test anonymizing empty text."""
        response = client.post(
            "/api/test/anonymize",
            json={"text": ""},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["anonymized"] == ""
        assert data["mapping"] == {}

    def test_anonymize_invalid_request(self, client):
        """Test anonymize with invalid request returns error."""
        response = client.post(
            "/api/test/anonymize",
            json={},  # Missing text field
        )
        assert response.status_code == 422  # Validation error


class TestDeanonymizeEndpoint:
    """Tests for the /api/test/deanonymize endpoint."""

    def test_deanonymize_simple(self, client):
        """Test deanonymizing text with placeholders."""
        response = client.post(
            "/api/test/deanonymize",
            json={
                "text": "联系<PERSON_1>获取帮助",
                "mapping": {"<PERSON_1>": "张三"},
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["original"] == "联系<PERSON_1>获取帮助"
        assert data["deanonymized"] == "联系张三获取帮助"

    def test_deanonymize_multiple(self, client):
        """Test deanonymizing text with multiple placeholders."""
        response = client.post(
            "/api/test/deanonymize",
            json={
                "text": "<PERSON_1>的电话是<PHONE_1>",
                "mapping": {
                    "<PERSON_1>": "张三",
                    "<PHONE_1>": "13800138000",
                },
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "张三" in data["deanonymized"]
        assert "13800138000" in data["deanonymized"]
        assert "<PERSON_1>" not in data["deanonymized"]
        assert "<PHONE_1>" not in data["deanonymized"]

    def test_deanonymize_no_placeholders(self, client):
        """Test deanonymizing text without placeholders."""
        response = client.post(
            "/api/test/deanonymize",
            json={
                "text": "Hello world",
                "mapping": {},
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["deanonymized"] == "Hello world"

    def test_deanonymize_empty_text(self, client):
        """Test deanonymizing empty text."""
        response = client.post(
            "/api/test/deanonymize",
            json={
                "text": "",
                "mapping": {},
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["deanonymized"] == ""

    def test_deanonymize_invalid_request(self, client):
        """Test deanonymize with invalid request returns error."""
        response = client.post(
            "/api/test/deanonymize",
            json={"text": "test"},  # Missing mapping field
        )
        assert response.status_code == 422  # Validation error


class TestRoundTrip:
    """Tests for full anonymize-deanonymize round trip."""

    def test_round_trip_preserves_text(self, client):
        """Test that anonymize + deanonymize preserves original text."""
        original = "张三的电话是13800138000"

        # Step 1: Anonymize
        anon_response = client.post(
            "/api/test/anonymize",
            json={"text": original},
        )
        assert anon_response.status_code == 200
        anon_data = anon_response.json()

        # Step 2: Deanonymize using the mapping from step 1
        deanon_response = client.post(
            "/api/test/deanonymize",
            json={
                "text": anon_data["anonymized"],
                "mapping": anon_data["mapping"],
            },
        )
        assert deanon_response.status_code == 200
        deanon_data = deanon_response.json()

        # Original text should be preserved
        assert deanon_data["deanonymized"] == original

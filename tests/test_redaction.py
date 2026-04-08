"""Tests for purpleforge.audit.redaction."""

import pytest

from purpleforge.audit.redaction import Redactor, redact_text, redact_dict


# ---------------------------------------------------------------------------
# Built-in pattern tests
# ---------------------------------------------------------------------------

class TestRedactText:
    """Tests for Redactor.redact_text / module-level redact_text."""

    def test_email_redacted(self):
        result = redact_text("email me at test@example.com please")
        assert "@" not in result or "[REDACTED_EMAIL]" in result
        assert "test@example.com" not in result
        assert "[REDACTED_EMAIL]" in result

    def test_bearer_token_redacted(self):
        result = redact_text("Authorization: Bearer abc123def456")
        assert "abc123def456" not in result
        assert "Bearer [REDACTED]" in result

    def test_jwt_redacted(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = redact_text(f"token={jwt}")
        assert jwt not in result
        assert "[REDACTED_JWT]" in result

    def test_aws_access_key_redacted(self):
        result = redact_text("key=AKIAIOSFODNN7EXAMPLE123")
        # AKIA + 16 chars = AKIAIOSFODNN7EXAM
        assert "AKIAIOSFODNN7EXAM" not in result
        assert "[REDACTED_AWS_KEY]" in result

    def test_api_key_header_value_redacted_key_name_kept(self):
        result = redact_text("x-api-key: supersecretvalue123")
        assert "supersecretvalue123" not in result
        assert "[REDACTED]" in result
        assert "x-api-key" in result.lower() or "api-key" in result.lower()

    def test_api_key_equals_form(self):
        result = redact_text("api_key=myprivatekey")
        assert "myprivatekey" not in result
        assert "[REDACTED]" in result

    def test_password_field_redacted(self):
        result = redact_text("password: hunter2")
        assert "hunter2" not in result
        assert "[REDACTED]" in result

    def test_password_equals_redacted(self):
        result = redact_text("password=mypassword123")
        assert "mypassword123" not in result
        assert "password=[REDACTED]" in result

    def test_private_key_block_redacted(self):
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        result = redact_text(f"key data: {pem}")
        assert "MIIEowIBAAKCAQEA" not in result
        assert "[REDACTED_PRIVATE_KEY]" in result

    def test_uk_ni_number_redacted(self):
        result = redact_text("NI: AB 12 34 56 C")
        assert "AB 12 34 56 C" not in result
        assert "[REDACTED_PII]" in result

    def test_uk_postcode_redacted(self):
        result = redact_text("postcode SW1A 1AA")
        assert "SW1A 1AA" not in result
        assert "[REDACTED_PII]" in result

    def test_uk_phone_redacted(self):
        result = redact_text("call me on 07700 900123")
        # Phone number should be redacted
        assert "07700 900123" not in result
        assert "[REDACTED_PII]" in result

    def test_multiple_patterns_in_one_string(self):
        text = "email me at test@example.com or token Bearer abc123def"
        result = redact_text(text)
        assert "test@example.com" not in result
        assert "abc123def" not in result
        assert "[REDACTED_EMAIL]" in result
        assert "[REDACTED]" in result

    def test_idempotent(self):
        text = "email test@example.com"
        once = redact_text(text)
        twice = redact_text(once)
        assert once == twice

    def test_no_sensitive_data_unchanged(self):
        text = "Hello, this is a safe string with no PII."
        assert redact_text(text) == text

    def test_disabled_passthrough(self):
        r = Redactor(enabled=False)
        text = "email test@example.com Bearer supersecret"
        assert r.redact_text(text) == text

    def test_bad_input_no_crash(self):
        r = Redactor()
        # Should not raise on non-string (coerces to str or returns gracefully)
        result = r.redact_text(None)  # type: ignore[arg-type]
        # Should not raise — result may be "None" or None
        assert result is not None or result is None  # trivially true, the test is no-crash

    def test_custom_patterns(self):
        r = Redactor(custom_patterns=[
            (r"MYTOKEN-[A-Z0-9]+", "[REDACTED_CUSTOM]"),
        ])
        result = r.redact_text("auth=MYTOKEN-ABC123")
        assert "MYTOKEN-ABC123" not in result
        assert "[REDACTED_CUSTOM]" in result

    def test_invalid_custom_pattern_no_crash(self):
        # Invalid regex should be silently skipped, not raise
        r = Redactor(custom_patterns=[("[invalid", "X")])
        assert r.redact_text("test@example.com") == "[REDACTED_EMAIL]"


# ---------------------------------------------------------------------------
# Dict-walk tests
# ---------------------------------------------------------------------------

class TestRedactDict:
    """Tests for Redactor.redact_dict."""

    def test_sensitive_key_value_replaced(self):
        r = Redactor()
        d = {"password": "hunter2", "username": "alice"}
        result = r.redact_dict(d)
        assert result["password"] == "[REDACTED]"
        assert result["username"] == "alice"

    def test_sensitive_key_token(self):
        r = Redactor()
        d = {"token": "super-secret-token"}
        result = r.redact_dict(d)
        assert result["token"] == "[REDACTED]"

    def test_sensitive_key_secret(self):
        r = Redactor()
        result = r.redact_dict({"secret": "abc"})
        assert result["secret"] == "[REDACTED]"

    def test_sensitive_key_api_key(self):
        r = Redactor()
        result = r.redact_dict({"api_key": "val"})
        assert result["api_key"] == "[REDACTED]"

    def test_sensitive_key_authorization(self):
        r = Redactor()
        result = r.redact_dict({"authorization": "Bearer tok"})
        assert result["authorization"] == "[REDACTED]"

    def test_non_sensitive_string_values_text_redacted(self):
        r = Redactor()
        result = r.redact_dict({"url": "http://example.com?user=test@example.com"})
        assert "test@example.com" not in result["url"]
        assert "[REDACTED_EMAIL]" in result["url"]

    def test_nested_dict(self):
        r = Redactor()
        d = {"outer": {"password": "secret", "data": "user@test.com"}}
        result = r.redact_dict(d)
        assert result["outer"]["password"] == "[REDACTED]"
        assert "user@test.com" not in result["outer"]["data"]

    def test_list_values_walked(self):
        r = Redactor()
        d = {"items": ["safe", "email: test@example.com", 42]}
        result = r.redact_dict(d)
        assert "test@example.com" not in result["items"][1]
        assert result["items"][2] == 42

    def test_non_string_leaf_untouched(self):
        r = Redactor()
        d = {"count": 42, "flag": True, "value": 3.14}
        result = r.redact_dict(d)
        assert result["count"] == 42
        assert result["flag"] is True
        assert result["value"] == 3.14

    def test_disabled_passthrough(self):
        r = Redactor(enabled=False)
        d = {"password": "hunter2", "email": "user@example.com"}
        result = r.redact_dict(d)
        assert result["password"] == "hunter2"
        assert result["email"] == "user@example.com"

    def test_bad_input_no_crash(self):
        r = Redactor()
        # Non-dict/list input — should not raise
        result = r.redact_dict("just a string")
        # Strings are also walked through redact_text
        assert result is not None

    def test_none_value_sensitive_key_preserved(self):
        r = Redactor()
        d = {"password": None}
        result = r.redact_dict(d)
        # None values under sensitive keys should remain None (not "[REDACTED]")
        assert result["password"] is None

    def test_module_level_redact_dict(self):
        result = redact_dict({"token": "abc", "name": "Alice"})
        assert result["token"] == "[REDACTED]"
        assert result["name"] == "Alice"

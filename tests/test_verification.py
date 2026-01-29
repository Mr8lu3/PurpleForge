"""Tests for target verification."""

import pytest
from unittest.mock import Mock, patch
import requests

from purpleforge.verification.verifier import (
    generate_verification_token,
    hash_token,
    verify_target_ownership,
    VerificationStatus,
    is_local_target,
)


def test_generate_token():
    """Test token generation."""
    token = generate_verification_token()
    assert len(token) == 32
    assert all(c in "0123456789abcdef" for c in token)


def test_hash_token():
    """Test token hashing."""
    token = "test_token"
    hash1 = hash_token(token)
    hash2 = hash_token(token)

    assert hash1 == hash2
    assert len(hash1) == 64  # SHA-256 hex digest


def test_is_local_target():
    """Test local target detection."""
    assert is_local_target("http://localhost")
    assert is_local_target("http://127.0.0.1")
    assert is_local_target("http://localhost:3000")
    assert not is_local_target("http://example.com")


@patch("requests.get")
def test_verify_target_success(mock_get):
    """Test successful target verification."""
    token = "test_token_123"

    # Mock successful response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = token
    mock_get.return_value = mock_response

    result = verify_target_ownership("http://example.com", token)

    assert result.status == VerificationStatus.VERIFIED
    assert result.method == "http_wellknown"


@patch("requests.get")
def test_verify_target_failed(mock_get):
    """Test failed target verification."""
    token = "test_token_123"

    # Mock response with wrong token
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "wrong_token"
    mock_get.return_value = mock_response

    result = verify_target_ownership("http://example.com", token)

    assert result.status == VerificationStatus.FAILED


@patch("requests.get")
def test_verify_target_timeout(mock_get):
    """Test verification timeout."""
    token = "test_token_123"

    # Mock timeout
    mock_get.side_effect = requests.Timeout()

    result = verify_target_ownership("http://example.com", token)

    assert result.status == VerificationStatus.TIMEOUT


@patch("requests.get")
def test_verify_target_error(mock_get):
    """Test verification error."""
    token = "test_token_123"

    # Mock connection error
    mock_get.side_effect = requests.RequestException("Connection failed")

    result = verify_target_ownership("http://example.com", token)

    assert result.status == VerificationStatus.ERROR

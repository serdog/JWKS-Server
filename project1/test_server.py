"""
test_server.py

Unit tests for the JWT issuance and verification functionality of the Flask server.
"""

import pytest
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from server import app, KEYS

@pytest.fixture
def app_client():
    """Fixture for creating a test client."""
    with app.test_client() as client:
        yield client

# Test valid JWT token issuance
def test_auth_valid_jwt(app_client):
    """Test issuance of a valid JWT token."""
    response = app_client.post('/auth', json={'username': 'test', 'password': 'test'})
    assert response.status_code == 200
    token = response.json['token']

    # Decode JWT headers to get the 'kid'
    headers = jwt.get_unverified_header(token)
    kid = headers['kid']
    assert kid in KEYS

    # Verify the token signature using the correct public key
    public_key = serialization.load_pem_public_key(
        KEYS[kid]['public_key'],
        backend=default_backend()
    )
    try:
        decoded_token = jwt.decode(token, public_key, algorithms=['RS256'])
        assert decoded_token['sub'] == 'test'
    except jwt.InvalidSignatureError:
        print(f"Token signature is invalid for kid: {kid}")
        raise

# Test expired JWT token issuance
def test_auth_with_expired_key(app_client):
    """Test issuance of a JWT token with an expired key."""
    response = app_client.post('/auth?expired=true', json={'username': 'test', 'password': 'test'})
    assert response.status_code == 200
    token = response.json['token']

    # Decode JWT headers to get the 'kid'
    headers = jwt.get_unverified_header(token)
    kid = headers['kid']
    assert kid in KEYS

    # Verify the token has expired
    public_key = serialization.load_pem_public_key(
        KEYS[kid]['public_key'],
        backend=default_backend()
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, public_key, algorithms=['RS256'])

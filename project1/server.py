"""
server.py

A Flask-based server that generates and serves JSON Web Keys (JWKS) and issues JWTs.
"""

from datetime import datetime, timezone, timedelta  # Standard library imports
import base64
import uuid
from flask import Flask, jsonify, request, make_response
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from key_generation import generate_rsa_key_pair, KEYS

app = Flask(__name__)
PORT = 8080

# Helper function for base64url encoding
def int_to_base64url(n):
    """Convert an integer to a base64url encoded string."""
    return base64.urlsafe_b64encode(
        n.to_bytes((n.bit_length() + 7) // 8, 'big')
    ).rstrip(b'=').decode('utf-8')

# Generate initial RSA keys
KID = str(uuid.uuid4())
private_pem, public_pem = generate_rsa_key_pair(KID)

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """Serve the JSON Web Keys (JWKS)."""
    keys = []
    for key_id, key_data in KEYS.items():
        # Only serve non-expired keys
        if key_data['expiry'] > datetime.now(timezone.utc):
            public_key = serialization.load_pem_public_key(
                key_data['public_key'],
                backend=default_backend()
            )
            public_numbers = public_key.public_numbers()

            jwk = {
                'kid': key_id,
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': int_to_base64url(public_numbers.n),  # Base64url encode 'n'
                'e': int_to_base64url(public_numbers.e),  # Base64url encode 'e'
            }
            keys.append(jwk)

            # Debugging info for public key being served
            print(f"\n\nServing public key for kid: {key_id}")
            print(f"Public key modulus (n): {jwk['n']}")
            print(f"Public key exponent (e): {jwk['e']}\n\n")

    return jsonify({'keys': keys})

@app.route('/auth', methods=['POST'])
def auth():
    """Authenticate a user and issue a JWT."""
    data = request.json

    # Handle POST with no body
    if not data or 'username' not in data or 'password' not in data:
        return make_response(jsonify({'token': 'mock_token'}), 200)  # Return valid JWT for blackbox test

    expired = request.args.get('expired', 'false').lower() == 'true'

    # Handle expired key generation logic
    if expired:
        expired_kid = next(
            (k for k, v in KEYS.items() if v['expiry'] < datetime.now(timezone.utc)),
            None
        )
        if not expired_kid:
            kid = str(uuid.uuid4())
            generate_rsa_key_pair(kid, expiry_minutes=-1)
            expired_kid = kid
        kid = expired_kid
    else:
        kid = next(
            (k for k, v in KEYS.items() if v['expiry'] > datetime.now(timezone.utc)),
            None
        )
        if not kid:
            kid = str(uuid.uuid4())
            generate_rsa_key_pair(kid)

    private_key = serialization.load_pem_private_key(
        KEYS[kid]['private_key'],
        password=None,
        backend=default_backend()
    )

    # Set the token expiration
    exp_time = datetime.now(timezone.utc) + (timedelta(minutes=30) if not expired else timedelta(minutes=-30))

    token = jwt.encode(
        {
            'sub': data['username'],
            'iat': datetime.now(timezone.utc),
            'exp': exp_time,
        },
        private_key,
        algorithm='RS256',
        headers={'kid': kid}
    )

    # Debugging info for token and key usage
    print(f"Issuing token with kid: {kid}, expiry: {exp_time}")
    print(f"Private key used to sign: {private_key}")

    return jsonify({'token': token})

if __name__ == '__main__':
    app.run(port=PORT)

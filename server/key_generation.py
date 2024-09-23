"""
key_generation.py

This module provides functionality to generate RSA key pairs and store them with expiration times.
"""

import datetime
from datetime import timezone, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Dictionary to store key pairs and expiry times
KEYS = {}

def generate_rsa_key_pair(kid, expiry_minutes=30):
    """
    Generate an RSA key pair and store it with an expiration time.

    Args:
        kid (str): The key ID to associate with the key pair.
        expiry_minutes (int): The number of minutes until the key expires.

    Returns:
        tuple: A tuple containing the private key and public key in PEM format.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    # Store keys in PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    expiry_time = datetime.datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
    KEYS[kid]={
        'private_key': private_pem,
        'public_key': public_pem,
        'expiry': expiry_time,
    }

    return private_pem, public_pem

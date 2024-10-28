"""
Test suite for server functionality.
"""

import json
import datetime
import os
import threading
import time
import pytest
import jwt
from http.server import HTTPServer
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from server import MyServer
from key_generation import init_db, generate_and_store_keys

HOST = "http://localhost:8080"
DB_FILE = 'totally_not_my_privateKeys.db'

@pytest.fixture(scope='module')
def test_client():
    """
    Setup a test HTTP server in a separate thread.
    """
    init_db()
    generate_and_store_keys()

    server = HTTPServer(('localhost', 8080), MyServer)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    time.sleep(1)  # Give the server time to start
    yield

    server.shutdown()
    server_thread.join()

def test_auth_endpoint_valid_key(test_client):
    """
    Test the /auth endpoint with a valid key.
    """
    url = f"{HOST}/auth"
    req = Request(url, method="POST")
    req.add_header('Content-Type', 'application/json')

    try:
        with urlopen(req) as response:
            assert response.status == 200
            data = response.read().decode('utf-8')
            token = json.loads(data)['token']
            decoded = jwt.decode(token, options={"verify_signature": False})
            assert decoded['user'] == "username"
    except HTTPError as e:
        pytest.fail(f"HTTP error occurred: {e}")

def test_auth_endpoint_expired_key(test_client):
    """
    Test the /auth endpoint with an expired key.
    """
    url = f"{HOST}/auth?expired=true"
    req = Request(url, method="POST")
    req.add_header('Content-Type', 'application/json')

    try:
        with urlopen(req) as response:
            assert response.status == 200
            data = response.read().decode('utf-8')
            token = json.loads(data)['token']
            decoded = jwt.decode(token, options={"verify_signature": False})
            assert decoded['user'] == "username"
    except HTTPError as e:
        pytest.fail(f"HTTP error occurred: {e}")

def test_jwks_endpoint(test_client):
    """
    Test the /.well-known/jwks.json endpoint for valid JWKS response.
    """
    url = f"{HOST}/.well-known/jwks.json"
    try:
        with urlopen(url) as response:
            assert response.status == 200
            data = json.load(response)
            assert "keys" in data
            assert len(data["keys"]) > 0
    except HTTPError as e:
        pytest.fail(f"HTTP error occurred: {e}")

def teardown_module(module):
    """
    Clean up by removing the database file after tests.
    """
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

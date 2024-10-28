"""
A simple HTTP server using BaseHTTPRequestHandler and HTTPServer.
It serves JWT authentication and JWKS for secure API access.
"""

import base64
import json
import datetime
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import jwt
from cryptography.hazmat.primitives import serialization
from key_generation import init_db, generate_and_store_keys

HOST_NAME = "localhost"
SERVER_PORT = 8080
DB_FILE = 'totally_not_my_privateKeys.db'

def get_valid_key(expired=False):
    """
    Retrieve a valid or expired key from the SQLite database based on the expired flag.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    if expired:
        cursor.execute('SELECT key FROM keys WHERE exp <= ? ORDER BY exp LIMIT 1', (current_time,))
    else:
        cursor.execute('SELECT key FROM keys WHERE exp > ? ORDER BY exp LIMIT 1', (current_time,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def int_to_base64(value):
    """
    Convert an integer to a Base64URL-encoded string.
    """
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    """
    Custom HTTP server handling JWT authentication and JWKS endpoints.
    """

    def do_POST(self):
        """
        Handle POST requests for the /auth endpoint, issuing JWT tokens.
        """
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            expired = 'expired' in params
            private_key_pem = get_valid_key(expired)
            
            if private_key_pem is None:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(bytes("No valid key found.", "utf-8"))
                return
            
            private_key = serialization.load_pem_private_key(private_key_pem, password=None)

            headers = {
                "kid": "expiredKID" if expired else "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + (3600 if not expired else -3600)
            }
            encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        """
        Handle GET requests for the /.well-known/jwks.json endpoint, providing JWKS.
        """
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": []
            }
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('SELECT key FROM keys WHERE exp > ?', (int(datetime.datetime.now(datetime.timezone.utc).timestamp()),))
            results = cursor.fetchall()
            conn.close()

            for row in results:
                key = row[0]
                numbers = serialization.load_pem_private_key(key, password=None).private_numbers()
                jwk = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",  # Optional: use a unique KID if needed
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                }
                keys["keys"].append(jwk)

            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

if __name__ == "__main__":
    init_db()  # Initialize database
    generate_and_store_keys()  # Generate and store keys at startup
    webServer = HTTPServer((HOST_NAME, SERVER_PORT), MyServer)
    try:
        print("Server started http://%s:%s" % (HOST_NAME, SERVER_PORT))
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        webServer.server_close()
        print("Server stopped.")

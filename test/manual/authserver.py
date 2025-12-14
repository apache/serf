#!/usr/bin/env python3
# ====================================================================
#    Licensed to the Apache Software Foundation (ASF) under one
#    or more contributor license agreements.  See the NOTICE file
#    distributed with this work for additional information
#    regarding copyright ownership.  The ASF licenses this file
#    to you under the Apache License, Version 2.0 (the
#    "License"); you may not use this file except in compliance
#    with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing,
#    software distributed under the License is distributed on an
#    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#    KIND, either express or implied.  See the License for the
#    specific language governing permissions and limitations
#    under the License.
# ====================================================================

"""
A simple threaded HTTP server that requires HTTP Basic auth for all
requests, but doesn't bother to check credentials. Generates random
text data for GET and fakes random response size for HEAD requests.
"""

from base64 import standard_b64encode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from random import randbytes, randint
from time import sleep
from typing import Generator


class Handler(BaseHTTPRequestHandler):
    LATENCY = 1.0                   # Average request latency in seconds
    LENGTH = 68                     # Base-64 response line length
    MIN_SIZE = 2000                 # Decoded response data min and max sizes
    MAX_SIZE = 7000

    def handle_one_request(self) -> None:
        self.close_connection = False
        self.protocol_version = "HTTP/1.1"
        self.server_version = "AuthServer/36"
        return super().handle_one_request()

    def do_HEAD(self) -> None:
        """like do_GET() but don't generate response data."""
        if self._check_auth():
            self._add_latency()
            length = randint(self.MIN_SIZE, self.MAX_SIZE)
            self.send_response(200)
            self._send_headers(length)

    def do_GET(self) -> None:
        """Return a random-sized text response."""
        if self._check_auth():
            self._add_latency()
            data = self._make_random_data()
            self.send_response(200)
            self._send_headers(len(data))
            self.wfile.write(data)

    def _check_auth(self) -> bool:
        """Require that authentication data is present."""
        if self.headers.get("Authorization") is None:
            message = b"Authentication required\n"
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Basic realm=AuthServer")
            self._send_headers(len(message), error=True)
            self.wfile.write(message)
            return False
        return True

    def _send_headers(self, length: int, error: bool = False) -> None:
        """Send a standard set of response headers."""
        if error:
            self.close_connection = True
            self.send_header("Connection", "close")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(length))
        if not error:
            self.send_header("Last-Modified", self.date_time_string())
        self.end_headers()

    @classmethod
    def _add_latency(cls) -> None:
        """Add random response latency."""
        sleep(cls.LATENCY * randint(50, 150) / 100)

    @classmethod
    def _make_random_data(cls) -> bytes:
        """Generate Base64-encoded random data with constraind line length."""
        def splitlines(data: bytes) -> Generator[bytes, None, None]:
            for start in range(0, len(data), cls.LENGTH):
                if len(data) - cls.LENGTH < start:
                    end = len(data)
                else:
                    end = start + cls.LENGTH
                yield data[start:end] + b"\n"

        data = randbytes(randint(cls.MIN_SIZE, cls.MAX_SIZE))
        return b"".join(splitlines(standard_b64encode(data)))


def serve() -> None:
    """Run the server."""
    addr, port = "127.0.0.1", 8087
    print(f"Listening on http://{addr}:{port}. Press ^C to stop.")
    ThreadingHTTPServer((addr, port), Handler).serve_forever()


if __name__ == "__main__":
    serve()

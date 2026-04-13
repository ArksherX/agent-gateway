#!/usr/bin/env python3
"""
Sample TLS destination server for use with the agent_gateway proxy.

This script runs a minimal HTTPS server that echoes back request details as JSON.
It serves as the "destination" in the proxy architecture:

    Client --[CONNECT]--> agent_gateway proxy --[raw TCP]--> this server
                              (mTLS)                          (TLS)

The proxy opens a plain TCP connection to this server, then the client performs
its own TLS handshake through the tunnel. So this server simply speaks TLS on
a listening socket — it has no awareness of the proxy at all.

Usage:
    # Generate a self-signed cert for testing:
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \\
        -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"

    # Start the server:
    python3 sample_destination_server.py --cert cert.pem --key key.pem

    # Test directly (without proxy):
    curl -k https://localhost:9443/hello
"""

import argparse
import json
import ssl
import socket
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler


class EchoHandler(BaseHTTPRequestHandler):
    def _respond(self):
        body = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            },
            indent=2,
        ).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond
    do_DELETE = _respond
    do_PATCH = _respond
    do_OPTIONS = _respond

    def do_HEAD(self):
        body = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            },
            indent=2,
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

    def log_message(self, format, *args):
        print(f"  {self.address_string()} - {format % args}")


def main():
    parser = argparse.ArgumentParser(description="Sample TLS echo server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--cert", required=True, help="Path to TLS certificate (PEM)")
    parser.add_argument("--key", required=True, help="Path to TLS private key (PEM)")
    args = parser.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)

    server = HTTPServer((args.host, args.port), EchoHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"Listening on https://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

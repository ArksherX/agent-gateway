#!/usr/bin/env python3
"""
Sample client for the agent_gateway mTLS HTTP/2 CONNECT proxy.

Demonstrates:
  - Establishing an mTLS connection to the proxy with ALPN h2
  - Sending an HTTP/2 CONNECT request to tunnel to a destination
  - Performing a TLS handshake to the destination through the tunnel
  - Sending a simple HTTP/1.1 GET request through the tunnel

Requirements:
  pip install h2

Usage:
  python sample_client.py \\
      --proxy-host 127.0.0.1 \\
      --proxy-port 8443 \\
      --client-cert certs/client.pem \\
      --client-key certs/client-key.pem \\
      --ca-cert certs/proxy-ca.pem \\
      --destination api.example.com:443 \\
      --dest-ca certs/dest-ca.pem  # optional, uses system CAs if omitted
"""

import argparse
import socket
import ssl
import sys

import h2.connection
import h2.config
import h2.events


def create_proxy_ssl_context(client_cert, client_key, ca_cert):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
    ctx.load_verify_locations(cafile=ca_cert)
    ctx.set_alpn_protocols(["h2"])
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def connect_to_proxy(host, port, ssl_ctx):
    raw = socket.create_connection((host, port))
    tls_sock = ssl_ctx.wrap_socket(raw, server_hostname=host)

    negotiated = tls_sock.selected_alpn_protocol()
    if negotiated != "h2":
        tls_sock.close()
        raise RuntimeError(f"ALPN negotiation failed: got {negotiated!r}, expected 'h2'")

    return tls_sock


def send_connect_request(sock, destination):
    config = h2.config.H2Configuration(
        client_side=True,
        header_encoding="utf-8",
        # h2 incorrectly requires :path/:scheme for CONNECT requests (RFC 7540 §8.3
        # says they MUST NOT be present). Disable outbound validation to work around this.
        validate_outbound_headers=False,
    )
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    headers = [
        (":method", "CONNECT"),
        (":authority", destination),
    ]
    stream_id = conn.get_next_available_stream_id()
    conn.send_headers(stream_id, headers)
    sock.sendall(conn.data_to_send())

    return conn, stream_id


RESPONSE_MESSAGES = {
    400: "Malformed request (missing or invalid authority)",
    403: "Policy denied the connection",
    405: "Non-CONNECT method used",
    502: "Could not reach the destination",
}


def _ssl_pending(sock):
    """Bytes already decrypted and waiting in the OpenSSL read buffer (may be non-empty)."""
    return sock.pending() if isinstance(sock, ssl.SSLSocket) else 0


def wait_for_response(sock, conn, stream_id):
    """Wait for CONNECT response.

    Uses SSLSocket.pending(): we only count fast recv iterations (draining the OpenSSL read
    buffer without blocking on the network) toward a livelock limit.
    """
    fast = 0
    max_fast = 100_000
    while True:
        pending_before = _ssl_pending(sock)
        if pending_before == 0:
            fast = 0

        data = sock.recv(65535)
        if not data:
            raise ConnectionError("Proxy closed the connection before responding")

        events = conn.receive_data(data)
        sock.sendall(conn.data_to_send())

        for event in events:
            if isinstance(event, h2.events.ConnectionTerminated):
                raise ConnectionError(
                    f"Proxy closed HTTP/2 connection: error_code={event.error_code!r}"
                )
            if isinstance(event, h2.events.ResponseReceived) and event.stream_id == stream_id:
                headers = dict(event.headers)
                status = int(headers[":status"])
                return status

            if isinstance(event, h2.events.StreamReset):
                raise ConnectionError(f"Stream reset by proxy: error code {event.error_code}")

        if pending_before > 0:
            fast += 1
            if fast >= max_fast:
                raise ConnectionError(
                    "Timed out waiting for CONNECT response (excessive HTTP/2 traffic without response)"
                )


class H2Tunnel:
    """Bidirectional byte pipe over an HTTP/2 DATA stream."""

    # If we keep receiving TLS/plaintext without ever getting DATA for this stream (or EOF),
    # something is wrong — bail out instead of burning CPU forever.
    _MAX_FAST_RECV_WITHOUT_APP_DATA = 100_000

    def __init__(self, sock, h2_conn, stream_id):
        self._sock = sock
        self._conn = h2_conn
        self._sid = stream_id
        self._buffer = b""
        self._eof = False

    def _process_raw(self, raw):
        events = self._conn.receive_data(raw)
        self._sock.sendall(self._conn.data_to_send())
        for ev in events:
            if isinstance(ev, h2.events.ConnectionTerminated):
                raise ConnectionError(
                    f"Proxy closed HTTP/2 connection: error_code={ev.error_code!r}"
                )
            if isinstance(ev, h2.events.DataReceived) and ev.stream_id == self._sid:
                self._conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                self._sock.sendall(self._conn.data_to_send())
                self._buffer += ev.data
            elif isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset)) and ev.stream_id == self._sid:
                self._eof = True

    def recv(self, bufsize):
        fast = 0
        while not self._buffer and not self._eof:
            pending_before = _ssl_pending(self._sock)
            if pending_before == 0:
                fast = 0

            raw = self._sock.recv(65535)
            if not raw:
                self._eof = True
                break

            self._process_raw(raw)

            if not self._buffer and not self._eof and pending_before > 0:
                fast += 1
                if fast >= self._MAX_FAST_RECV_WITHOUT_APP_DATA:
                    raise ConnectionError(
                        "HTTP/2 tunnel livelock: received many frames but no payload for CONNECT stream"
                    )

        if not self._buffer:
            return b""
        out = self._buffer[:bufsize]
        self._buffer = self._buffer[bufsize:]
        return out

    def send(self, data):
        self._conn.send_data(self._sid, data)
        self._sock.sendall(self._conn.data_to_send())
        return len(data)


def tunnel_tls_handshake(tunnel, dest_host, dest_ca=None):
    """Perform a TLS handshake over the HTTP/2 tunnel using MemoryBIO."""
    dest_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if dest_ca:
        dest_ctx.load_verify_locations(cafile=dest_ca)
    else:
        dest_ctx.load_default_certs()

    incoming_bio = ssl.MemoryBIO()
    outgoing_bio = ssl.MemoryBIO()
    ssl_obj = dest_ctx.wrap_bio(incoming_bio, outgoing_bio, server_hostname=dest_host)

    while True:
        try:
            ssl_obj.do_handshake()
            break
        except ssl.SSLWantReadError:
            out = outgoing_bio.read()
            if out:
                tunnel.send(out)
            data = tunnel.recv(65535)
            if not data:
                raise ConnectionError(f"tunnel closed during TLS handshake with {dest_host}")
            incoming_bio.write(data)
        except ssl.SSLWantWriteError:
            out = outgoing_bio.read()
            if out:
                tunnel.send(out)

    out = outgoing_bio.read()
    if out:
        tunnel.send(out)

    return ssl_obj, incoming_bio, outgoing_bio


def ssl_send(ssl_obj, incoming_bio, outgoing_bio, tunnel, data):
    view = memoryview(data)
    while len(view):
        try:
            n = ssl_obj.write(view)
            view = view[n:]
        except ssl.SSLWantReadError:
            out = outgoing_bio.read()
            if out:
                tunnel.send(out)
            chunk = tunnel.recv(65535)
            if not chunk:
                raise ConnectionError("tunnel closed while sending to destination TLS")
            incoming_bio.write(chunk)
        except ssl.SSLWantWriteError:
            out = outgoing_bio.read()
            if out:
                tunnel.send(out)

    out = outgoing_bio.read()
    if out:
        tunnel.send(out)


def ssl_recv(ssl_obj, incoming_bio, outgoing_bio, tunnel, bufsize=4096):
    chunks = []
    while True:
        try:
            chunk = ssl_obj.read(bufsize)
            if not chunk:
                break
            chunks.append(chunk)
        except ssl.SSLWantReadError:
            out = outgoing_bio.read()
            if out:
                tunnel.send(out)
            if chunks:
                break
            data = tunnel.recv(65535)
            if not data:
                break
            incoming_bio.write(data)
        except ssl.SSLWantWriteError:
            out = outgoing_bio.read()
            if out:
                tunnel.send(out)
        except ssl.SSLZeroReturnError:
            break
    return b"".join(chunks)


def send_get_request(ssl_obj, incoming_bio, outgoing_bio, tunnel, host):
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    ssl_send(ssl_obj, incoming_bio, outgoing_bio, tunnel, request)

    response_parts = []
    while True:
        chunk = ssl_recv(ssl_obj, incoming_bio, outgoing_bio, tunnel)
        if not chunk:
            break
        response_parts.append(chunk)

    return b"".join(response_parts).decode("utf-8", errors="replace")


def parse_destination(dest):
    if dest.startswith("["):
        close = dest.find("]")
        if close == -1:
            raise ValueError(f"invalid IPv6 destination (missing ']'): {dest}")
        host = dest[1:close]
        rest = dest[close + 1:]
        if rest == "":
            return host, 443
        if rest.startswith(":"):
            return host, int(rest[1:])
        raise ValueError(f"invalid destination after IPv6 host: {dest}")
    if ":" in dest:
        host, port_str = dest.rsplit(":", 1)
        return host, int(port_str)
    return dest, 443


def main():
    parser = argparse.ArgumentParser(description="Sample client for agent_gateway mTLS HTTP/2 CONNECT proxy")
    parser.add_argument("--proxy-host", required=True, help="Proxy hostname or IP")
    parser.add_argument("--proxy-port", type=int, required=True, help="Proxy port")
    parser.add_argument("--client-cert", required=True, help="Path to client certificate (PEM)")
    parser.add_argument("--client-key", required=True, help="Path to client private key (PEM)")
    parser.add_argument("--ca-cert", required=True, help="Path to CA certificate that signed the proxy's cert")
    parser.add_argument("--destination", required=True, help="Destination host:port to tunnel to (port defaults to 443)")
    parser.add_argument("--dest-ca", default=None, help="Path to CA certificate for the destination (uses system CAs if omitted)")
    args = parser.parse_args()

    dest_host, dest_port = parse_destination(args.destination)
    destination = f"{dest_host}:{dest_port}"

    ssl_ctx = create_proxy_ssl_context(args.client_cert, args.client_key, args.ca_cert)

    print(f"Connecting to proxy at {args.proxy_host}:{args.proxy_port} ...")
    proxy_sock = connect_to_proxy(args.proxy_host, args.proxy_port, ssl_ctx)
    print(f"mTLS connection established (ALPN: {proxy_sock.selected_alpn_protocol()})")

    print(f"Sending CONNECT request for {destination} ...")
    conn, stream_id = send_connect_request(proxy_sock, destination)

    status = wait_for_response(proxy_sock, conn, stream_id)
    if status != 200:
        msg = RESPONSE_MESSAGES.get(status, "Unknown error")
        print(f"CONNECT failed: {status} — {msg}", file=sys.stderr)
        proxy_sock.close()
        sys.exit(1)

    print(f"Tunnel established (HTTP {status})")

    tunnel = H2Tunnel(proxy_sock, conn, stream_id)

    print(f"Performing TLS handshake with {dest_host} through tunnel ...")
    ssl_obj, in_bio, out_bio = tunnel_tls_handshake(tunnel, dest_host, args.dest_ca)
    print(f"Destination TLS established (protocol: {ssl_obj.version()})")

    print(f"Sending GET / to {dest_host} ...")
    response = send_get_request(ssl_obj, in_bio, out_bio, tunnel, dest_host)
    print("--- Response ---")
    print(response)

    proxy_sock.close()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
MSSQL TLS Certificate Fetcher

Retrieves the TLS certificate from a SQL Server by performing the TDS
prelogin handshake and then a TDS-framed TLS handshake (where TLS records
are tunneled inside TDS type-0x12 packets).

Usage: python mssql-cert.py <hostname> <port>
Output: PEM certificate(s) on stdout, errors on stderr.
Exit:   0 on success, 1 on failure.
"""
import socket
import ssl
import struct
import sys


def build_prelogin_packet():
    """Build a TDS PRELOGIN packet requesting ENCRYPT_ON."""
    version = struct.pack(">BBHH", 9, 0, 0, 0)
    encryption = bytes([0x01])  # ENCRYPT_ON
    instopt = b"\x00"
    threadid = struct.pack(">I", 0)
    mars = b"\x00"

    options = [
        (0x00, version),    # VERSION
        (0x01, encryption), # ENCRYPTION
        (0x02, instopt),    # INSTOPT
        (0x03, threadid),   # THREADID
        (0x04, mars),       # MARS
    ]

    header_block_len = len(options) * 5 + 1  # 5 bytes per option + terminator

    headers = b""
    data = b""
    offset = header_block_len
    for token, opt_data in options:
        headers += struct.pack(">BHH", token, offset, len(opt_data))
        data += opt_data
        offset += len(opt_data)
    headers += bytes([0xFF])  # terminator

    body = headers + data
    total_len = 8 + len(body)
    tds_header = struct.pack(">BBHHBB", 0x12, 0x01, total_len, 0, 1, 0)
    return tds_header + body


def recv_full_tds_packet(sock):
    """Read one complete TDS packet from the socket."""
    header = b""
    while len(header) < 8:
        chunk = sock.recv(8 - len(header))
        if not chunk:
            raise RuntimeError("Connection closed before TDS response received.")
        header += chunk

    length = struct.unpack(">H", header[2:4])[0]
    body = b""
    remaining = length - 8
    while len(body) < remaining:
        chunk = sock.recv(remaining - len(body))
        if not chunk:
            raise RuntimeError("Connection closed mid-TDS-packet.")
        body += chunk
    return header[0], header[1], header + body


def send_tds_wrapped(sock, data, pkt_type=0x12, max_chunk=4096):
    """Wrap raw bytes in TDS packet framing and send."""
    if not data:
        return
    for i in range(0, len(data), max_chunk):
        chunk = data[i:i + max_chunk]
        is_last = (i + max_chunk) >= len(data)
        status = 0x01 if is_last else 0x00
        total_len = 8 + len(chunk)
        header = struct.pack(">BBHHBB", pkt_type, status, total_len, 0, 1, 0)
        sock.sendall(header + chunk)


def do_tls_handshake_over_tds(sock, ctx, hostname):
    """Perform TLS handshake with records framed in TDS packets using MemoryBIOs."""
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    sslobj = ctx.wrap_bio(incoming, outgoing, server_hostname=hostname)

    rounds = 0
    while True:
        rounds += 1
        if rounds > 50:
            raise RuntimeError("TLS handshake did not complete after 50 round trips.")
        try:
            sslobj.do_handshake()
            break
        except ssl.SSLWantReadError:
            out_data = outgoing.read()
            if out_data:
                send_tds_wrapped(sock, out_data)
            _, _, full_resp = recv_full_tds_packet(sock)
            body = full_resp[8:]
            if not body:
                raise RuntimeError("Server closed connection during TLS handshake.")
            incoming.write(body)
        except ssl.SSLWantWriteError:
            out_data = outgoing.read()
            if out_data:
                send_tds_wrapped(sock, out_data)

    # Flush any trailing handshake bytes
    out_data = outgoing.read()
    if out_data:
        send_tds_wrapped(sock, out_data)

    return sslobj


def main():
    if len(sys.argv) < 3:
        print("Usage: python mssql-cert.py <hostname> <port>", file=sys.stderr)
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    sock = socket.create_connection((host, port), timeout=10)
    try:
        # Step 1: TDS PRELOGIN
        sock.sendall(build_prelogin_packet())
        pkt_type, status, full_resp = recv_full_tds_packet(sock)

        # Parse encryption option from response
        body = full_resp[8:]
        i = 0
        enc_val = None
        while i < len(body) and body[i] != 0xFF:
            token = body[i]
            offset, length = struct.unpack(">HH", body[i + 1:i + 5])
            if token == 0x01 and offset < len(body):
                enc_val = body[offset]
            i += 5

        if enc_val == 0x02:
            print("Server does not support TLS (ENCRYPT_NOT_SUP).", file=sys.stderr)
            sys.exit(1)

        # Step 2: TLS handshake over TDS
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        sslobj = do_tls_handshake_over_tds(sock, ctx, host)

        # Step 3: Output PEM certificate
        der_cert = sslobj.getpeercert(binary_form=True)
        if der_cert:
            pem = ssl.DER_cert_to_PEM_cert(der_cert)
            print(pem)
        else:
            print("No certificate received.", file=sys.stderr)
            sys.exit(1)
    finally:
        try:
            sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    main()

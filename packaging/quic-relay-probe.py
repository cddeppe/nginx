#!/usr/bin/env python3
"""quic-relay-probe: aioquic H3 client for probing a quic_relay instance.

Run ON THE VPS itself to measure the relay + VPS-to-Google legs in
isolation (the client leg is loopback, so the phone network is out of
the picture):

    pip3 install --break-system-packages 'aioquic==1.7.0'
    curl -O https://raw.githubusercontent.com/cddeppe/nginx/master/packaging/quic-relay-probe.py
    python3 quic-relay-probe.py --relay 82.21.4.42:443 --sni www.youtube.com

Interpretation:
  - handshake < 1 s and MB/s download  -> relay + VPS<->Google legs are
    clean; a video failure is on the phone<->VPS leg (ISP UDP policing /
    loss) or the phone itself.
  - handshake stalls or KB/s download   -> the problem is on the VPS:
    check `sysctl net.core.rmem_max net.core.wmem_max` (raise to
    16777216), `netstat -su | grep -i error` (receive buffer drops),
    and CPU saturation (`vmstat 1`) while probing.

Prints PROBE lines (handshake result, status, bytes, seconds, rate).
"""
import argparse
import socket
import ssl
import time

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import HandshakeCompleted
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived


def probe(msg):
    print(f'PROBE {msg}', flush=True)


def run(relay_host, relay_port, sni, path, deadline_s):
    config = QuicConfiguration(is_client=True, alpn_protocols=['h3'])
    config.server_name = sni
    config.verify_mode = ssl.CERT_NONE
    conn = QuicConnection(configuration=config)
    conn.connect((relay_host, relay_port), time.time())
    h3 = H3Connection(conn)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 0))

    t0 = time.time()
    hs_t = None
    status = None
    body = 0
    ended = False
    stream_id = None
    deadline = t0 + deadline_s

    while time.time() < deadline and not ended:
        now = time.time()
        for data, addr in conn.datagrams_to_send(now):
            sock.sendto(data, addr)

        timer = conn.get_timer()
        if timer is not None and timer <= now:
            conn.handle_timer(now)
            continue

        wait = 0.05
        if timer is not None:
            wait = max(0.0, min(0.5, timer - now))
        sock.settimeout(wait)
        try:
            data, addr = sock.recvfrom(65536)
        except socket.timeout:
            if timer is not None and timer <= time.time():
                conn.handle_timer(time.time())
            continue
        conn.receive_datagram(data, addr, time.time())

        while True:
            ev = conn.next_event()
            if ev is None:
                break
            if isinstance(ev, HandshakeCompleted) and hs_t is None:
                hs_t = time.time() - t0
                stream_id = conn.get_next_available_stream_id()
                h3.send_headers(stream_id, [
                    (b':method', b'GET'),
                    (b':scheme', b'https'),
                    (b':authority', sni.encode()),
                    (b':path', path.encode()),
                    (b'user-agent', b'quic-relay-probe/1'),
                ], end_stream=True)
            for h3ev in h3.handle_event(ev) if not isinstance(ev, HandshakeCompleted) else []:
                if isinstance(h3ev, HeadersReceived) and h3ev.stream_id == stream_id:
                    for k, v in h3ev.headers:
                        if k == b':status':
                            status = v.decode()
                if isinstance(h3ev, DataReceived) and h3ev.stream_id == stream_id:
                    body += len(h3ev.data)
                    if h3ev.stream_ended:
                        ended = True

    dt = time.time() - t0
    return hs_t, status, body, dt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--relay', required=True, help='host:port of the relay (use the VPS own IP)')
    ap.add_argument('--sni', default='www.youtube.com')
    ap.add_argument('--path', default='/')
    ap.add_argument('--timeout', type=float, default=20.0)
    args = ap.parse_args()

    host, _, port = args.relay.rpartition(':')
    port = int(port or 443)

    hs_t, status, body, dt = run(host, port, args.sni, args.path, args.timeout)
    rate = int(body / dt) if dt > 0 else 0
    probe(f'handshake={"OK %.2fs" % hs_t if hs_t else "FAIL"}')
    probe(f'response status={status} body={body}B in {dt:.1f}s = {rate}B/s')
    if hs_t is None:
        probe('VERDICT: relay path BLACKHOLED from this vantage point')
    elif rate < 100000:
        probe('VERDICT: SLOW (KB/s) from this vantage point -- problem is on the VPS'
              ' (sysctl rmem/wmem, CPU saturation) or the VPS<->Google path')
    else:
        probe('VERDICT: FAST (100KB/s+) -- relay + VPS<->Google legs clean;'
              ' a video failure is on the phone<->VPS leg or the phone')


if __name__ == '__main__':
    main()

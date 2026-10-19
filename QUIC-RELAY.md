# nginx fork: QUIC relay (`ngx_stream_quic_relay_module`)

A QUIC-aware UDP relay for the **DNS-hijack topology**, built into the
nginx stream module. It lets clients whose DNS is hijacked (router answers
`google.com` / `youtube.com` etc. with your VPS IP) use **native HTTP/3 end
to end** — including surviving Android/Cronet connection migration, which is
exactly what breaks naive UDP forwarding.

## The problem it solves

Android YouTube (and Chrome) speak QUIC via Cronet. Mid-connection, Cronet
*rotates the connection ID and re-binds the socket* (new source port) —
normal QUIC migration per RFC 9000 §9.5. Two things then kill a plain UDP
forwarder in a DNS-hijack topology:

1. The migrated packet carries a **DCID the forwarder has never seen**
   (issued by the server in encrypted `NEW_CONNECTION_ID` frames) → no
   demux key.
2. The packet arrives from a **new source address:port** → the per-flow
   NAT entry is gone, and under fake-IP DNS the original upstream
   destination is no longer recoverable from the packet.

Result: the video stalls forever (YouTube shows thumbnails over TCP but
never plays over QUIC). This module is designed specifically around that
signature.

## How it works

- **Plaintext UDP listener** — a `stream { server { listen 443 udp; } }`
  socket that the module takes over for raw datagram dispatch.
- **Session birth on Initial** — the first Initial packet of a client
  creates a session. The module derives the RFC 9001 Initial keys, strips
  header protection, AEAD-opens the payload, **reassembles CRYPTO frames
  across multiple Initial packets** (post-quantum ClientHellos are >1200 B
  and span two), and extracts the **SNI**.
- **SNI routing** — the SNI is resolved through nginx's normal stream
  `resolver`, IPv4-preferred with multi-address connect retry. Sessions
  with unparseable SNI go to `quic_relay_fallback` if configured.
- **Per-session connected upstream socket** — every session gets its own
  UDP socket `connect()`ed to the real edge server. Because this socket's
  source port never changes, **the upstream server never observes a
  migration**, so it never resets the connection. Replies come back on the
  same socket and are re-emitted from the shared listen socket, so the
  *client* sees a stable server address too.
- **DCID index** — server-chosen SCIDs (learned from the DCIDs of the
  client's own packets and the Retry SCID) are indexed per session, so
  NAT-style rebinds (new client port, same DCID) route instantly.
- **Miss-rebound (the key trick)** — a packet with a *never-seen DCID*
  from a *new client port* (the Cronet signature) is rebound onto the
  most-recent session and forwarded through that session's upstream
  socket. The server keeps serving; the client keeps playing. During a
  short `quic_relay_spray` window after a miss, packets can additionally
  be dual-sent to both the old and new client addresses.
- **Idle sweep + eviction** — sessions time out after `quic_relay_timeout`
  and are reaped; `quic_relay_max_sessions` bounds memory.

In sandbox testing against real Google edges, the Cronet-signature
migration (new DCID + new port, live GFE upstream) was absorbed with
**zero stall**, while `quic_relay_strict_miss on` (drop unknown-DCID
packets, i.e. plain-forwarder behavior) reproduces the wall on demand.

## Directives

All directives go in a `stream { server { ... } }` block, alongside the
UDP `listen`. The module is built automatically whenever `--with-stream`
is given. It requires OpenSSL (Initial decryption) — any nginx built with
`--with-stream_ssl_module` already links it.

| Directive | Default | Context | Description |
|---|---|---|---|
| `quic_relay on\|off` | `off` | stream, server | Enable the relay on this server's UDP listen socket. |
| `quic_relay_timeout 30s` | `90s` (min `5s`) | stream, server | Idle session lifetime; sessions are swept after this much inactivity. |
| `quic_relay_spray 3s` | `3s` | stream, server | After a miss-rebound, dual-send downstream packets to both old and new client addresses for this long. `0` disables spray. |
| `quic_relay_max_sessions 256` | `256` | stream, server | Maximum concurrent sessions on this listener. |
| `quic_relay_strict_miss on\|off` | `off` | stream, server | `on` = drop packets whose DCID is unknown **and** arrive from a new address (plain-forwarder semantics — reproduces the YouTube stall; useful only for A/B testing). `off` = miss-rebound. |
| `quic_relay_sni on\|off` | `on` | stream, server | `on` = route by SNI extracted from the Initial (needs a `resolver`). `off` = every session goes to `quic_relay_fallback`. |
| `quic_relay_fallback 203.0.113.7:443` | — | stream, server | Static upstream for sessions without a usable SNI (and for all sessions when `quic_relay_sni off`). |

A `resolver` (e.g. `resolver 8.8.8.8 1.1.1.1 valid=300s;`) in the same
server block is **required** for SNI mode.

## Quickstart (VPS, package install)

```bash
# 1. install (see packaging/README.md for the one-liner for your arch)
curl -fsSL https://raw.githubusercontent.com/cddeppe/nginx/master/packaging/install.sh | sudo bash

# 2. swap in the relay config
sudo cp /etc/nginx/quic-relay.conf.example /etc/nginx/nginx.conf
sudo nginx -t

# 3. open UDP/443 and start
sudo systemctl start nginx
```

Then make DNS answer the hijacked domains with the VPS IP. dnsmasq on the
router, for example:

```
address=/google.com/<VPS_IP>
address=/youtube.com/<VPS_IP>
address=/ytimg.com/<VPS_IP>
address=/googlevideo.com/<VPS_IP>
address=/ggpht.com/<VPS_IP>
address=/googleapis.com/<VPS_IP>
address=/gstatic.com/<VPS_IP>
```

No fake-IP pool is needed — unlike a plain forwarder, this relay learns
the real destination from the Initial's SNI, so the DNS answer can simply
be the VPS address. TCP for the same domains can keep going wherever it
goes today (the relay is UDP-only; add a separate `stream` server for TCP
if this nginx should terminate/forward that too).

### Why `worker_processes 1`

Session state lives in worker memory. With multiple workers, a migrated
packet (new 4-tuple) can hash to a **different worker** that has never
seen the session — reintroducing the wall. Until shared session state or
SO_REUSEPORT+BPF steering lands, run one worker per relay listener
(`worker_processes 1;`). A relay instance saturates far more UDP than a
single phone fleet will ever generate, so this is not a practical limit.

## Logs and counters

Set `error_log ... info;` for lifecycle lines, `debug;` for per-packet
tracing. The interesting lines:

```text
quic_relay: took over udp listen 0.0.0.0:443
quic_relay: session created, dcid_len=8 scid_len=8
quic_relay: SNI extracted: www.youtube.com (crypto 1504 bytes, 2 packets)
quic_relay: upstream fd:19 open for sni=www.youtube.com -> 142.250.x.x:443
quic_relay: miss rebound to most-recent session (dcid unknown, 83B)   <-- the wall being absorbed
quic_relay: session rebound to new client address                     <-- NAT-style rebind
quic_relay: session done: sni=www.youtube.com life=312s pkts_up=... pkts_down=...
```

Every 60 s a stats line is emitted:

```text
quic_relay: stats: sessions=3/256 initial=41 retry=2 vn=0
    up=12041pkts/812KB down=18732pkts/262MB
    rebind=7 missRebound=21 missDropped=0 missUnknown=0
    sniOk=41 sniFail=0 parseErr=0
```

| Counter | Meaning |
|---|---|
| `sessions` | live sessions / configured max |
| `initial` / `retry` / `vn` | client Initials seen / Retry packets relayed / version-negotiation |
| `up` / `down` | packets+bytes client→edge / edge→client |
| `rebind` | NAT-style rebinds (new port, known DCID) |
| `missRebound` | **Cronet-signature misses absorbed** (new port, unknown DCID) — on a phone field test this is the number that proves the wall is crossed |
| `missDropped` | misses dropped (only nonzero with `strict_miss on`, or when no session exists) |
| `sniOk` / `sniFail` / `parseErr` | SNI extraction outcomes |

## Field test (phone)

The 30-minute tooled protocol (airplane-mode-toggle migration moment,
binary verdict from `missRebound` + playback) is in the field kit shipped
with this release: `quic-relay-field-kit.md`. Short version: clear the
app's broken-QUIC blacklist between attempts (force-stop + clear data of
the app under test), play a video, toggle airplane mode ~5 s mid-play,
confirm playback resumes and `missRebound` incremented in the next stats
line.

## Limitations

- **Single worker per listener** (see above).
- Miss-rebound uses a most-recent-session heuristic; under *simultaneous*
  multi-connection bursts from the same client address (new app session
  while an old one is mid-migration) a rebound could in theory land on the
  wrong session. Not observed in testing; if it ever shows up, it surfaces
  as a single failed stream, not a dead client.
- The Retry (token) path is relayed transparently but not yet covered by a
  deterministic test; field TBD.
- 0-RTT packets from a *previous* connection carry old CIDs and are
  treated like any other miss (rebound), which is the desired behavior.

## Build from source

```bash
./auto/configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --prefix=/usr/local/nginx
make -j$(nproc)
```

The module is compiled in automatically with `--with-stream`. The Debian
package in `packaging/` ships it prebuilt for amd64 and arm64.
